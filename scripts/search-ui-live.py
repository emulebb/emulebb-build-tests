"""Live Win32 UI smoke for starting eD2K and Kad searches from the Search page."""

from __future__ import annotations

import argparse
import importlib.util
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import win32con
import win32gui
import win32process


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
rest_smoke = load_local_module("rest_api_smoke_for_search_ui", "rest-api-smoke.py")

from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL, refresh_seed_files

try:
    from pywinauto import Application
    _PYWINAUTO_IMPORT_ERROR = None
except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
    Application = object  # type: ignore[assignment]
    _PYWINAUTO_IMPORT_ERROR = exc


BM_CLICK = 0x00F5
CB_SETCURSEL = 0x014E
CBN_SELCHANGE = 1
EN_CHANGE = 0x0300
WM_COMMAND = 0x0111
WM_SETTEXT = 0x000C

MP_HM_SEARCH = 10212
IDC_SEARCHNAME = 2183
IDC_STARTS = 2189
IDC_COMBO1 = 2175
IDC_SEARCHLIST = 2172
IDC_TAB1 = 2442

LVM_FIRST = 0x1000
LVM_GETITEMCOUNT = LVM_FIRST + 4
TCM_FIRST = 0x1300
TCM_GETITEMCOUNT = TCM_FIRST + 4

SEARCH_TYPE_ED2K_SERVER = 1
SEARCH_TYPE_KADEMLIA = 3
SUITE_INCONCLUSIVE_RETURN_CODE = 2

DEFAULT_SEARCH_PLAN = (
    {"query": "linux", "method": "server", "method_index": SEARCH_TYPE_ED2K_SERVER},
    {"query": "ubuntu", "method": "kad", "method_index": SEARCH_TYPE_KADEMLIA},
)


def choose_rest_listen_port() -> int:
    """Returns one ephemeral localhost TCP port for a live REST verification listener."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_json(path: Path, payload) -> None:
    """Writes a stable UTF-8 JSON artifact."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def configure_search_ui_profile(config_dir: Path, app_exe: Path, api_key: str, port: int, bind_interface: str) -> None:
    """Enables live network policy and localhost REST for the Search UI scenario."""

    rest_smoke.configure_webserver_profile(
        config_dir,
        app_exe,
        api_key,
        port,
        "127.0.0.1",
    )
    rest_smoke.apply_p2p_bind_interface_override(config_dir, bind_interface)


def http_request(base_url: str, path: str, *, api_key: str, request_timeout_seconds: float = 5.0) -> dict[str, object]:
    """Performs one JSON REST GET request against the live WebServer API."""

    request = urllib.request.Request(base_url + path, method="GET", headers={"X-API-Key": api_key})
    with urllib.request.urlopen(request, timeout=request_timeout_seconds) as response:
        body_text = response.read().decode("utf-8", errors="replace")
        payload = None
        if "application/json" in response.headers.get("Content-Type", ""):
            payload = json.loads(body_text)
        return {
            "status": int(response.status),
            "body_text": body_text,
            "json": rest_smoke.unwrap_rest_payload(payload),
            "raw_json": payload,
        }


def wait_for(predicate, timeout: float, interval: float, description: str):
    """Polls until the predicate returns a truthy value or raises on timeout."""

    deadline = time.time() + timeout
    last_value = None
    while time.time() < deadline:
        try:
            last_value = predicate()
        except Exception as exc:
            last_value = f"{type(exc).__name__}: {exc}"
            time.sleep(interval)
            continue
        if last_value:
            return last_value
        time.sleep(interval)
    raise RuntimeError(f"Timed out waiting for {description}. Last value: {last_value!r}")


def find_control(parent_hwnd: int, control_id: int, class_name: str | None = None) -> int:
    """Finds one descendant control by dialog ID and optional Win32 class name."""

    matches: list[int] = []

    def visit(hwnd: int, _param) -> bool:
        if win32gui.GetDlgCtrlID(hwnd) == control_id:
            if class_name is None or win32gui.GetClassName(hwnd) == class_name:
                matches.append(hwnd)
                return False
        return True

    win32gui.EnumChildWindows(parent_hwnd, visit, None)
    if not matches:
        expected = f" id={control_id}" + (f" class={class_name}" if class_name else "")
        raise RuntimeError(f"Could not find Search UI control{expected}.")
    return matches[0]


def notify_parent_control_change(control_hwnd: int, control_id: int, notification: int) -> None:
    """Sends a standard WM_COMMAND control-notification message to the parent."""

    parent = win32gui.GetParent(control_hwnd)
    win32gui.SendMessage(parent, WM_COMMAND, (notification << 16) | control_id, control_hwnd)


def open_search_page(main_hwnd: int) -> None:
    """Activates the main Search page."""

    win32gui.SendMessage(main_hwnd, WM_COMMAND, MP_HM_SEARCH, 0)


def start_search_from_ui(main_hwnd: int, query: str, method_index: int) -> None:
    """Starts one search through the real Search page controls."""

    open_search_page(main_hwnd)
    edit_hwnd = wait_for(lambda: find_control(main_hwnd, IDC_SEARCHNAME, "Edit"), 10.0, 0.2, "Search text edit")
    method_hwnd = find_control(main_hwnd, IDC_COMBO1, "ComboBox")
    start_hwnd = find_control(main_hwnd, IDC_STARTS, "Button")

    win32gui.SendMessage(method_hwnd, CB_SETCURSEL, method_index, 0)
    notify_parent_control_change(method_hwnd, IDC_COMBO1, CBN_SELCHANGE)
    win32gui.SendMessage(edit_hwnd, WM_SETTEXT, 0, query)
    notify_parent_control_change(edit_hwnd, IDC_SEARCHNAME, EN_CHANGE)
    win32gui.SendMessage(start_hwnd, BM_CLICK, 0, 0)


def get_tab_count(tab_hwnd: int) -> int:
    """Returns the Search results tab count."""

    return int(win32gui.SendMessage(tab_hwnd, TCM_GETITEMCOUNT, 0, 0))


def get_list_count(list_hwnd: int) -> int:
    """Returns the Search results list row count."""

    return int(win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0))


def wait_for_ui_started_search(main_hwnd: int, previous_tab_count: int, query: str, method: str) -> dict[str, object]:
    """Waits until the Search tab control records the UI-started search."""

    observations: list[dict[str, object]] = []

    def resolve():
        tab_hwnd = find_control(main_hwnd, IDC_TAB1, "SysTabControl32")
        tab_count = get_tab_count(tab_hwnd)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "tab_count": tab_count,
            }
        )
        if tab_count > previous_tab_count:
            return {"tab_count": tab_count, "observations": observations}
        return None

    return wait_for(resolve, timeout=30.0, interval=1.0, description=f"UI-started {method} search for {query!r}")


def wait_for_search_result_rows(main_hwnd: int, timeout_seconds: float) -> dict[str, object]:
    """Waits for the active Search results list to expose at least one row."""

    observations: list[dict[str, object]] = []

    def resolve():
        list_hwnd = find_control(main_hwnd, IDC_SEARCHLIST, "SysListView32")
        row_count = get_list_count(list_hwnd)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "row_count": row_count,
            }
        )
        if row_count > 0:
            return {"row_count": row_count, "observations": observations}
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=2.0, description="Search result rows")


def run_search_ui_live(
    *,
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    p2p_bind_interface_name: str,
    skip_live_seed_refresh: bool,
    network_ready_timeout_seconds: float,
    search_observation_timeout_seconds: float,
) -> dict[str, object]:
    """Runs the UI-driven search start scenario and returns the result report."""

    rest_api_key = "search-ui-live-key"
    rest_port = choose_rest_listen_port()
    profile = live_common.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    configure_search_ui_profile(
        Path(str(profile["config_dir"])),
        app_exe,
        rest_api_key,
        rest_port,
        p2p_bind_interface_name,
    )
    seed_refresh = None
    if not skip_live_seed_refresh:
        seed_refresh = refresh_seed_files(Path(str(profile["config_dir"])))

    base_url = f"http://127.0.0.1:{rest_port}"
    report: dict[str, object] = {
        "suite": "search-ui-live",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(profile["profile_base"]),
        "rest_base_url": base_url,
        "live_seed_source_url": EMULE_SECURITY_HOME_URL,
        "live_seed_refresh": seed_refresh,
        "p2p_bind_interface_name": p2p_bind_interface_name,
        "search_plan": [
            {"query": row["query"], "method": row["method"]}
            for row in DEFAULT_SEARCH_PLAN
        ],
        "searches": [],
    }
    app = None
    try:
        app = live_common.launch_app(app_exe, Path(str(profile["profile_base"])))
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        live_common.bring_window_to_front(main_window)
        report["process_id"] = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        report["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        report["main_window_is_maximized"] = report["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED

        rest_smoke.wait_for_rest_ready(base_url, rest_api_key, timeout_seconds=60.0)
        report["live_seed_imports"] = rest_smoke.exercise_live_seed_imports(
            base_url,
            rest_api_key,
            seed_refresh,
            request_timeout_seconds=60.0,
        )
        servers_result = rest_smoke.http_request(base_url, "/api/v1/servers", api_key=rest_api_key)
        server_rows = rest_smoke.require_json_array(servers_result, 200)
        report["servers"] = {"count": len(server_rows)}
        report["server_connect"] = rest_smoke.connect_to_live_server(
            base_url,
            rest_api_key,
            server_rows,
            timeout_seconds=network_ready_timeout_seconds,
        )
        kad_start = rest_smoke.http_request(
            base_url,
            "/api/v1/kad/operations/start",
            method="POST",
            api_key=rest_api_key,
            json_body={},
        )
        report["kad_start"] = rest_smoke.compact_http_result(kad_start)
        if int(kad_start["status"]) != 200:
            raise RuntimeError(f"Kad start failed: {rest_smoke.compact_http_result(kad_start)!r}")

        tab_hwnd = find_control(main_hwnd, IDC_TAB1, "SysTabControl32")
        previous_tab_count = get_tab_count(tab_hwnd)
        for planned in DEFAULT_SEARCH_PLAN:
            query = str(planned["query"])
            method = str(planned["method"])
            start_search_from_ui(main_hwnd, query, int(planned["method_index"]))
            started = wait_for_ui_started_search(main_hwnd, previous_tab_count, query, method)
            previous_tab_count = int(started["tab_count"])
            result_rows = wait_for_search_result_rows(main_hwnd, search_observation_timeout_seconds)
            report["searches"].append(
                {
                    "query": query,
                    "method": method,
                    "start_observations": started["observations"],
                    "tab_count_after_start": started["tab_count"],
                    "result_row_count": result_rows["row_count"],
                    "result_observations": result_rows["observations"],
                }
            )

        report["status"] = "passed"
        return report
    except rest_smoke.LiveNetworkUnavailableError as exc:
        report["status"] = "inconclusive"
        report["inconclusive_reason"] = str(exc)
        return report
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        write_json(artifacts_dir / "result.json", report)
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception:
                try:
                    app.kill()
                except Exception:
                    pass


def main(argv: list[str]) -> int:
    """Parses arguments, runs the Search UI live scenario, and publishes artifacts."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=240.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)

    if _PYWINAUTO_IMPORT_ERROR is not None:
        live_common.require_pywinauto()

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="search-ui-live",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir

    try:
        report = run_search_ui_live(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            artifacts_dir=artifacts_dir,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            skip_live_seed_refresh=args.skip_live_seed_refresh,
            network_ready_timeout_seconds=args.network_ready_timeout_seconds,
            search_observation_timeout_seconds=args.search_observation_timeout_seconds,
        )
        harness_cli_common.publish_run_artifacts(paths)
        status = str(report.get("status") or "failed")
        summary_payload = harness_cli_common.build_live_ui_summary(status=status, paths=paths)
        summary_path = paths.run_report_dir / "ui-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        harness_cli_common.cleanup_source_artifacts(paths)
        if status == "inconclusive":
            return SUITE_INCONCLUSIVE_RETURN_CODE
        return 0 if status == "passed" else 1
    except Exception as exc:
        (artifacts_dir / "error.txt").write_text(f"{exc}\n", encoding="utf-8")
        harness_cli_common.publish_run_artifacts(paths)
        summary_payload = harness_cli_common.build_live_ui_summary(status="failed", paths=paths, error_message=str(exc))
        summary_path = paths.run_report_dir / "ui-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        harness_cli_common.cleanup_source_artifacts(paths)
        raise


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
