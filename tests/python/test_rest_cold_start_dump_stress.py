from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "rest-cold-start-dump-stress.py"
    spec = importlib.util.spec_from_file_location("rest_cold_start_dump_stress_test_module", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operator_script_help_loads() -> None:
    module = load_script_module()
    parser = module.build_parser()
    help_text = parser.format_help()

    assert "--waves" in help_text
    assert "--enable-umdh" in help_text
    assert "--skip-dumps" in help_text


def test_wave_plan_mixes_methods_when_both_networks_are_ready() -> None:
    module = load_script_module()
    plan = module.build_wave_search_plan(
        wave_index=2,
        searches_per_wave=5,
        search_terms=("alpha", "beta", "gamma"),
        network_mode="both",
    )

    assert [row["method"] for row in plan] == ["server", "kad", "automatic", "server", "kad"]
    assert [row["network"] for row in plan] == ["server", "kad", "server", "server", "kad"]
    assert [row["query_index"] for row in plan] == [2, 0, 1, 2, 0]


def test_discover_diagnostic_tools_uses_path_first(monkeypatch) -> None:
    module = load_script_module()

    def fake_which(name: str):
        return rf"C:\tools\{name}" if name == "procdump64.exe" else None

    monkeypatch.setattr(module.shutil, "which", fake_which)
    monkeypatch.setattr(module, "candidate_tool_paths", lambda name: [])

    tools = module.discover_diagnostic_tools()

    assert tools["procdump"] == r"C:\tools\procdump64.exe"
    assert tools["cdb"] is None


def test_umdh_gflags_commands_are_explicit(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    calls: list[list[str]] = []

    def fake_run(command, output_path, timeout_seconds, *, env=None):
        calls.append(command)
        return {"command": command, "output_path": str(output_path), "return_code": 0, "timed_out": False}

    monkeypatch.setattr(module, "run_tool_to_file", fake_run)

    module.set_umdh_stack_tracing("gflags.exe", tmp_path / "emule.exe", True, tmp_path / "enable.txt", 1.0)
    module.set_umdh_stack_tracing("gflags.exe", tmp_path / "emule.exe", False, tmp_path / "disable.txt", 1.0)

    assert calls == [
        ["gflags.exe", "/i", "emule.exe", "+ust"],
        ["gflags.exe", "/i", "emule.exe", "-ust"],
    ]


def test_diagnostics_completeness_requires_all_default_dumps() -> None:
    module = load_script_module()
    report = {
        "diagnostics": {
            label: {
                "tools": {
                    "dump_analysis": {
                        "dump": {"dump_exists": True},
                    }
                }
            }
            for label in module.DIAGNOSTIC_LABELS
        }
    }

    assert module.diagnostics_are_complete(report, skip_dumps=False) is True
    report["diagnostics"]["peak"]["tools"]["dump_analysis"]["dump"]["dump_exists"] = False
    assert module.diagnostics_are_complete(report, skip_dumps=False) is False
    assert module.diagnostics_are_complete({}, skip_dumps=True) is True


def test_validate_rejects_invalid_stress_shape() -> None:
    module = load_script_module()
    args = SimpleNamespace(
        waves=0,
        searches_per_wave=1,
        max_concurrent_searches=1,
        downloads_per_wave=0,
        post_drain_seconds=0,
        tool_timeout_seconds=1,
    )

    try:
        module.validate_args(args)
    except ValueError as exc:
        assert "waves" in str(exc)
    else:
        raise AssertionError("expected invalid waves to be rejected")
