from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

from emule_test_harness import cpu_profile, vpn_guard_live
from emule_test_harness.live_wire_inputs import LiveWireInputs


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_launch_soak_module():
    script_path = REPO_ROOT / "scripts" / "launch-soak.py"
    spec = importlib.util.spec_from_file_location("launch_soak_script_under_test", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inputs_with_profiles(profile_dir: Path | None, rust_profile_dir: Path | None = None) -> LiveWireInputs:
    return LiveWireInputs(
        path=REPO_ROOT / "live-wire-inputs.local.json",
        generic_open_terms=("ubuntu",),
        document_terms=("manual",),
        radarr_movie_terms=("movie",),
        sonarr_series_terms=("series",),
        video_roots=(),
        bootstrap_transfer_hashes=(),
        direct_bootstrap_transfers=(),
        mfc_profile_dir=profile_dir,
        rust_profile_dir=rust_profile_dir,
    )


def test_launch_soak_resolves_direct_mfc_profile_from_live_wire_inputs(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    profile_dir = tmp_path / "EMULE_BIN"

    assert module.resolve_direct_mfc_profile(
        inputs_with_profiles(profile_dir),
        no_mfc=False,
    ) == profile_dir.resolve()
    assert module.resolve_direct_mfc_profile(
        inputs_with_profiles(profile_dir),
        no_mfc=True,
    ) is None
    assert module.resolve_direct_mfc_profile(
        inputs_with_profiles(None),
        no_mfc=False,
    ) is None


def test_launch_soak_resolves_direct_rust_profile_from_live_wire_inputs(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    profile_dir = tmp_path / "rust-profile"

    assert module.resolve_direct_rust_profile(inputs_with_profiles(None, profile_dir)) == profile_dir.resolve()


def test_launch_soak_requires_direct_rust_profile_from_live_wire_inputs() -> None:
    module = load_launch_soak_module()

    try:
        module.resolve_direct_rust_profile(inputs_with_profiles(None, None))
    except RuntimeError as exc:
        assert "rust_profile.profile_dir" in str(exc)
    else:
        raise AssertionError("resolve_direct_rust_profile should reject missing rust_profile.profile_dir")


def test_launch_soak_parser_accepts_lan_bind_addr() -> None:
    module = load_launch_soak_module()
    args = module.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.lan_bind_addr == "192.0.2.10"


def test_launch_soak_parser_accepts_profile_and_vpn_guard_options() -> None:
    module = load_launch_soak_module()
    args = module.build_parser().parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--rust-regular",
            "--no-mfc",
            "--cpu-profile",
            "--cpu-profile-seconds",
            "60",
            "--cpu-profile-stack",
            "--duration-seconds",
            "3600",
            "--rest-timeout-seconds",
            "30",
            "--connect-timeout-seconds",
            "90",
            "--rust-ui",
            "--rust-ui-poll-interval-ms",
            "2000",
            "--vpn-guard-live-config",
            "vpn-guard-live.local.json",
            "--vpn-guard-scenario",
            "success",
        ]
    )

    assert args.rust_regular is True
    assert args.no_mfc is True
    assert args.cpu_profile is True
    assert args.cpu_profile_seconds == 60
    assert args.cpu_profile_stack is True
    assert args.duration_seconds == 3600
    assert args.rest_timeout_seconds == 30
    assert args.connect_timeout_seconds == 90
    assert args.rust_ui is True
    assert args.rust_ui_poll_interval_ms == 2000
    assert args.vpn_guard_scenario == "success"


def test_launch_soak_resolves_vpn_guard_from_live_config(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    config_path = tmp_path / "vpn-guard-live.local.json"
    vpn_guard_live.write_config(
        config_path,
        {
            "schema": vpn_guard_live.SCHEMA,
            "p2pBindInterfaceName": "hide.me",
            "allowedPublicIpCidrs": ",".join(vpn_guard_live.REQUIRED_HIDEME_PUBLIC_CIDRS),
            "commands": {},
        },
    )
    args = module.build_parser().parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--vpn-guard-live-config",
            str(config_path),
            "--vpn-guard-scenario",
            "success",
        ]
    )

    resolved = module.resolve_vpn_guard_profile(args)

    assert resolved["mode"] == "block"
    assert resolved["allowed_public_ip_cidrs"] == ",".join(vpn_guard_live.REQUIRED_HIDEME_PUBLIC_CIDRS)
    assert resolved["config_path"] == str(config_path.resolve())


def test_launch_soak_initializes_cpu_profile_with_staged_symbols(tmp_path: Path, monkeypatch) -> None:
    module = load_launch_soak_module()
    args = module.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10", "--cpu-profile"])
    run_paths = module.soak_run_layout.build_run_paths(tmp_path / "soak", "20260712T010203Z")
    rust_exe = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    rust_exe.parent.mkdir(parents=True)
    rust_exe.write_text("", encoding="utf-8")
    rust_exe.with_suffix(".pdb").write_text("", encoding="utf-8")

    monkeypatch.setattr(module.cpu_profile, "discover_cpu_profile_tools", lambda: cpu_profile.CpuProfileTools(xperf="xperf.exe"))
    monkeypatch.setattr(
        module.cpu_profile,
        "start_cpu_profile",
        lambda **_kwargs: {"return_code": 0},
    )

    _tools, paths, report = module.initialize_cpu_profile(args=args, run_paths=run_paths, rust_exe=rust_exe)

    assert paths is not None
    assert report is not None
    assert report["app_exe"] == str(rust_exe)
    assert report["profile_paths"]["summary"].endswith("cpu-profile-summary.json")
    assert report["symbols"]["app_pdb_exists"] is True


def test_launch_soak_wires_direct_mfc_profile_to_cleanup_and_launch() -> None:
    module = load_launch_soak_module()
    source = inspect.getsource(module.main)

    assert "load_live_wire_inputs(inputs_path)" in source
    assert "direct_mfc_profile = resolve_direct_mfc_profile(inputs, no_mfc=args.no_mfc)" in source
    assert "rust_profile_dir = resolve_direct_rust_profile(inputs)" in source
    assert "rust_ui_exe = resolve_rust_ui_exe(output_root) if args.rust_ui else None" in source
    assert "rust_ui_handles = launch_rust_ui(" in source
    assert "direct_profile_dir=direct_mfc_profile" in source
    assert "vpn_guard_mode=str(vpn_guard_profile[\"mode\"])" in source
    assert "duration_deadline = time.monotonic() + args.duration_seconds" in source
    assert "\"durationSeconds\": args.duration_seconds" in source
