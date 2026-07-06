from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

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


def inputs_with_mfc_profile(profile_dir: Path | None) -> LiveWireInputs:
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
    )


def test_launch_soak_resolves_direct_mfc_profile_from_live_wire_inputs(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    profile_dir = tmp_path / "EMULE_BIN"

    assert module.resolve_direct_mfc_profile(
        inputs_with_mfc_profile(profile_dir),
        no_mfc=False,
    ) == profile_dir.resolve()
    assert module.resolve_direct_mfc_profile(
        inputs_with_mfc_profile(profile_dir),
        no_mfc=True,
    ) is None
    assert module.resolve_direct_mfc_profile(
        inputs_with_mfc_profile(None),
        no_mfc=False,
    ) is None


def test_launch_soak_wires_direct_mfc_profile_to_cleanup_and_launch() -> None:
    module = load_launch_soak_module()
    source = inspect.getsource(module.main)

    assert "load_live_wire_inputs(inputs_path)" in source
    assert "direct_mfc_profile = resolve_direct_mfc_profile(inputs, no_mfc=args.no_mfc)" in source
    assert "direct_profile_dir=direct_mfc_profile" in source
