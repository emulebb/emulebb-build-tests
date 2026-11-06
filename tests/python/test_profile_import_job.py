"""Operator import jobs stay offline and independent of development workspaces."""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from emule_test_harness import profile_import_job as module


@pytest.fixture
def job(tmp_path):
    stock = tmp_path / "stock"
    stock.mkdir()
    (stock / "known.met").touch()
    backend = "windows" if os.name == "nt" else "docker"
    binary = tmp_path / "client.exe"
    binary.touch()
    media = tmp_path / "media"
    media.mkdir()
    config = tmp_path / "job.toml"
    runtime = f"binary={json.dumps(str(binary))}" if backend == "windows" else "image='local/sample'"
    target = str(media) if backend == "windows" else "/data/shared"
    config.write_text(f"""schema_version=1
[source]
profile='stock'
[target]
backend='{backend}'
profile='destination'
{runtime}
[output]
directory='reports'
[[path_mappings]]
source='D:\\Shared'
host='media'
target={json.dumps(target)}
""", encoding="utf-8")
    return config


@pytest.fixture
def quiet_roots(monkeypatch):
    monkeypatch.setattr(module.export, "discover_shared_roots", lambda *args: [])


def test_job_resolves_relative_paths_without_workspace(job, quiet_roots, monkeypatch):
    # A fresh interpreter, rather than deleting inherited operator environment.
    env = {k: v for k, v in os.environ.items() if k not in
           ("EMULEBB_WORKSPACE_ROOT", "EMULEBB_WORKSPACE_OUTPUT_ROOT", "CARGO_TARGET_DIR", "X_LOCAL_IP")}
    code = "from pathlib import Path; from emule_test_harness.profile_import_job import load_job; import sys; j=load_job(Path(sys.argv[1])); print(j.profile.name)"
    result = subprocess.run([sys.executable, "-B", "-c", code, str(job)], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "destination"
    assert not (job.parent / "destination").exists()


@pytest.mark.parametrize("change,message", [
    ("allow_merge=true\n", "unknown"),
    ("schema_version=2\n", "schema_version"),
])
def test_job_rejects_unsupported_controls(job, quiet_roots, change, message):
    text = job.read_text(encoding="utf-8")
    job.write_text(change + text.replace("schema_version=1\n", "") if change.startswith("schema_version") else change + text, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        module.load_job(job)


def test_nonempty_destination_is_never_merged(job, quiet_roots):
    destination = job.parent / "destination"
    destination.mkdir()
    (destination / "keep.txt").write_text("operator data", encoding="utf-8")
    with pytest.raises(ValueError, match="new or empty"):
        module.load_job(job)
    assert (destination / "keep.txt").read_text(encoding="utf-8") == "operator data"


def test_destination_cannot_overlap_media(job, quiet_roots):
    job.write_text(job.read_text(encoding="utf-8").replace("profile='destination'", "profile='media/child'"), encoding="utf-8")
    with pytest.raises(ValueError, match="overlaps"):
        module.load_job(job)


@pytest.mark.parametrize("pending,missing,rejected,expected", [(0, 0, 0, 0), (1, 0, 0, 2), (0, 1, 0, 2), (0, 0, 1, 2)])
def test_operator_status_keeps_valid_import_without_hashing(job, quiet_roots, monkeypatch, pending, missing, rejected, expected):
    parsed = module.load_job(job)
    monkeypatch.setattr(module, "write_exchange", lambda *a, **k: {"summary": {"recoveryMissingSets": missing, "skippedKnown": 0}})
    monkeypatch.setattr(module, "command_prefix", lambda *a: ["sample-client"])
    calls = []
    def run(command, timeout):
        calls.append(command)
        if command[-1] == "reconcile-shared-files":
            return {"hashedCount": 0, "completedReadBytes": 0, "activeHashCount": 0, "running": False,
                    "plannedHashCount": pending, "statFailedCount": 0, "skippedFailedCount": 0, "skippedIntakeCount": 0,
                    "scannedCount": 1}
        return {"rejectedRecoverySets": rejected}
    monkeypatch.setattr(module.audit, "run_json", run)
    for name in ("validate_imported_hashes", "validate_stock_records", "validate_native_bindings", "profile_counts"):
        monkeypatch.setattr(module.audit, name, lambda *a, **k: {})
    code, report = module.run_job(parsed)
    assert code == expected
    assert report["destinationModified"]
    assert len(calls) == 2
    assert all("import-emule-profile" in c or "reconcile-shared-files" in c for c in calls)
    assert Path(report["report"]).is_file()


@pytest.fixture
def directory_alias(tmp_path):
    """Create a real Windows junction or Unix directory symlink in the test root."""
    actual, alias = tmp_path / "actual media", tmp_path / "alias"
    actual.mkdir()
    if os.name == "nt":
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(actual)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    else:
        alias.symlink_to(actual, target_is_directory=True)
    assert alias.samefile(actual)
    return alias, actual


def test_physical_overlap_handles_aliases_and_nonexistent_children(directory_alias):
    alias, actual = directory_alias
    assert module.paths_overlap(alias, actual / "new" / "profile")
    assert module.paths_overlap(actual, alias / "new" / "reports")
    assert not module.paths_overlap(actual, actual.with_name("actual media-other"))


@pytest.mark.skipif(os.name != "nt", reason="Windows mapping semantics")
def test_windows_mapping_accepts_junction_identity(job, quiet_roots, directory_alias):
    alias, actual = directory_alias
    text = job.read_text(encoding="utf-8").replace("host='media'", "host=" + json.dumps(str(actual)))
    text = text.replace("target=" + json.dumps(str(job.parent / "media")), "target=" + json.dumps(str(alias)))
    job.write_text(text, encoding="utf-8")
    module.load_job(job)


@pytest.mark.parametrize("output", [False, True])
def test_preflight_rejects_profile_or_reports_inside_aliased_share(job, quiet_roots, directory_alias, monkeypatch, output):
    if os.name != "nt":
        pytest.skip("Windows unmapped stock root")
    alias, actual = directory_alias
    text = job.read_text(encoding="utf-8").split("[[path_mappings]]")[0]
    text = text.replace("directory='reports'" if output else "profile='destination'",
                        ("directory=" if output else "profile=") + json.dumps(str(actual / "new")))
    job.write_text(text, encoding="utf-8")
    monkeypatch.setattr(module.export, "discover_shared_roots", lambda *a: [SimpleNamespace(path=str(alias))])
    with pytest.raises(ValueError, match="overlaps"):
        module.load_job(job)
    assert not (actual / "new").exists()


def test_failure_retains_diagnostic(job, quiet_roots, monkeypatch):
    parsed = module.load_job(job)
    def fail(*args, **kwargs):
        raise RuntimeError("sample export failure")
    monkeypatch.setattr(module, "write_exchange", fail)
    code, report = module.run_job(parsed)
    assert code == 1 and not report["destinationModified"]
    assert "sample export failure" in Path(report["report"]).read_text(encoding="utf-8")


def test_docker_command_is_network_none_and_media_readonly(job, quiet_roots, monkeypatch):
    from contextlib import ExitStack
    parsed = replace(module.load_job(job), backend="docker", image="local/sample")
    monkeypatch.setattr(module, "checked", lambda *a: None)
    monkeypatch.setattr(module, "remove_container", lambda *a: None)
    monkeypatch.setattr(module.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(module.os, "getgid", lambda: 1000, raising=False)
    with ExitStack() as cleanup:
        command = module.command_prefix(parsed, parsed.output, cleanup)
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--entrypoint") + 1] == "/usr/lib/emulebb-rust/emulebb-rust"
    assert sum("readonly" in x for x in command) == 2


@pytest.mark.native
def test_rejected_aich_keeps_md4_reuse_without_workspace(tmp_path):
    """A corrupt optional tree must reach reconciliation, not fail verification early."""
    if os.name != "nt":
        pytest.skip("Windows executable integration")
    from emule_test_harness.paths import get_workspace_output_root
    from emule_test_harness.profile_import_audit import create_import_fixture
    binary = get_workspace_output_root() / "tools/emulebb-rust/bin/emulebb-rust.exe"
    if not binary.is_file():
        pytest.skip("requires staged Rust executable")
    fixture = tmp_path / "fixture"
    create_import_fixture(fixture)
    cache = fixture / "stock/config/known2_64.met"
    data = bytearray(cache.read_bytes())
    # Fixture records contain root(20), count(4), and a single leaf(20).
    # Alter the second record's leaf; keep its framing and master unchanged.
    data[1 + 44 + 24] ^= 1
    cache.write_bytes(data)
    config = tmp_path / "job.toml"
    config.write_text('\n'.join([
        'schema_version=1', '[source]', 'profile=' + json.dumps(str(fixture / 'stock')),
        '[target]', 'backend="windows"', 'profile=' + json.dumps(str(tmp_path / 'destination')),
        'binary=' + json.dumps(str(binary)), '[output]', 'directory=' + json.dumps(str(tmp_path / 'reports')),
    ]), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in
           ("EMULEBB_WORKSPACE_ROOT", "EMULEBB_WORKSPACE_OUTPUT_ROOT", "CARGO_TARGET_DIR", "X_LOCAL_IP")}
    script = Path(__file__).resolve().parents[2] / "scripts/import-emule-profile.py"
    result = subprocess.run([sys.executable, "-B", str(script), "--config", str(config)],
                            env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 2, result.stdout + result.stderr
    report = json.loads(next((tmp_path / "reports").glob("*/summary.json")).read_text(encoding="utf-8"))
    assert report["import"]["rejectedRecoverySets"] == 1
    assert report["hashValidation"]["unavailableRecoverySets"] == 1
    assert report["reconciliation"]["reusedCount"] == 4
    assert report["reconciliation"]["plannedHashCount"] == 0
    assert report["reconciliation"]["completedReadBytes"] == 0
    assert report["bindingValidation"]["verifiedPathBindings"] == 4


@pytest.mark.native
def test_linux_docker_job_from_independent_checkout(tmp_path):
    """Run the Linux operator path against real Docker and a metadata-capable host view."""
    if os.name != "nt" or not os.environ.get("EMULEBB_IMPORT_TEST_IMAGE"):
        pytest.skip("requires Windows/WSL and EMULEBB_IMPORT_TEST_IMAGE")
    from contextlib import ExitStack
    from emule_test_harness import emule_profile_export as export
    from emule_test_harness.profile_import_audit import create_import_fixture
    fixture = tmp_path / "fixture"
    create_import_fixture(fixture)
    state = tmp_path / "linux-state"
    state.mkdir()
    control = tmp_path / "control"
    control.mkdir()
    image = os.environ["EMULEBB_IMPORT_TEST_IMAGE"]
    prep = module.ImportJob(export.load_export_job(fixture / "windows.toml"), "wsl-docker", state,
                            control, None, image, "Ubuntu", (), 120)
    with ExitStack() as cleanup:
        prefix = module.command_prefix(prep, control, cleanup)
        view = next(arg.split("src=", 1)[1].split(",", 1)[0] for arg in prefix if "dst=/profile" in arg)
        def linux_path(path):
            return subprocess.check_output(["wsl.exe", "-d", "Ubuntu", "--", "wslpath", "-a", "-u", path.as_posix()], text=True).strip()
        config = state / "linux.toml"
        config.write_text(f'''schema_version=1
[source]
profile={json.dumps(linux_path(fixture / 'stock'))}
[target]
backend="docker"
image={json.dumps(image)}
profile={json.dumps(view + '/profile')}
[output]
directory={json.dumps(view + '/reports')}
[[path_mappings]]
source={json.dumps(str(fixture / 'shared'))}
host={json.dumps(linux_path(fixture / 'shared'))}
target="/data/sample"
''', encoding="utf-8")
        repo = Path(__file__).resolve().parents[2]
        result = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "python3", "-B",
                                 linux_path(repo / "scripts/import-emule-profile.py"), "--config", view + "/linux.toml"],
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(next((state / "reports").glob("*/summary.json")).read_text(encoding="utf-8"))
        assert report["reconciliation"]["reusedCount"] == 4
        assert report["reconciliation"]["plannedHashCount"] == 0
        assert report["hashValidation"]["verifiedRecoverySets"] == 3
