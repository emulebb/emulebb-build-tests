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


def test_existing_destination_is_preserved_for_merge(job, quiet_roots):
    destination = job.parent / "destination"
    destination.mkdir()
    (destination / "keep.txt").write_text("operator data", encoding="utf-8")
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
def test_direct_directory_import_hashes_then_reuses(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows executable integration")
    import sqlite3
    from emule_test_harness.paths import get_workspace_output_root
    from emule_test_harness.profile_import_audit import create_import_fixture

    binary = get_workspace_output_root() / "tools/emulebb-rust/bin/emulebb-rust.exe"
    create_import_fixture(tmp_path / "fixture")
    profile = tmp_path / "profile"
    command = [
        str(binary),
        "--profile",
        str(profile),
        "import-shared-directories",
        str(tmp_path / "fixture/stock/config/shareddir.dat"),
    ]
    first = module.audit.run_json(command, 120)
    assert first["hashing"]["hashedCount"] == 4
    assert first["hashing"]["completedReadBytes"] == 19
    assert first["missingAichRecoverySets"] == 0
    second = module.audit.run_json(command, 120)
    assert second["hashing"]["hashedCount"] == 0
    assert second["hashing"]["reusedCount"] == 4
    with sqlite3.connect(profile / "emulebb-rust-metadata.db") as db:
        assert db.execute("SELECT count(*) FROM aich_recovery_sets").fetchone()[0] == 3
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'imported_%'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.native
@pytest.mark.parametrize("index", [0, 1])
def test_operator_selected_directory_lists_after_metadata_import(tmp_path, index):
    """Explicit operator inputs only: real media is read, never copied or modified."""
    config_path = os.environ.get("EMULEBB_IMPORT_DIRECTORY_TEST_INPUT")
    if os.name != "nt" or not config_path:
        pytest.skip("requires explicitly selected directory-test inputs")
    import hashlib
    import sqlite3
    from emule_test_harness.paths import get_workspace_output_root

    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    binary = get_workspace_output_root() / "tools/emulebb-rust/bin/emulebb-rust.exe"
    archive = Path(config["archive"])
    digest = hashlib.sha256(archive.read_bytes()).digest()
    directory_list = Path(config["directoryLists"][index])
    directory_digest = hashlib.sha256(directory_list.read_bytes()).digest()
    profile = tmp_path / "profile"
    if index == 1 and config.get("resumeProfile"):
        profile = Path(config["resumeProfile"])
    imported = before = None
    if index == 0:
        imported = module.audit.run_json(
            [
                str(binary),
                "--profile",
                str(profile),
                "import-emule-profile",
                str(archive),
            ],
            120,
        )
        before = module.audit.run_json(
            [str(binary), "--profile", str(profile), "reconcile-shared-files"], 120
        )
    report_path = tmp_path / "directory-test.json"
    report = {"status": "hashing-directory-list", "import": imported, "before": before}
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    command = [
        str(binary),
        "--profile",
        str(profile),
        "import-shared-directories",
        config["directoryLists"][index],
    ]
    if index == 0:
        with (
            (tmp_path / "hashing.stdout.json").open("w", encoding="utf-8") as stdout,
            (tmp_path / "hashing.stderr.log").open("w", encoding="utf-8") as stderr,
        ):
            result = subprocess.run(
                command, stdout=stdout, stderr=stderr, text=True, timeout=7200
            )
        assert result.returncode == 0, (
            f"directory import failed; inspect {report_path.parent}"
        )
        after = json.loads(
            (tmp_path / "hashing.stdout.json").read_text(encoding="utf-8")
        )
        repeat = module.audit.run_json(command, 7200)
        report.update(status="complete", after=after, repeat=repeat)
        assert after["reconciliation"]["plannedHashCount"] == 0
        assert after["reconciliation"]["statFailedCount"] == 0
        assert repeat["hashing"]["hashedCount"] == 0
        assert repeat["hashing"]["completedReadBytes"] == 0
    else:
        # WHY: the operator selected a large library for interruption testing,
        # not a full hash pass. Count durable paths and kill this process only.
        first = _hash_until_durable_paths(command, profile, tmp_path, 200, "first")
        second = _hash_until_durable_paths(
            command,
            profile,
            tmp_path,
            len(first) + config.get("additionalSampleFiles", 100),
            "resumed",
        )
        assert first.keys() <= second.keys()
        assert all(second[key] == value for key, value in first.items())
        reconciliation = module.audit.run_json(
            [str(binary), "--profile", str(profile), "reconcile-shared-files"], 7200
        )
        assert reconciliation["reusedCount"] >= len(second)
        assert reconciliation["plannedHashCount"] > 0
        report.update(
            status="sampled-and-interrupted",
            firstDurablePaths=len(first),
            resumedDurablePaths=len(second),
            reconciliation=reconciliation,
        )
    from emule_test_harness.ini import read_ini_text
    from emule_test_harness.mfc_known_met import normal_windows_display_path

    listed = [
        Path(line.strip()).resolve()
        for line in read_ini_text(directory_list).splitlines()
        if line.strip() and not line.strip().startswith(("#", ";"))
    ]
    with sqlite3.connect(profile / "emulebb-rust-metadata.db") as db:
        native_roots = db.execute(
            "SELECT p.native_path FROM shared_directory_roots r JOIN local_paths p ON p.id=r.path_id JOIN shared_directory_root_origins o ON o.root_id=r.id WHERE o.origin='explicit' AND r.enabled=1"
        ).fetchall()
    roots = [
        Path(normal_windows_display_path(row[0].decode("utf-16-le"))).resolve()
        for row in native_roots
    ]
    assert all(any(path.is_relative_to(root) for root in roots) for path in listed)
    assert all(
        not child.is_relative_to(parent)
        for child in roots
        for parent in roots
        if child != parent
    )
    assert all(root in listed or index == 0 for root in roots)
    report.update(listedRoots=len(listed), collapsedRoots=len(roots))
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    assert hashlib.sha256(archive.read_bytes()).digest() == digest
    assert hashlib.sha256(directory_list.read_bytes()).digest() == directory_digest
    with sqlite3.connect(profile / "emulebb-rust-metadata.db") as db:
        assert (
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'imported_%'"
            ).fetchone()[0]
            == 0
        )


def _hash_until_durable_paths(command, profile, output, target, label):
    """Kill an owned offline process after a bounded sample; retain committed hashes."""
    import sqlite3
    import time
    from contextlib import closing

    database = profile / "emulebb-rust-metadata.db"

    def snapshot():
        if not database.is_file():
            return {}
        try:
            with closing(
                sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1)
            ) as db:
                return dict(
                    db.execute(
                        "SELECT p.native_path,k.ed2k_hash FROM local_file_instances i JOIN local_paths p ON p.id=i.path_id JOIN known_files k ON k.id=i.known_file_id"
                    )
                )
        except sqlite3.OperationalError:
            return {}

    with (
        (output / f"{label}.stdout.log").open("w", encoding="utf-8") as stdout,
        (output / f"{label}.stderr.log").open("w", encoding="utf-8") as stderr,
    ):
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, text=True)
        deadline = time.monotonic() + 3600
        try:
            while len(snapshot()) < target:
                assert process.poll() is None, (
                    f"hash process exited early; inspect {output}"
                )
                assert time.monotonic() < deadline, "bounded hashing deadline exceeded"
                time.sleep(0.1)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)
    result = snapshot()
    assert len(result) >= target
    return result


@pytest.mark.native
@pytest.mark.parametrize("relocated", [False, True])
def test_rejected_aich_keeps_md4_reuse_without_workspace(tmp_path, relocated):
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
    if relocated:
        destination = fixture / "relocated-library"
        assert destination.resolve().is_relative_to(get_workspace_output_root().resolve())
        (fixture / "shared").rename(destination)
    cache = fixture / "stock/config/known2_64.met"
    data = bytearray(cache.read_bytes())
    # Fixture records contain root(20), count(4), and a single leaf(20).
    # Alter the second record's leaf; keep its framing and master unchanged.
    data[1 + 44 + 24] ^= 1
    cache.write_bytes(data)
    config = tmp_path / "job.toml"
    config.write_text(
        "\n".join(
            [
                "schema_version=1",
                "[source]",
                "profile=" + json.dumps(str(fixture / "stock")),
                "[target]",
                'backend="windows"',
                "profile=" + json.dumps(str(tmp_path / "destination")),
                "binary=" + json.dumps(str(binary)),
                "[output]",
                "directory=" + json.dumps(str(tmp_path / "reports")),
            ]
            + (["[[path_mappings]]",
                "source=" + json.dumps(str(fixture / "shared")),
                "host=" + json.dumps(str(destination)),
                "target=" + json.dumps(str(destination))] if relocated else [])
        ),
        encoding="utf-8",
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (
            "EMULEBB_WORKSPACE_ROOT",
            "EMULEBB_WORKSPACE_OUTPUT_ROOT",
            "CARGO_TARGET_DIR",
            "X_LOCAL_IP",
        )
    }
    script = Path(__file__).resolve().parents[2] / "scripts/import-emule-profile.py"
    result = subprocess.run(
        [sys.executable, "-B", str(script), "--config", str(config)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    report = json.loads(
        next((tmp_path / "reports").glob("*/summary.json")).read_text(encoding="utf-8")
    )
    assert report["import"]["rejectedRecoverySets"] == 1
    assert report["hashValidation"]["unavailableRecoverySets"] == 1
    assert report["reconciliation"]["reusedCount"] == 4
    assert report["reconciliation"]["plannedHashCount"] == 0
    assert report["reconciliation"]["completedReadBytes"] == 0
    assert report["bindingValidation"]["verifiedPathBindings"] == 4

    # Repair the optional source cache and merge into the same live profile.
    # Completed MD4 work must survive; only missing AICH is enriched.
    data[1 + 44 + 24] ^= 1
    cache.write_bytes(data)
    known = fixture / "stock/config/known.met"
    original_known = known.read_bytes()
    for scenario in ("clean", "recovery-conflict", "aich-conflict", "ed2k-conflict"):
        import base64
        import hashlib
        source = bytearray(original_known)
        cache.write_bytes(data)
        if scenario == "recovery-conflict":
            corrupt = bytearray(data)
            corrupt[1 + 44 + 24] ^= 1
            cache.write_bytes(corrupt)
        elif scenario == "aich-conflict":
            master = base64.b32encode(hashlib.sha1(b"abc").digest()).rstrip(b"=")
            assert source.count(master) == 1
            source = source.replace(master, b"A" * len(master))
        elif scenario == "ed2k-conflict":
            source[9:25] = bytes.fromhex("11" * 16)
        known.write_bytes(source)
        result = subprocess.run(
            [sys.executable, "-B", str(script), "--config", str(config)],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == (0 if scenario == "clean" else 2), result.stdout + result.stderr
        latest = max(
            (tmp_path / "reports").glob("*/summary.json"),
            key=lambda p: p.stat().st_mtime_ns,
        )
        merged = json.loads(latest.read_text(encoding="utf-8"))
        assert merged["hashValidation"]["verifiedRecoverySets"] == (2 if scenario in ("recovery-conflict", "aich-conflict") else 3)
        assert merged["hashValidation"]["retainedExistingRecoverySets"] == (1 if scenario == "recovery-conflict" else 0)
        assert merged["hashValidation"]["preservedConflictingRecords"] == (1 if scenario == "aich-conflict" else 0)
        assert merged["counts"]["known_files"] == 3
        assert merged["reconciliation"]["reusedCount"] == 4
        assert merged["reconciliation"]["completedReadBytes"] == 0
        assert merged["import"]["conflictingPaths"] == (1 if scenario in ("aich-conflict", "ed2k-conflict") else 0)


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
    prep = module.ImportJob(
        export.load_export_job(fixture / "windows.toml"),
        "wsl-docker",
        state,
        control,
        None,
        image,
        "Ubuntu",
        (export.PathMapping(str(fixture / "shared"), "/data/sample"),),
        120,
    )
    with ExitStack() as cleanup:
        prefix = module.command_prefix(prep, control, cleanup)
        view = next(
            arg.split("src=", 1)[1].split(",", 1)[0]
            for arg in prefix
            if "dst=/profile" in arg
        )

        def linux_path(path):
            return subprocess.check_output(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu",
                    "--",
                    "wslpath",
                    "-a",
                    "-u",
                    path.as_posix(),
                ],
                text=True,
            ).strip()

        config = state / "linux.toml"
        config.write_text(
            f"""schema_version=1
[source]
profile={json.dumps(linux_path(fixture / "stock"))}
[target]
backend="docker"
image={json.dumps(image)}
profile={json.dumps(view + "/profile")}
[output]
directory={json.dumps(view + "/reports")}
[[path_mappings]]
source={json.dumps(str(fixture / "shared"))}
host={json.dumps(linux_path(fixture / "shared"))}
target="/data/sample"
""",
            encoding="utf-8",
        )
        repo = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [
                "wsl.exe",
                "-d",
                "Ubuntu",
                "--",
                "python3",
                "-B",
                linux_path(repo / "scripts/import-emule-profile.py"),
                "--config",
                view + "/linux.toml",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(
            next((state / "reports").glob("*/summary.json")).read_text(encoding="utf-8")
        )
        assert report["reconciliation"]["reusedCount"] == 4
        assert report["reconciliation"]["plannedHashCount"] == 0
        assert report["hashValidation"]["verifiedRecoverySets"] == 3
        # Repeat against the Linux-created profile, then reject a corrupt
        # incoming optional tree while proving the existing tree is unchanged.
        for corrupt in (False, True):
            if corrupt:
                cache = fixture / "stock/config/known2_64.met"
                data = bytearray(cache.read_bytes())
                data[1 + 44 + 24] ^= 1
                cache.write_bytes(data)
            merged_run = subprocess.run(result.args, capture_output=True, text=True, timeout=120)
            assert merged_run.returncode == (2 if corrupt else 0), merged_run.stdout + merged_run.stderr
            latest = max((state / "reports").glob("*/summary.json"), key=lambda p: p.stat().st_mtime_ns)
            merged = json.loads(latest.read_text(encoding="utf-8"))
            assert merged["auditBaseline"]["contentRecords"] == 3
            assert merged["auditBaseline"]["recoverySets"] == 3
            assert merged["hashValidation"]["retainedExistingRecoverySets"] == int(corrupt)
            assert merged["reconciliation"]["reusedCount"] == 4
            assert merged["reconciliation"]["plannedHashCount"] == 0
            assert merged["reconciliation"]["completedReadBytes"] == 0
        # Direct native .dat import uses paths visible inside the container.
        # Exercise the other BOM encoding and the regular MD4/AICH pipeline.
        (control / "shareddir-linux.dat").write_bytes(
            b"\xfe\xff" + "/data/sample\n".encode("utf-16-be")
        )
        native_command = prefix + [
            "import-shared-directories",
            "/import/shareddir-linux.dat",
        ]
        first = module.audit.run_json(native_command, 120)
        assert first["hashing"]["hashedCount"] == 4
        assert first["hashing"]["completedReadBytes"] == 19
        repeated = module.audit.run_json(native_command, 120)
        assert repeated["hashing"]["hashedCount"] == 0
        assert repeated["hashing"]["reusedCount"] == 4
