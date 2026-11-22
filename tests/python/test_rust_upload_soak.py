from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from emule_test_harness import rust_upload_soak


def configure_workspace_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    workspace_root = tmp_path / "workspace"
    output_root = tmp_path / "out"
    workspace_root.mkdir()
    output_root.mkdir()
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    return workspace_root, output_root


def stage_dummy_rust_tools(output_root: Path) -> Path:
    bin_dir = output_root / "tools" / "emulebb-rust" / "bin"
    bin_dir.mkdir(parents=True)
    rust_exe = bin_dir / "emulebb-rust.exe"
    rust_exe.write_bytes(b"rust")
    return rust_exe


def test_utc_run_id_uses_canonical_format() -> None:
    now = rust_upload_soak.datetime(2026, 7, 15, 10, 11, 12, tzinfo=rust_upload_soak.UTC)

    assert rust_upload_soak.utc_run_id(now) == "20260715T101112Z"


def test_wsl_delivered_path_mapping_stays_in_owned_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _root, output = configure_workspace_env(monkeypatch, tmp_path)
    delivered = output / "leecher" / "incoming" / "file.bin"
    mapped = rust_upload_soak.wsl_metadata_path("/mnt/proof", delivered)
    assert rust_upload_soak.windows_output_path("/mnt/proof", mapped) == delivered.resolve()
    with pytest.raises(ValueError):
        rust_upload_soak.windows_output_path("/mnt/proof", "/mnt/foreign/file.bin")
    with pytest.raises(ValueError):
        rust_upload_soak.windows_output_path("/mnt/proof", "/mnt/proof/../foreign/file.bin")
    with pytest.raises(ValueError):
        rust_upload_soak.windows_output_path("/mnt/proof", "/mnt/proof/Windows/foreign.bin")


def test_native_profile_mount_cleans_up_after_seed_copy_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _root, output = configure_workspace_env(monkeypatch, tmp_path)
    profile = output / "profile"
    profile.mkdir()
    commands = []
    monkeypatch.setattr(rust_upload_soak.rust_ed2k, "wsl_path", lambda _path: "/mnt/c/seed")
    monkeypatch.setattr(rust_upload_soak.subprocess, "check_output", lambda *_args, **_kwargs: "1000\n")

    def run(command, **_kwargs):
        commands.append(command)
        if "cp" in command:
            raise rust_upload_soak.subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(rust_upload_soak.subprocess, "run", run)
    with pytest.raises(rust_upload_soak.subprocess.CalledProcessError):
        rust_upload_soak.mount_native_wsl_profile("/mnt/proof", profile, "/mnt/c/seed", 128)
    native = rust_upload_soak.wsl_metadata_path("/mnt/proof", profile)
    assert commands[-1] == ["wsl.exe", "--user", "root", "--", "umount", native]
    assert "size=128m,uid=1000,gid=1000" in commands[0]
    commands.clear()
    with pytest.raises(ValueError):
        rust_upload_soak.mount_native_wsl_profile("/mnt/proof", tmp_path / "outside", "/mnt/c/seed", 128)
    assert commands == []
    with pytest.raises(ValueError, match="separate pre-mount"):
        rust_upload_soak.mount_native_wsl_profile("/mnt/proof", profile, native, 128)
    assert commands == []


def test_parser_defaults_to_staged_rust_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    rust_exe = stage_dummy_rust_tools(output_root)

    args = rust_upload_soak.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])
    rust_upload_soak.validate_args(args)

    assert args.rust_exe == rust_exe
    assert args.duration_seconds == rust_upload_soak.DEFAULT_DURATION_SECONDS


def test_kad_wsl_mode_requires_staged_linux_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    stage_dummy_rust_tools(output_root)
    args = rust_upload_soak.build_parser().parse_args(
        ["--lan-bind-addr", "192.0.2.10", "--discovery-mode", "kad-wsl"]
    )

    with pytest.raises(ValueError, match="Linux Rust executable"):
        rust_upload_soak.validate_args(args)
    args.linux_rust_exe.parent.mkdir(parents=True, exist_ok=True)
    args.linux_rust_exe.write_bytes(b"linux rust")
    rust_upload_soak.validate_args(args)


def test_kad_recheck_waits_for_both_connected_peers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, str]] = []

    def request(base: str, method: str, path: str, _key: str, _body=None):
        calls.append((base, method, path))
        if path == "/api/v1/kad/operations/import-nodes-url":
            assert _body == {"url": "http://192.0.2.20/nodes.dat"}
            return {"imported": True}
        if path.startswith("/api/v1/kad/nodes"):
            return {"items": [{
                "ip": "192.0.2.20", "kadVersion": 9, "udpPort": 4672,
                "tcpPort": 4662, "udpFirewalled": False,
            }]}
        if method == "GET":
            return {"connected": True, "contactCount": 2}
        return {"operationQueued": True}

    monkeypatch.setattr(rust_upload_soak, "request_json", request)
    result = rust_upload_soak.recheck_kad_after_bootstrap(
        "http://seed", "http://leech", "local-key", "192.0.2.10",
        witness_nodes_url="http://192.0.2.20/nodes.dat",
    )

    assert result == {
        "seederConnectedContacts": 2,
        "leecherConnectedContacts": 2,
        "seederFirewallContacts": [{
            "sameBindIp": False,
            "kadVersion": 9,
            "udpPortPresent": True,
            "tcpPortPresent": True,
            "udpFirewalled": False,
        }],
        "seederEligibleFirewallHelpers": 1,
        "witnessImported": True,
        "recheckQueued": True,
    }
    assert calls == [
        ("http://seed", "GET", "/api/v1/kad"),
        ("http://leech", "GET", "/api/v1/kad"),
        ("http://seed", "POST", "/api/v1/kad/operations/import-nodes-url"),
        ("http://seed", "GET", "/api/v1/kad/nodes?limit=100"),
        ("http://seed", "POST", "/api/v1/kad/operations/recheck-firewall"),
    ]


def test_wsl_metadata_path_stays_within_output_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    profile = output_root / "soak" / "profile"

    mapped = rust_upload_soak.wsl_metadata_path("/mnt/metadata", profile)

    assert mapped.startswith("/mnt/metadata/")
    assert mapped.endswith("/out/soak/profile")
    with pytest.raises(ValueError, match="below the workspace output root"):
        rust_upload_soak.wsl_metadata_path("/mnt/metadata", workspace_root / "profile")


def test_canonical_ed2k_server_does_not_use_repo_override() -> None:
    assert rust_upload_soak.resolve_ed2k_server_repo_override(None) is None


def test_resolve_ed2k_server_repo_override_prefers_explicit_path(tmp_path: Path) -> None:
    override = tmp_path / "custom-ed2k-server"

    assert rust_upload_soak.resolve_ed2k_server_repo_override(override) == str(override)


def test_validate_args_rejects_unusable_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    stage_dummy_rust_tools(output_root)
    args = rust_upload_soak.build_parser().parse_args(
        ["--lan-bind-addr", "192.0.2.10", "--duration-seconds", "0"]
    )

    with pytest.raises(ValueError, match="duration-seconds"):
        rust_upload_soak.validate_args(args)

    args = rust_upload_soak.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10", "--api-key", "short"])
    with pytest.raises(ValueError, match="api-key"):
        rust_upload_soak.validate_args(args)


def test_write_payload_records_size_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    duplicate_path = tmp_path / "payload-again.bin"
    size = 4099

    result = rust_upload_soak.write_payload(path, size)
    duplicate = rust_upload_soak.write_payload(duplicate_path, size)

    data = path.read_bytes()
    duplicate_data = duplicate_path.read_bytes()
    assert len(data) == size
    assert data == duplicate_data
    assert len(set(data[:256])) > 64
    assert result == {
        "path": str(path),
        "sizeBytes": size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "contentKind": "deterministic-randbytes",
    }
    assert duplicate["sha256"] == result["sha256"]


def test_safe_counter_helpers_tolerate_missing_values() -> None:
    assert rust_upload_soak.safe_int(None) == 0
    assert rust_upload_soak.safe_int("12") == 12
    assert rust_upload_soak.safe_int("bad") == 0
    assert rust_upload_soak.safe_float(None) == 0.0
    assert rust_upload_soak.safe_float("1.5") == 1.5
    assert rust_upload_soak.safe_float("bad") == 0.0


def test_find_library_file_uses_the_exact_hash_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    file_hash = "00112233445566778899aabbccddeeff"
    row = {"hash": file_hash, "path": "/sample/incoming/payload.bin"}
    def read(_base, method, path, _key):
        assert method == "GET" and path == f"/api/v1/library/files/{file_hash}"
        return row
    monkeypatch.setattr(rust_upload_soak, "request_json", read)
    assert rust_upload_soak.find_library_file("http://127.0.0.1", "key", file_hash) == row


def test_find_library_file_distinguishes_absence_and_failure(monkeypatch):
    def missing(*_args):
        raise rust_upload_soak.RustRestFailure("not found", status=404, detail='{"error":{"code":"NOT_FOUND"}}')
    monkeypatch.setattr(rust_upload_soak, "request_json", missing)
    assert rust_upload_soak.find_library_file("http://127.0.0.1", "key", "a" * 32) is None
    def failed(*_args):
        raise rust_upload_soak.RustRestFailure("busy", status=503, detail='{"error":{"code":"PERSISTENCE_BUSY"}}')
    monkeypatch.setattr(rust_upload_soak, "request_json", failed)
    with pytest.raises(rust_upload_soak.RustRestFailure):
        rust_upload_soak.find_library_file("http://127.0.0.1", "key", "a" * 32)


def test_verify_download_delivery_checks_retained_terminal_job_and_exact_bytes(tmp_path: Path) -> None:
    delivered = tmp_path / "incoming" / "payload.bin"
    payload = rust_upload_soak.write_payload(delivered, 4096)
    download = {"id": "7", "state": "completed", "sizeBytes": 4096, "payloadVerified": True,
                "delivery": {"state": "delivered", "path": str(delivered), "ownership": "owned"}}
    result = rust_upload_soak.verify_download_delivery(download, payload, require_completion=True, require_delivered_path=True)
    assert result["ok"] is True and result["completed"] is True
    assert result["verifiedBytes"] == 4096
    assert result["deliveredPathPresent"] is True and result["deliveredFileExists"] is True
    assert result["deliveredFileSizeBytes"] == payload["sizeBytes"]
    assert result["deliveredSha256"] == payload["sha256"]


def test_verify_download_delivery_rejects_incomplete_job(tmp_path: Path) -> None:
    payload = rust_upload_soak.write_payload(tmp_path / "payload.bin", 4096)
    with pytest.raises(RuntimeError, match="did not complete verified delivery"):
        rust_upload_soak.verify_download_delivery({"state": "downloading", "sizeBytes": 4096,
            "payloadVerified": False, "delivery": {"state": "pending", "path": None}}, payload,
            require_completion=True, require_delivered_path=False, verified_bytes=1024)


@pytest.mark.parametrize("verified, delivery_state", [(False, "delivered"), (True, "pending")])
def test_delivery_requires_verified_terminal_state(tmp_path: Path, verified, delivery_state) -> None:
    delivered = tmp_path / "incoming" / "payload.bin"
    payload = rust_upload_soak.write_payload(delivered, 4096)
    with pytest.raises(RuntimeError, match="has not completed verified delivery"):
        rust_upload_soak.verify_download_delivery({"id": "7", "state": "completed", "sizeBytes": 4096,
            "payloadVerified": verified, "delivery": {"state": delivery_state, "path": str(delivered)}}, payload,
            require_completion=False, require_delivered_path=True)


def test_completed_delivery_still_requires_matching_file_bytes(tmp_path: Path) -> None:
    payload = rust_upload_soak.write_payload(tmp_path / "source.bin", 4096)
    delivered = tmp_path / "damaged.bin"
    delivered.write_bytes(b"damaged")
    with pytest.raises(RuntimeError, match="did not match the source payload"):
        rust_upload_soak.verify_download_delivery({"id": "7", "state": "completed", "sizeBytes": 4096,
            "payloadVerified": True, "delivery": {"state": "delivered", "path": str(delivered)}}, payload,
            require_completion=True, require_delivered_path=True)


@pytest.mark.parametrize("verified, expected", [(True, 4096), (False, 0)])
def test_progress_separates_retired_piece_presence_from_payload_verification(monkeypatch, verified, expected):
    monkeypatch.setattr(rust_upload_soak, "download_part_totals", lambda *_args: {
        "partCount": 0, "presentBytes": 0, "verifiedBytes": 0,
    })
    totals = rust_upload_soak._download_progress_totals("http://127.0.0.1", "key", {
        "id": "7", "sizeBytes": 4096, "state": "completed", "payloadVerified": verified,
    })
    assert totals == {"partCount": 0, "presentBytes": 0, "verifiedBytes": expected}


@pytest.mark.parametrize("conflict", [False, True])
def test_upload_cap_uses_observed_revision_and_does_not_retry(monkeypatch, conflict):
    calls = []
    def request(base, path, **kwargs):
        calls.append((base, path, kwargs))
        if kwargs.get("method") == "PATCH":
            assert kwargs["body"] == {
                "expectedRevision": "9007199254740993",
                "set": {"transfers": {"uploadLimitBytesPerSecond": 65536}},
            }
            if conflict:
                raise RuntimeError("SETTINGS_CONFLICT")
            return {"data": {"application": {"pendingRestart": []}}}
        return {"data": {}, "meta": {"settingsRevision": "9007199254740993"}}
    monkeypatch.setattr(rust_upload_soak, "http_json", request)
    if conflict:
        with pytest.raises(RuntimeError, match="SETTINGS_CONFLICT"):
            rust_upload_soak.patch_upload_limit("http://127.0.0.1:4711", "synthetic-key", 64)
    else:
        assert rust_upload_soak.patch_upload_limit("http://127.0.0.1:4711", "synthetic-key", 64) == {
            "application": {"pendingRestart": []}}
    assert len(calls) == 2
    assert all(path == "/api/v1/settings" and kwargs["api_key"] == "synthetic-key"
               for _, path, kwargs in calls)
