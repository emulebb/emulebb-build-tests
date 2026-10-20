"""Unit tests for the solo scripted-capture launcher (scripts/soak-scripted-capture.py)."""

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from emule_test_harness.scripted_actions import ScriptedAction

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CAPTURE_SCRIPT = REPO_ROOT / "scripts" / "soak-scripted-capture.py"


def _load_capture() -> ModuleType:
    spec = importlib.util.spec_from_file_location("soak_scripted_capture_script", CAPTURE_SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_capture_secident_knob_defaults_on() -> None:
    module = _load_capture()

    args = module.build_parser().parse_args(["--client", "mfc"])
    assert args.secident == "on"

    off_args = module.build_parser().parse_args(["--client", "mfc", "--secident", "off"])
    assert off_args.secident == "off"


def test_direct_capture_parser_exposes_connectivity_and_total_download_deadline() -> None:
    module = _load_capture()

    args = module.build_parser().parse_args(
        ["--client", "rust", "--route", "direct", "--connectivity", "firewalled"]
    )

    assert args.route == "direct"
    assert args.connectivity == "firewalled"
    assert args.download_timeout_seconds > 0


@pytest.mark.parametrize(
    "value",
    ("../escape", "nested/case", r"nested\case", r"C:\absolute", ".", "..", "case..escape", "CON"),
)
def test_campaign_leaf_rejects_paths_and_unsafe_windows_names(value: str) -> None:
    module = _load_capture()

    with pytest.raises(RuntimeError, match="safe report-directory leaf"):
        module._campaign_leaf(value)


def test_campaign_leaf_returns_sanitized_retained_value() -> None:
    module = _load_capture()

    assert module._campaign_leaf("ci-054-native-case") == "ci-054-native-case"


def test_cli_maps_unexpected_failures_to_sanitized_harness_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_capture()
    monkeypatch.setattr(
        module,
        "main",
        lambda: (_ for _ in ()).throw(RuntimeError("private fixture path")),
    )

    assert module._cli_main() == 2
    stderr = capsys.readouterr().err
    assert stderr == "harness-failure: RuntimeError\n"
    assert "private fixture path" not in stderr


def test_cli_reports_sanitized_post_run_failure_taxonomy(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_capture()
    error = module.PostRunSafetyError(
        [("upnp-absence-audit", RuntimeError("private router detail"))]
    )
    monkeypatch.setattr(module, "main", lambda: (_ for _ in ()).throw(error))

    assert module._cli_main() == 2
    stderr = capsys.readouterr().err
    assert stderr == (
        "harness-failure: PostRunSafetyError: Post-run safety failures: "
        "upnp-absence-audit:RuntimeError\n"
    )
    assert "private router detail" not in stderr


def test_capture_exception_tracking_keeps_python_310_compatibility() -> None:
    source = CAPTURE_SCRIPT.read_text(encoding="utf-8")

    assert "sys.exc_info()[1]" in source
    assert "sys.exception()" not in source


def test_native_capture_filter_selects_only_exact_protocol_ports() -> None:
    module = _load_capture()

    capture_filter = module._native_capture_filter(
        local_address="192.0.2.10",
        rest_port=4731,
        tcp_ports=(4662, 4661, 4662),
        udp_ports=(4672, 1900, 4665, 4672),
    )

    assert capture_filter == (
        "host 192.0.2.10 and not tcp port 4731 and "
        "(tcp port 4661 or tcp port 4662 or udp port 1900 or udp port 4665 or udp port 4672)"
    )


def test_gather_recording_preserves_relative_paths(tmp_path: Path) -> None:
    module = _load_capture()
    source = tmp_path / "source"
    (source / "tcp").mkdir(parents=True)
    (source / "udp").mkdir()
    (source / "tcp" / "events.jsonl").write_text("tcp\n", encoding="utf-8")
    (source / "udp" / "events.jsonl").write_text("udp\n", encoding="utf-8")

    copied = module.gather_recording(source, tmp_path / "recording", 0.0)

    assert copied == 2
    assert (tmp_path / "recording" / "tcp" / "events.jsonl").read_text(encoding="utf-8") == "tcp\n"
    assert (tmp_path / "recording" / "udp" / "events.jsonl").read_text(encoding="utf-8") == "udp\n"


def test_gather_recording_fails_on_destination_collision(tmp_path: Path) -> None:
    module = _load_capture()
    source = tmp_path / "source"
    destination = tmp_path / "recording"
    source.mkdir()
    destination.mkdir()
    (source / "events.jsonl").write_text("new\n", encoding="utf-8")
    (destination / "events.jsonl").write_text("old\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="collision"):
        module.gather_recording(source, destination, 0.0)

    assert (destination / "events.jsonl").read_text(encoding="utf-8") == "old\n"


def test_gather_recording_fails_on_copy_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_capture()
    source = tmp_path / "source"
    source.mkdir()
    (source / "events.jsonl").write_text("event\n", encoding="utf-8")
    monkeypatch.setattr(module.shutil, "copy2", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))

    with pytest.raises(RuntimeError, match="Could not copy"):
        module.gather_recording(source, tmp_path / "recording", 0.0)


def test_gather_recording_fails_on_entry_stat_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_capture()
    source = tmp_path / "source"
    source.mkdir()
    broken = source / "events.jsonl"
    broken.write_text("event\n", encoding="utf-8")
    original_stat = Path.stat

    def fail_entry_stat(path: Path, *args: object, **kwargs: object):
        if path == broken:
            raise OSError
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fail_entry_stat)

    with pytest.raises(RuntimeError, match="Could not inspect a diagnostic dump entry"):
        module.gather_recording(source, tmp_path / "recording", 0.0)


def test_native_completion_verifies_fixture_without_retaining_name_or_hash(tmp_path: Path) -> None:
    module = _load_capture()
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "private.pdf").write_bytes(b"abc")
    action = ScriptedAction("action-0004", "download", {})

    markers: list[dict[str, object]] = []
    private, summary = module._verify_native_downloads(
        actions=[action],
        fixtures=[
            {
                "name": "private.pdf",
                "size": 3,
                "hash": "a448017aaf21d8525fc10ae87aa6729d",
            }
        ],
        incoming_dir=incoming,
        timeout_seconds=1.0,
        marker_writer=markers.append,
    )

    assert private[0]["status"] == "verified"
    assert private[0]["sizeVerified"] is True
    assert summary == [
        {
            "actionId": "action-0004",
            "status": "verified",
            "sizeBytes": 3,
            "sizeVerified": True,
            "ed2kVerified": True,
            "sha256Computed": True,
        }
    ]
    assert "private.pdf" not in str(summary)
    assert markers == [
        {
            "schema": "scripted_action_marker_v1",
            "marker": "end",
            "actionId": "action-0004",
            "kind": "download",
            "terminal": True,
            "status": "verified",
            "ts_utc": markers[0]["ts_utc"],
        }
    ]


def test_recording_archive_is_sanitized_and_retains_private_artifacts(tmp_path: Path) -> None:
    module = _load_capture()
    report = tmp_path / "rust-case"
    (report / "rust-profile" / "incoming").mkdir(parents=True)
    (report / "rust-profile" / "incoming" / "private.pdf").write_bytes(b"payload")
    (report / "dumps").mkdir()
    (report / "dumps" / "diag.jsonl").write_text("{}\n", encoding="utf-8")
    (report / "native-capture.pcapng").write_bytes(b"capture")
    (report / "results.json").write_text("{}", encoding="utf-8")
    (report / "markers.jsonl").write_text("{}\n", encoding="utf-8")
    (report / "capture-protocol-summary.txt").write_text("protocols", encoding="utf-8")

    private_evidence = report / "completion-private.json"
    private_evidence.write_text('{"private": true}', encoding="utf-8")
    archive = module.pack_recording(
        report,
        incoming_dir=report / "rust-profile" / "incoming",
        private_evidence_path=private_evidence,
    )

    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        classification_name = next(name for name in names if name.endswith("evidence-classification.json"))
        classification = json.loads(zipped.read(classification_name))
    assert not any(name.endswith("native-capture.pcapng") for name in names)
    assert not any(name.endswith("dumps/diag.jsonl") for name in names)
    assert not any("rust-profile" in name for name in names)
    assert not any("completion-private" in name for name in names)
    assert any(name.endswith("results.json") for name in names)
    assert any(name.endswith("markers.jsonl") for name in names)
    assert any(name.endswith("capture-protocol-summary.txt") for name in names)
    assert classification["archiveClassification"] == "sanitized-report"
    private_artifacts = tmp_path / "rust-case-private-artifacts"
    retained = private_artifacts / "downloaded-payloads" / "private.pdf"
    assert retained.read_bytes() == b"payload"
    assert (private_artifacts / "completion-private.json").is_file()
    assert (private_artifacts / "native-capture.pcapng").read_bytes() == b"capture"
    assert (private_artifacts / "dumps" / "diag.jsonl").is_file()
    assert not report.exists()


def test_recording_retains_nested_mfc_incoming_payloads(tmp_path: Path) -> None:
    module = _load_capture()
    report = tmp_path / "mfc-case"
    incoming = report / "mfc-profile" / "profiles" / "converged-soak" / "incoming"
    incoming.mkdir(parents=True)
    (incoming / "private.pdf").write_bytes(b"payload")
    (report / "results.json").write_text("{}", encoding="utf-8")
    (report / "markers.jsonl").write_text("", encoding="utf-8")

    module.pack_recording(report, incoming_dir=incoming)

    retained = tmp_path / "mfc-case-private-artifacts" / "downloaded-payloads" / "private.pdf"
    assert retained.read_bytes() == b"payload"


def test_pack_recording_fails_closed_when_private_move_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_capture()
    report = tmp_path / "rust-case"
    report.mkdir()
    capture = report / "native-capture.pcapng"
    capture.write_bytes(b"capture")
    (report / "results.json").write_text("{}", encoding="utf-8")
    (report / "markers.jsonl").write_text("", encoding="utf-8")
    original_replace = Path.replace

    def fail_capture_move(path: Path, destination: Path) -> Path:
        if path == capture:
            raise OSError
        return original_replace(path, destination)

    monkeypatch.setattr(Path, "replace", fail_capture_move)

    with pytest.raises(RuntimeError, match="Could not retain the private native packet capture"):
        module.pack_recording(report)

    assert not report.with_suffix(".zip").exists()


def test_pack_recording_reports_source_tree_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_capture()
    report = tmp_path / "rust-case"
    report.mkdir()
    (report / "results.json").write_text("{}", encoding="utf-8")
    (report / "markers.jsonl").write_text("", encoding="utf-8")
    monkeypatch.setattr(module.shutil, "rmtree", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))

    with pytest.raises(RuntimeError, match="source tree could not be removed"):
        module.pack_recording(report)

    assert report.with_suffix(".zip").is_file()
    assert report.is_dir()


def test_shared_inventory_wait_requires_all_files_and_idle_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_capture()
    shared = tmp_path / "shared"
    (shared / "nested").mkdir(parents=True)
    (shared / "one.bin").write_bytes(b"1")
    (shared / "nested" / "two.bin").write_bytes(b"2")
    assert module._approved_shared_file_count(
        [{"path": str(shared), "recursive": True}]
    ) == 2

    expected = module._approved_shared_file_identities(
        [{"path": str(shared), "recursive": True}]
    )
    first_identity, second_identity = sorted(expected)
    replies = iter(
        [
            {"data": {"runtimeDiagnostics": {"sharedFileCount": 1, "sharedHashingCount": 1}}},
            {
                "data": {
                    "items": [{"hash": first_identity[0], "sizeBytes": first_identity[1]}],
                    "total": 1,
                }
            },
            {"data": {"runtimeDiagnostics": {"sharedFileCount": 2, "sharedHashingCount": 0}}},
            {
                "data": {
                    "items": [
                        {"hash": first_identity[0], "sizeBytes": first_identity[1]},
                        {"hash": second_identity[0], "sizeBytes": second_identity[1]},
                    ],
                    "total": 2,
                }
            },
        ]
    )
    monkeypatch.setattr(module, "_http", lambda *_args, **_kwargs: next(replies))
    ticks = iter((0.0, 0.0, 1.0))
    result = module._wait_for_shared_inventory(
        client="mfc",
        base_url="http://127.0.0.1:1",
        api_key="test",
        expected_identities=expected,
        timeout_seconds=5.0,
        sleep=lambda _seconds: None,
        monotonic=lambda: next(ticks),
    )
    assert result == {
        "ready": True,
        "expectedFileCount": 2,
        "advertisedFileCount": 2,
        "hashingFileCount": 0,
        "identitySetMatched": True,
        "pollReadErrorCount": 0,
        "maxConsecutivePollReadErrors": 0,
    }


@pytest.mark.parametrize("include_expected_second", (False, True))
def test_shared_inventory_wait_rejects_substitution_or_extra_advertised_files(
    include_expected_second: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()
    expected = frozenset({("1" * 32, 10), ("2" * 32, 20)})
    items = [
        {"hash": "1" * 32, "sizeBytes": 10},
        {"hash": "3" * 32, "sizeBytes": 30},
    ]
    if include_expected_second:
        items.append({"hash": "2" * 32, "sizeBytes": 20})
    replies = iter(
        [
            {"data": {"runtimeDiagnostics": {"sharedHashingCount": 0}}},
            {"data": {"items": items, "total": len(items)}},
        ]
    )
    monkeypatch.setattr(module, "_http", lambda *_args, **_kwargs: next(replies))

    with pytest.raises(module.SharedInventorySafetyError):
        module._wait_for_shared_inventory(
            client="mfc",
            base_url="http://127.0.0.1:1",
            api_key="test",
            expected_identities=expected,
            timeout_seconds=0.5,
            sleep=lambda _seconds: None,
            monotonic=lambda: 0.0,
        )


def test_shared_inventory_reader_pages_and_retains_only_identity_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()
    requested: list[str] = []
    replies = iter(
        [
            {"data": {"items": [{"hash": "1" * 32, "sizeBytes": 10}], "total": 2}},
            {"data": {"items": [{"hash": "2" * 32, "sizeBytes": 20}], "total": 2}},
        ]
    )

    def request(_base_url: str, _api_key: str, path: str) -> dict[str, object]:
        requested.append(path)
        return next(replies)

    monkeypatch.setattr(module, "_http", request)
    identities, total = module._read_shared_inventory_identities("http://127.0.0.1:1", "test", page_size=1)

    assert identities == frozenset({("1" * 32, 10), ("2" * 32, 20)})
    assert total == 2
    assert requested == [
        "/api/v1/shared-files?offset=0&limit=1",
        "/api/v1/shared-files?offset=1&limit=1",
    ]


def test_shared_inventory_wait_retries_a_growing_catalog_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()
    expected = frozenset({("1" * 32, 10)})
    replies = iter(
        [
            {"data": {"sharedHashingCount": 1}},
            {
                "data": {
                    "items": [{"hash": "1" * 32, "sizeBytes": 10}],
                    "total": 0,
                }
            },
            {"data": {"sharedHashingCount": 0}},
            {
                "data": {
                    "items": [{"hash": "1" * 32, "sizeBytes": 10}],
                    "total": 1,
                }
            },
        ]
    )
    monkeypatch.setattr(module, "_http", lambda *_args, **_kwargs: next(replies))
    ticks = iter((0.0, 0.0))

    result = module._wait_for_shared_inventory(
        client="rust",
        base_url="http://127.0.0.1:1",
        api_key="test",
        expected_identities=expected,
        timeout_seconds=5.0,
        sleep=lambda _seconds: None,
        monotonic=lambda: next(ticks),
    )

    assert result == {
        "ready": True,
        "expectedFileCount": 1,
        "advertisedFileCount": 1,
        "hashingFileCount": 0,
        "identitySetMatched": True,
        "pollReadErrorCount": 1,
        "maxConsecutivePollReadErrors": 1,
    }


def test_shared_inventory_wait_bounds_persistently_incoherent_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()
    expected = frozenset({("1" * 32, 10)})

    def request(_base_url: str, _api_key: str, path: str) -> dict[str, object]:
        if path == "/api/v1/stats":
            return {"data": {"sharedHashingCount": 1}}
        return {
            "data": {
                "items": [{"hash": "1" * 32, "sizeBytes": 10}],
                "total": 0,
            }
        }

    monkeypatch.setattr(module, "_http", request)
    monkeypatch.setattr(
        module, "MAX_CONSECUTIVE_SHARED_INVENTORY_READ_ERRORS", 2
    )

    with pytest.raises(module.SharedInventoryPollingError):
        module._wait_for_shared_inventory(
            client="rust",
            base_url="http://127.0.0.1:1",
            api_key="test",
            expected_identities=expected,
            timeout_seconds=5.0,
            sleep=lambda _seconds: None,
            monotonic=lambda: 0.0,
        )


def test_shared_inventory_wait_fails_fast_on_malformed_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()
    replies = iter(
        [
            {"data": {"sharedHashingCount": 1}},
            {
                "data": {
                    "items": [{"hash": "invalid", "sizeBytes": 10}],
                    "total": 1,
                }
            },
        ]
    )
    monkeypatch.setattr(module, "_http", lambda *_args, **_kwargs: next(replies))

    with pytest.raises(RuntimeError, match="invalid shared-file identity"):
        module._wait_for_shared_inventory(
            client="rust",
            base_url="http://127.0.0.1:1",
            api_key="test",
            expected_identities=frozenset({("1" * 32, 10)}),
            timeout_seconds=5.0,
            sleep=lambda _seconds: pytest.fail("malformed identity was retried"),
            monotonic=lambda: 0.0,
        )


def test_rust_shared_state_uses_paged_inventory_total() -> None:
    module = _load_capture()

    advertised, hashing = module._shared_runtime_state(
        "rust",
        {
            "data": {
                "sharedFilesReady": True,
                "sharedFilesComplete": False,
                "sharedHashingCount": 4,
            }
        },
        {"data": {"items": [{}], "total": 46, "offset": 0, "limit": 1}},
    )

    assert advertised == 46
    assert hashing == 4


def test_mapping_state_wait_retains_only_sanitized_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()

    class Audit:
        @staticmethod
        def sanitized_counts() -> dict[str, object]:
            return {
                "expectedMapped": True,
                "expectedCount": 2,
                "presentCount": 2,
                "matchingLocalCount": 2,
                "foreignTargetCount": 0,
                "missingCount": 0,
                "observedStatus": "mapped",
                "passed": True,
            }

    monkeypatch.setattr(module, "verify_upnp_port_mappings", lambda *_args, **_kwargs: Audit())
    result = module._wait_for_mapping_state(
        local_address="192.0.2.10",
        tcp_ports=(4662,),
        udp_ports=(4672,),
        expected_mapped=True,
        timeout_seconds=1.0,
    )

    assert result["available"] is True
    assert result["passed"] is True
    assert "192.0.2.10" not in str(result)


def test_post_run_audits_attempt_every_invariant_after_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()
    calls: list[str] = []

    class Cleanup:
        @staticmethod
        def sanitized_counts() -> dict[str, object]:
            return {"removedCount": 2, "passed": True}

    def cleanup(*_args: object, **_kwargs: object) -> Cleanup:
        calls.append("cleanup")
        return Cleanup()

    def mapping(**_kwargs: object) -> dict[str, object]:
        calls.append("mapping")
        raise RuntimeError("private mapping detail")

    def clients(**_kwargs: object) -> dict[str, object]:
        calls.append("clients")
        raise RuntimeError("private process detail")

    def legacy(_roots: tuple[str, ...]) -> dict[str, object]:
        calls.append("legacy")
        return {"passed": True}

    def fingerprints(_roots: tuple[str, ...]) -> tuple[object, ...]:
        calls.append("fingerprints")
        return ()

    monkeypatch.setattr(module, "_wait_for_mapping_state", mapping)
    monkeypatch.setattr(module, "remove_exact_local_upnp_port_mappings", cleanup)
    monkeypatch.setattr(module, "_require_no_other_clients", clients)
    monkeypatch.setattr(module, "_require_clean_legacy_audit", legacy)
    monkeypatch.setattr(module, "fingerprint_forbidden_roots", fingerprints)
    monkeypatch.setattr(
        module,
        "compare_forbidden_root_fingerprints",
        lambda *_args: SimpleNamespace(changed_root_indices=()),
    )
    monkeypatch.setattr(module, "summarize_forbidden_root_metadata_audit", lambda _audit: {"passed": True})
    results: dict[str, object] = {}

    failures = module._run_post_run_safety_audits(
        local_address="192.0.2.10",
        tcp_ports=(4662,),
        udp_ports=(4672,),
        timeout_seconds=1.0,
        forbidden_roots=(r"X:\legacy",),
        forbidden_root_fingerprints_before=(),
        upnp_audits={},
        client_audits={},
        legacy_audits={},
        results_meta=results,
        remove_owned_upnp_mappings=True,
    )

    assert calls == ["cleanup", "mapping", "clients", "legacy", "fingerprints"]
    assert [(stage, type(error).__name__) for stage, error in failures] == [
        ("upnp-absence-audit", "RuntimeError"),
        ("client-process-audit", "RuntimeError"),
    ]
    assert results["upnpMappingAudits"]["cleanup"] == {
        "removedCount": 2,
        "passed": True,
    }
    assert results["legacyRootMetadataAudit"] == {"passed": True}


def test_post_run_failures_preserve_primary_error_with_sanitized_notes() -> None:
    module = _load_capture()
    primary = ValueError("private primary detail")

    module._preserve_post_run_failures(
        primary,
        [("upnp-absence-audit", RuntimeError("private audit detail"))],
    )

    assert primary.__notes__ == ["Additional post-run failure: upnp-absence-audit:RuntimeError"]
    assert "private audit detail" not in " ".join(primary.__notes__)


def test_post_run_failures_preserve_primary_on_python_310_without_add_note() -> None:
    module = _load_capture()

    class Python310StyleError:
        pass

    primary = Python310StyleError()
    module._preserve_post_run_failures(
        primary,
        [("upnp-absence-audit", RuntimeError("private audit detail"))],
    )
    assert not hasattr(primary, "__notes__")


def test_mfc_teardown_retains_clean_close_and_forced_kill_failures() -> None:
    module = _load_capture()

    class App:
        def kill(self) -> None:
            raise OSError("private kill detail")

    class LiveCommon:
        @staticmethod
        def close_app_cleanly(_app: App) -> None:
            raise RuntimeError("private close detail")

    failures = module._teardown_client(
        client="mfc",
        handles={"app": App()},
        mods={"live_common": LiveCommon()},
        base_url="",
        api_key="",
        sleep=lambda _seconds: None,
    )

    assert [(stage, type(error).__name__) for stage, error in failures] == [
        ("mfc-clean-teardown", "RuntimeError"),
        ("mfc-forced-teardown", "OSError"),
    ]
    with pytest.raises(module.PostRunSafetyError) as captured:
        module._preserve_post_run_failures(None, failures)
    assert "private close detail" not in str(captured.value)
    assert "private kill detail" not in str(captured.value)


def test_rust_teardown_accepts_verified_exit_after_lost_shutdown_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()

    class Process:
        @staticmethod
        def poll() -> int:
            return 0

    class LogHandle:
        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(
        module,
        "_http",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("private shutdown detail")
        ),
    )

    failures = module._teardown_client(
        client="rust",
        handles={"process": Process(), "logHandle": LogHandle()},
        mods={},
        base_url="http://192.0.2.1:1",
        api_key="private",
        sleep=lambda _seconds: None,
    )

    assert failures == []


def test_rust_teardown_retains_shutdown_failure_when_forced_stop_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()

    class Process:
        @staticmethod
        def poll() -> None:
            return None

    class LogHandle:
        @staticmethod
        def close() -> None:
            return None

    stopped: list[Process] = []
    monkeypatch.setattr(
        module,
        "_http",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("private shutdown detail")
        ),
    )
    monkeypatch.setattr(module, "stop_process_tree", stopped.append)

    process = Process()
    failures = module._teardown_client(
        client="rust",
        handles={"process": process, "logHandle": LogHandle()},
        mods={},
        base_url="http://192.0.2.1:1",
        api_key="private",
        sleep=lambda _seconds: None,
    )

    assert [(stage, type(error).__name__) for stage, error in failures] == [
        ("rust-clean-teardown", "RuntimeError")
    ]
    assert stopped == [process]
    assert "private shutdown detail" not in str(module.PostRunSafetyError(failures))


def test_connectivity_state_normalizes_rust_and_mfc_firewall_signals() -> None:
    module = _load_capture()

    rust = module._connectivity_state(
        "rust",
        {"data": {"ed2kConnected": True, "ed2kHighId": True, "kadFirewalled": False}},
        "upnp",
    )
    mfc = module._connectivity_state(
        "mfc",
        {
            "data": {
                "servers": {"connected": True, "lowId": True},
                "kad": {"firewalled": True},
            }
        },
        "firewalled",
    )

    assert rust["matchesExpectedCase"] is True
    assert mfc["matchesExpectedCase"] is True


def test_linux_document_term_selection_accepts_operator_phrase() -> None:
    module = _load_capture()
    assert module._select_linux_document_term(("public linux documents", "other")) == (
        "public linux documents"
    )
