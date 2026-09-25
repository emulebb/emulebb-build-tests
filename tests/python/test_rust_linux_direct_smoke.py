from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script_path = REPO_ROOT / "scripts" / "rust-linux-direct-smoke.py"
    spec = importlib.util.spec_from_file_location("rust_linux_direct_smoke_under_test", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_inputs(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"auto_browse": {"direct_bootstrap_transfers": rows}}), encoding="utf-8")


def transfer(name: str, file_hash: str) -> dict[str, object]:
    return {
        "name": name,
        "hash": file_hash,
        "size": 123,
        "sha256": "a" * 64,
    }


def test_safe_transfers_require_requested_types_and_put_pdf_first(tmp_path: Path) -> None:
    module = load_module()
    inputs = tmp_path / "inputs.json"
    write_inputs(
        inputs,
        [
            transfer("distribution.iso", "1" * 32),
            transfer("linux-manual.pdf", "2" * 32),
        ],
    )

    rows = module.load_safe_transfers(inputs, {"iso", "pdf"})

    assert [row["suffix"] for row in rows] == [".pdf", ".iso"]


def test_safe_transfers_fail_before_network_when_required_pdf_is_absent(tmp_path: Path) -> None:
    module = load_module()
    inputs = tmp_path / "inputs.json"
    write_inputs(inputs, [transfer("distribution.iso", "1" * 32)])

    with pytest.raises(RuntimeError, match=r"missing required transfer type\(s\): \.pdf"):
        module.load_safe_transfers(inputs, {"iso", "pdf"})


def test_safe_transfers_reject_paths_and_unapproved_extensions(tmp_path: Path) -> None:
    module = load_module()
    inputs = tmp_path / "inputs.json"
    write_inputs(inputs, [transfer("../payload.exe", "1" * 32)])

    with pytest.raises(RuntimeError, match="verified ISO/PDF"):
        module.load_safe_transfers(inputs)


def test_safe_transfers_reject_non_linux_pdf(tmp_path: Path) -> None:
    module = load_module()
    inputs = tmp_path / "inputs.json"
    write_inputs(inputs, [transfer("unrelated-manual.pdf", "1" * 32)])

    with pytest.raises(RuntimeError, match="verified ISO/PDF"):
        module.load_safe_transfers(inputs)


def test_safe_transfer_add_percent_encodes_stock_filename(monkeypatch) -> None:
    module = load_module()
    calls = []
    monkeypatch.setattr(module, "post_json", lambda *args: calls.append(args))

    module.add_allowlisted_transfer("http://192.0.2.1:4731", transfer("Linux Guide é.pdf", "a" * 32))

    assert calls[0][2]["link"] == "ed2k://|file|Linux%20Guide%20%C3%A9.pdf|123|" + "A" * 32 + "|/"


def test_sha256_file_hashes_completed_payload(tmp_path: Path) -> None:
    module = load_module()
    payload = tmp_path / "manual.pdf"
    payload.write_bytes(b"safe fixture\n")

    assert module.sha256_file(payload) == "aec7add6c399ba7576af4cf2a888838cf159bd90876b431f3de1ba3e032efd90"


def test_beta_probe_selection_reserves_required_iso_and_pdf() -> None:
    module = load_module()
    rows = [
        {"hash": str(index) * 32, "suffix": ".pdf"} for index in range(1, 5)
    ] + [{"hash": "a" * 32, "suffix": ".iso"}]

    selected = module.select_probe_rows(rows, 3, {"pdf", "iso"})

    assert {row["suffix"] for row in selected} == {".pdf", ".iso"}
    assert len(selected) == 3


def test_beta_completed_probe_requires_delivered_verified_bytes(tmp_path: Path) -> None:
    module = load_module()
    payload = b"safe fixture\n"
    delivered = tmp_path / "linux-manual.pdf"
    delivered.write_bytes(payload)
    row = {
        "name": delivered.name,
        "hash": "a" * 32,
        "suffix": ".pdf",
        "size": len(payload),
        "sha256": module.sha256_file(delivered),
    }
    probe = {"hash": row["hash"], "completedBytes": len(payload)}

    assert module.verify_completed_probe_types([probe], [row], tmp_path, {"pdf"}) == {"pdf": True}
    delivered.write_bytes(b"bad  fixture\n")
    with pytest.raises(RuntimeError, match="SHA-256"):
        module.verify_completed_probe_types([probe], [row], tmp_path, {"pdf"})


def test_packet_dump_monitor_counts_only_complete_fresh_records(tmp_path: Path) -> None:
    module = load_module()
    process = SimpleNamespace(poll=lambda: None)
    monitor = module.PacketDumpMonitor(tmp_path, process)
    dump = tmp_path / "emulebb-rust-ed2k-tcp-dump-test.jsonl"
    dump.write_bytes(b'{"schema":"ed2k_packet_v1"}\n{"schema":"diag_event_v1"')

    assert monitor.sample()["schemas"] == {"ed2k_packet_v1": 1}
    with dump.open("ab") as handle:
        handle.write(b"}\n")
    assert monitor.sample()["schemas"] == {"diag_event_v1": 1, "ed2k_packet_v1": 1}
    assert monitor.sample()["records"] == 2


def test_packet_dump_monitor_rejects_malformed_record(tmp_path: Path) -> None:
    module = load_module()
    monitor = module.PacketDumpMonitor(tmp_path, SimpleNamespace(poll=lambda: None))
    (tmp_path / "emulebb-rust-kad-udp-dump-test.jsonl").write_bytes(b"not-json\n")

    with pytest.raises(RuntimeError, match="Malformed live diagnostic"):
        monitor.sample()


def test_packet_dump_monitor_attributes_only_accepted_payload(tmp_path: Path) -> None:
    module = load_module()
    monitor = module.PacketDumpMonitor(tmp_path, SimpleNamespace(poll=lambda: None))
    rows = [
        {"schema": "diag_event_v1", "event": "source_count", "body": {"sourceCount": 4}},
        {"schema": "diag_event_v1", "event": "download_payload_accepted",
         "keys": {"fileHash": "a" * 32, "peer": "192.0.2.1:4662"}, "body": {"bytes": 128}},
        {"schema": "diag_event_v1", "event": "download_source_software",
         "keys": {"fileHash": "a" * 32, "peer": "192.0.2.1:4662"},
         "body": {"clientSoftware": "eMule v0.50a"}},
    ]
    dump = tmp_path / "emulebb-rust-diag-test.jsonl"
    dump.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    summary = monitor.sample()

    assert summary["acceptedPayloadBytes"] == 128
    assert summary["stockIdentifiedAcceptedBytes"] == 128
    assert summary["acceptedSourceCount"] == 1
    assert summary["peakSourceCount"] == 4
