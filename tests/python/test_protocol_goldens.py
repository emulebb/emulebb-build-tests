from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness.protocol_goldens import (
    build_dumpcap_command,
    compare_record_sets,
    default_golden_path,
    GOLDEN_SCHEMA_VERSION,
    normalize_ed2k_records,
    normalize_udp_records,
    pcap_tool_status,
    run_compare_cli,
    run_normalize_cli,
    validate_golden_manifest,
)


def test_tracked_protocol_oracle_manifest_validates() -> None:
    validation = validate_golden_manifest(default_golden_path(Path(__file__).resolve().parents[2]))

    assert validation.errors == ()


def test_protocol_oracle_manifest_rejects_raw_capture_fields(tmp_path: Path) -> None:
    manifest = tmp_path / "golden.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": GOLDEN_SCHEMA_VERSION,
                "scenarios": [{"scenarioId": "kad.example.v1", "protocol": "kad2"}],
                "records": [
                    {
                        "scenarioId": "kad.example.v1",
                        "recordType": "udp-packet",
                        "protocol": "kad2",
                        "transport": "udp",
                        "direction": "send",
                        "opcodeName": "KADEMLIA2_HELLO_REQ",
                        "payloadDigest": "sha256:" + "0" * 64,
                        "wire_hex": "1122",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    validation = validate_golden_manifest(manifest)

    assert any("wire_hex" in error for error in validation.errors)


def test_protocol_oracle_manifest_rejects_unredacted_ipv4(tmp_path: Path) -> None:
    manifest = tmp_path / "golden.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": GOLDEN_SCHEMA_VERSION,
                "scenarios": [{"scenarioId": "ed2k.example.v1", "protocol": "ed2k"}],
                "records": [
                    {
                        "scenarioId": "ed2k.example.v1",
                        "recordType": "ed2k-state",
                        "protocol": "ed2k",
                        "transport": "tcp",
                        "direction": "recv",
                        "flow": "source",
                        "stateId": "source.accept",
                        "payloadDigest": "sha256:" + "1" * 64,
                        "note": "connected to 93.184.216.34",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    validation = validate_golden_manifest(manifest)

    assert any("unredacted IPv4" in error for error in validation.errors)


def test_udp_jsonl_normalizer_builds_compact_opcode_buckets() -> None:
    records = normalize_udp_records(
        [
            {
                "direction": "send",
                "family": "kad",
                "opcode": "0x11",
                "opcode_name": "KADEMLIA2_HELLO_REQ",
                "wire_len": 2,
                "wire_hex": "E311",
            },
            {
                "direction": "recv",
                "family": "kad",
                "opcode": "0x44",
                "wire_len": 2,
                "wire_hex": "0244",
                "decoded_hex": "44",
            },
        ],
        scenario_id="kad.sample.v1",
    )

    by_opcode = {record["opcodeName"]: record for record in records}
    assert by_opcode["KADEMLIA2_HELLO_REQ"]["transportMode"] == "plaintext"
    assert by_opcode["KADEMLIA2_HELLO_REQ"]["payloadDigest"].startswith("sha256:")
    assert by_opcode["KADEMLIA2_PUBLISH_SOURCE_REQ"]["transportMode"] == "receiver_verify_key"


def test_ed2k_jsonl_normalizer_preserves_state_machine_shape() -> None:
    records = normalize_ed2k_records(
        [
            {
                "flow": "native_download",
                "phase": "connect",
                "direction": "meta",
                "state_id": "download.connect",
                "transport_mode": "obfuscated",
            },
            {
                "flow": "native_download",
                "phase": "packet",
                "direction": "recv",
                "opcode": 1,
                "opcode_name": "OP_HELLO",
                "payload_len": 1,
                "payload_hex": "01",
                "state_id": "download.hello",
                "transport_mode": "obfuscated",
            },
        ],
        scenario_id="ed2k.sample.v1",
    )

    assert records[0]["stateId"] == "download.connect"
    assert records[0]["opcode"] == "NONE"
    assert records[1]["opcode"] == "0x01"
    assert records[1]["payloadLength"] == 1


def test_compare_record_sets_reports_count_drift() -> None:
    left = [{"scenarioId": "a", "recordType": "udp-packet", "opcodeName": "KADEMLIA2_HELLO_REQ"}]
    right = left + left

    lines = compare_record_sets(left, right)

    assert lines == ['record={"opcodeName":"KADEMLIA2_HELLO_REQ","recordType":"udp-packet","scenarioId":"a"} left=1 right=2']


def test_normalize_cli_writes_manifest(tmp_path: Path) -> None:
    udp_jsonl = tmp_path / "udp.jsonl"
    udp_jsonl.write_text(
        json.dumps(
            {
                "direction": "send",
                "family": "kad",
                "opcode": "0x11",
                "opcode_name": "KADEMLIA2_HELLO_REQ",
                "wire_len": 1,
                "wire_hex": "11",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "candidate.json"

    assert run_normalize_cli(["--scenario-id", "kad.cli.v1", "--udp-jsonl", str(udp_jsonl), "--output", str(output)]) == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schemaVersion"] == GOLDEN_SCHEMA_VERSION
    assert payload["records"][0]["opcodeName"] == "KADEMLIA2_HELLO_REQ"


def test_compare_cli_detects_manifest_drift(tmp_path: Path) -> None:
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    payload = {
        "schemaVersion": GOLDEN_SCHEMA_VERSION,
        "records": [{"scenarioId": "a", "recordType": "udp-packet"}],
    }
    left.write_text(json.dumps(payload), encoding="utf-8")
    right.write_text(json.dumps({**payload, "records": payload["records"] * 2}), encoding="utf-8")

    assert run_compare_cli(["--left", str(left), "--right", str(right)]) == 1


def test_pcap_helper_reports_tool_availability_and_command_shape(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("emule_test_harness.protocol_goldens.shutil.which", lambda name: f"C:/Tools/{name}.exe")

    status = pcap_tool_status()
    command = build_dumpcap_command(output_path=tmp_path / "capture.pcapng", capture_filter="udp port 4662", interface="1")

    assert status["dumpcap"] == "C:/Tools/dumpcap.exe"
    assert command[:2] == ("C:/Tools/dumpcap.exe", "-w")
    assert "udp port 4662" in command


def test_pcap_helper_fails_when_dumpcap_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("emule_test_harness.protocol_goldens.shutil.which", lambda name: None)

    with pytest.raises(RuntimeError, match="dumpcap is not available"):
        build_dumpcap_command(output_path=tmp_path / "capture.pcapng", capture_filter="udp")
