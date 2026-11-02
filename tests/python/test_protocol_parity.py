from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from emule_test_harness.protocol_parity import (
    build_dumpcap_command,
    build_catalog_report,
    CATALOG_SCHEMA,
    compare_record_sets,
    default_catalog_path,
    NORMALIZED_EVIDENCE_SCHEMA,
    normalize_ed2k_records,
    normalize_udp_records,
    pcap_tool_status,
    REQUIRED_STOCK_COVERAGE_IDS,
    run_compare_cli,
    run_normalize_cli,
    run_validate_cli,
    validate_protocol_catalog,
)


def test_tracked_protocol_oracle_manifest_validates() -> None:
    validation = validate_protocol_catalog(default_catalog_path(Path(__file__).resolve().parents[2]))

    assert validation.errors == ()


def test_tracked_stock_oracle_owns_every_required_phase_four_behavior_once() -> None:
    manifest_path = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    coverage_ids = [coverage_id for group in payload["coverageGroups"] for coverage_id in group["coverageIds"]]

    assert len(REQUIRED_STOCK_COVERAGE_IDS) == 100
    assert len(coverage_ids) == len(set(coverage_ids))
    assert set(coverage_ids) == REQUIRED_STOCK_COVERAGE_IDS
    assert payload["stockAuthority"]["requiredCoverageCount"] == len(REQUIRED_STOCK_COVERAGE_IDS)


def test_catalog_report_records_per_id_evidence_and_complete_group_coverage() -> None:
    manifest_path = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    validation = validate_protocol_catalog(manifest_path)

    report = build_catalog_report(payload, validation)

    assert report["valid"] is True
    assert report["coverage"] == {
        "coveredGroupCount": 3,
        "coveredIdCount": 21,
        "groupVerdictCounts": {
            "parity": 3,
            "divergence": 0,
            "evidence-incomplete": 14,
            "not-observed": 0,
            "intentional-difference": 0,
        },
        "idVerdictCounts": {
            "parity": 21,
            "divergence": 0,
            "evidence-incomplete": 79,
            "not-observed": 0,
            "intentional-difference": 0,
        },
        "requiredGroupCount": 17,
        "requiredIdCount": 100,
    }
    assert report["unconfiguredAuthorityIds"] == []
    assert report["assets"]["classificationCounts"] == {
        "canonical": 6,
        "duplicate": 0,
        "historical": 2,
        "product-only": 2,
        "support": 11,
    }
    assert report["assets"]["cleanupCandidates"] == [
        "scripts/local-ed2k-search-soak.py",
        "scripts/native-windows-parity-campaign.py",
    ]

    assets = {row["path"]: row for row in payload["assetClassifications"]}
    assert assets["scripts/local-ed2k-server-state-campaign.py"]["classification"] == "support"
    assert assets["scripts/local-ed2k-search-soak.py"]["classification"] == "historical"
    server_queries = next(
        group for group in payload["coverageGroups"] if group["groupId"] == "server-query-reply"
    )
    assert server_queries["deterministicRunner"] == "scripts/deterministic-two-client-transfer.py"
    assert [row["coverageId"] for row in payload["coverageEvidence"]] == [
        "peer.startup.aich",
        "peer.startup.metadata-recovery",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.connect.fallback",
        "server.connect.obfuscated",
        "server.connect.plaintext",
        "server.login.request",
        "server.reply.search",
        "server.reply.sources",
        "server.reply.tcp-ident",
        "server.reply.tcp-status",
        "server.reply.udp-description",
        "server.reply.udp-status",
        "server.search.keyword",
        "server.source.tcp-obfuscated",
        "server.source.tcp-plain",
        "server.source.udp-v1",
        "server.source.udp-v2",
        "transfer.block.compressed",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][0]["coverageIds"] == [
        "queue.admission",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][1]["coverageIds"] == [
        "queue.admission",
        "transfer.block.compressed",
    ]
    assert payload["evidenceReceipts"][2]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][3]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.metadata-recovery",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][4]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.login.request",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][5]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.connect.plaintext",
        "server.login.request",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][6]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.connect.obfuscated",
        "server.login.request",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][7]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.connect.fallback",
        "server.login.request",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][8]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.search",
        "server.search.keyword",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][9]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.tcp-ident",
        "server.reply.tcp-status",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][10]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.udp-description",
        "server.reply.udp-status",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][11]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.sources",
        "server.source.tcp-plain",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][12]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.sources",
        "server.source.tcp-obfuscated",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][13]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.sources",
        "server.source.udp-v1",
        "transfer.block.uncompressed",
    ]
    assert payload["evidenceReceipts"][14]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.sources",
        "server.source.udp-v2",
        "transfer.block.uncompressed",
    ]


def test_stock_server_metadata_vectors_are_transport_and_opcode_exact() -> None:
    manifest_path = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = {
        row["coverageIds"][0]: row
        for row in payload["records"]
        if len(row.get("coverageIds", [])) == 1 and row["coverageIds"][0].startswith("server.reply.")
    }

    actual = {
        coverage_id: (
            row["transport"],
            row["direction"],
            row["opcode"],
            row["opcodeName"],
            row["fixtureEncoding"],
        )
        for coverage_id, row in records.items()
    }
    expected = {
        "server.reply.tcp-ident": ("tcp", "recv", "0x41", "OP_SERVERIDENT", "ed2k-frame"),
        "server.reply.tcp-status": ("tcp", "recv", "0x34", "OP_SERVERSTATUS", "ed2k-frame"),
        "server.reply.udp-description": (
            "udp",
            "recv",
            "0xA3",
            "OP_SERVER_DESC_RES",
            "ed2k-server-udp-datagram",
        ),
        "server.reply.udp-status": (
            "udp",
            "recv",
            "0x97",
            "OP_GLOBSERVSTATRES",
            "ed2k-server-udp-datagram",
        ),
    }
    assert expected.items() <= actual.items()


def test_stock_server_metadata_vector_rejects_encoded_request_opcode(tmp_path: Path) -> None:
    source = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(source.read_text(encoding="utf-8"))
    record = next(
        row for row in payload["records"] if row.get("coverageIds") == ["server.reply.udp-status"]
    )
    fixture = bytearray(base64.b64decode(record["fixtureBase64"]))
    fixture[1] = 0x96
    record["fixtureBase64"] = base64.b64encode(fixture).decode("ascii")
    record["payloadDigest"] = "sha256:" + hashlib.sha256(fixture).hexdigest()
    manifest = tmp_path / "request-opcode.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_protocol_catalog(manifest)

    assert any(
        "(server.reply.udp-status) encoded opcode is 0x96, expected 0x97" in error
        for error in validation.errors
    )


def test_catalog_report_keeps_partially_proven_group_incomplete() -> None:
    manifest_path = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["coverageEvidence"] = [
        {
            "coverageId": "transfer.block.uncompressed",
            "reason": "exact uncompressed transfer",
            "receiptIds": ["example"],
            "verdict": "parity",
        }
    ]

    report = build_catalog_report(payload, validate_protocol_catalog(manifest_path))

    assert report["coverage"]["coveredIdCount"] == 1
    assert report["coverage"]["coveredGroupCount"] == 0
    transfer = next(row for row in report["entries"] if row["groupId"] == "transfer-blocks")
    assert transfer["coveredCoverageIdCount"] == 1
    assert transfer["coverageIdCount"] == 4
    assert transfer["verdict"] == "evidence-incomplete"


def test_catalog_cli_json_report_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_validate_cli(["--test-repo-root", str(Path(__file__).resolve().parents[2]), "--format", "json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "emulebb-build-tests.protocol-parity-catalog-report"
    assert report["coverage"]["coveredGroupCount"] == 3


def test_stock_oracle_rejects_binary_digest_and_coverage_drift(tmp_path: Path) -> None:
    source = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["records"][-1]["payloadDigest"] = "sha256:" + "0" * 64
    payload["coverageGroups"][-1]["coverageIds"].remove("queue.admission")
    manifest = tmp_path / "drifted.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_protocol_catalog(manifest)

    assert any("payloadDigest does not match fixtureBase64" in error for error in validation.errors)
    assert any("missing required coverage IDs" in error for error in validation.errors)


def test_catalog_rejects_unproven_green_and_analysis_only_authority(tmp_path: Path) -> None:
    source = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["coverageGroups"][0]["authorityIds"].append("amule-head")
    payload["coverageEvidence"] = [{
        "coverageId": "server.login.request",
        "evidenceLayers": payload["coverageGroups"][0]["requiredEvidenceLayers"],
        "reason": "invalid synthetic green",
        "receiptIds": ["missing"],
        "verdict": "parity",
    }]
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_protocol_catalog(catalog)

    assert any("cannot use analysis-only amule-head" in error for error in validation.errors)
    assert any("references unknown receipt missing" in error for error in validation.errors)


def test_catalog_rejects_legacy_group_evidence(tmp_path: Path) -> None:
    source = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["coverageGroups"][0]["latestEvidence"] = {
        "reason": "obsolete group-wide verdict",
        "verdict": "evidence-incomplete",
    }
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_protocol_catalog(catalog)

    assert any("latestEvidence is obsolete" in error for error in validation.errors)


def test_catalog_rejects_unclassified_canonical_runner(tmp_path: Path) -> None:
    source = default_catalog_path(Path(__file__).resolve().parents[2])
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["assetClassifications"] = [
        row
        for row in payload["assetClassifications"]
        if row["path"] != "scripts/deterministic-two-client-transfer.py"
    ]
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(payload), encoding="utf-8")

    validation = validate_protocol_catalog(catalog)

    assert any("server-session deterministic runner is not classified" in error for error in validation.errors)


def test_protocol_oracle_manifest_rejects_raw_capture_fields(tmp_path: Path) -> None:
    manifest = tmp_path / "golden.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": CATALOG_SCHEMA,
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

    validation = validate_protocol_catalog(manifest)

    assert any("wire_hex" in error for error in validation.errors)


def test_protocol_oracle_manifest_rejects_unredacted_ipv4(tmp_path: Path) -> None:
    manifest = tmp_path / "golden.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": CATALOG_SCHEMA,
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

    validation = validate_protocol_catalog(manifest)

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
    assert payload["schema"] == NORMALIZED_EVIDENCE_SCHEMA
    assert payload["records"][0]["opcodeName"] == "KADEMLIA2_HELLO_REQ"


def test_compare_cli_detects_manifest_drift(tmp_path: Path) -> None:
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    payload = {
        "schema": NORMALIZED_EVIDENCE_SCHEMA,
        "records": [{"scenarioId": "a", "recordType": "udp-packet"}],
    }
    left.write_text(json.dumps(payload), encoding="utf-8")
    right.write_text(json.dumps({**payload, "records": payload["records"] * 2}), encoding="utf-8")

    assert run_compare_cli(["--left", str(left), "--right", str(right)]) == 1


def test_pcap_helper_reports_tool_availability_and_command_shape(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("emule_test_harness.protocol_parity.shutil.which", lambda name: f"C:/Tools/{name}.exe")

    status = pcap_tool_status()
    command = build_dumpcap_command(output_path=tmp_path / "capture.pcapng", capture_filter="udp port 4662", interface="1")

    assert status["dumpcap"] == "C:/Tools/dumpcap.exe"
    assert command[:2] == ("C:/Tools/dumpcap.exe", "-w")
    assert "udp port 4662" in command


def test_pcap_helper_fails_when_dumpcap_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("emule_test_harness.protocol_parity.shutil.which", lambda name: None)

    with pytest.raises(RuntimeError, match="dumpcap is not available"):
        build_dumpcap_command(output_path=tmp_path / "capture.pcapng", capture_filter="udp")
