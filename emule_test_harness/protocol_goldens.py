"""Protocol oracle golden-vector normalization and validation helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

GOLDEN_SCHEMA_VERSION = "emulebb-build-tests.protocol-oracle-golden.v1"
SENSITIVE_FIELD_NAMES = {
    "decoded_hex",
    "payload_hex",
    "peer",
    "raw_hex",
    "remote_addr",
    "ts",
    "ts_utc",
    "wire_hex",
}
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DIGEST_RE = re.compile(r"^(fnv1a64:0x[0-9A-F]{16}|sha256:[0-9a-f]{64})$")
HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")

KAD_OPCODE_NAME_BY_HEX = {
    "0x01": "KADEMLIA2_BOOTSTRAP_REQ",
    "0x09": "KADEMLIA2_BOOTSTRAP_RES",
    "0x11": "KADEMLIA2_HELLO_REQ",
    "0x19": "KADEMLIA2_HELLO_RES",
    "0x20": "KADEMLIA2_HELLO_RES_ACK",
    "0x21": "KADEMLIA2_REQ",
    "0x29": "KADEMLIA2_RES",
    "0x33": "KADEMLIA2_SEARCH_KEY_REQ",
    "0x34": "KADEMLIA2_SEARCH_SOURCE_REQ",
    "0x35": "KADEMLIA2_SEARCH_NOTES_REQ",
    "0x3B": "KADEMLIA2_SEARCH_RES",
    "0x43": "KADEMLIA2_PUBLISH_KEY_REQ",
    "0x44": "KADEMLIA2_PUBLISH_SOURCE_REQ",
    "0x45": "KADEMLIA2_PUBLISH_NOTES_REQ",
    "0x4B": "KADEMLIA2_PUBLISH_RES",
    "0x4C": "KADEMLIA2_PUBLISH_RES_ACK",
    "0x50": "KADEMLIA_FIREWALLED_REQ",
    "0x53": "KADEMLIA2_FIREWALLED2_REQ",
    "0x58": "KADEMLIA2_FIREWALLED_RES",
    "0x59": "KADEMLIA2_FIREWALLED_ACK_RES",
    "0x60": "KADEMLIA2_FIREWALLUDP",
    "0x61": "KADEMLIA2_FIREWALLUDP",
    "0x62": "KADEMLIA_FINDBUDDY_REQ",
    "0x63": "KADEMLIA_FINDBUDDY_RES",
    "0x64": "KADEMLIA_CALLBACK_REQ",
    "0x65": "KADEMLIA2_PING",
    "0x66": "KADEMLIA2_PONG",
}


@dataclass(frozen=True)
class ProtocolGoldenValidation:
    """Result of validating one protocol oracle golden manifest."""

    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Reports whether the manifest passed all validation checks."""

        return not self.errors


def default_golden_path(test_repo_root: Path) -> Path:
    """Returns the tracked protocol oracle golden manifest path."""

    return test_repo_root.resolve() / "manifests" / "protocol-oracle-golden.v1.json"


def load_json(path: Path) -> Any:
    """Loads one UTF-8 JSON document."""

    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Loads UTF-8 JSONL records from one tracing artifact."""

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            value = json.loads(stripped)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: JSONL rows must be objects")
            records.append(value)
    return records


def normalize_udp_records(records: Iterable[dict[str, Any]], *, scenario_id: str) -> list[dict[str, Any]]:
    """Normalizes tracing-harness UDP packet JSONL rows into compact oracle records."""

    normalized: list[dict[str, Any]] = []
    for record in records:
        direction = _clean_token(record.get("direction") or "-")
        family = _clean_token(record.get("family") or "udp")
        opcode = _normalize_opcode(record.get("opcode"))
        opcode_name = _clean_token(record.get("opcode_name") or KAD_OPCODE_NAME_BY_HEX.get(opcode, "UNKNOWN"))
        transport_mode = _clean_token(record.get("transport_mode") or _infer_udp_transport_mode(record))
        digest_source = _first_hex_value(record, ("decoded_hex", "wire_hex"))
        normalized.append(
            {
                "scenarioId": scenario_id,
                "recordType": "udp-packet",
                "protocol": "kad2" if family == "kad" else family,
                "transport": "udp",
                "direction": direction,
                "transportMode": transport_mode,
                "opcode": opcode,
                "opcodeName": opcode_name,
                "wireLength": _read_int(record.get("wire_len")),
                "payloadDigest": _sha256_hex_digest(digest_source),
            }
        )
    return sorted(normalized, key=_record_sort_key)


def normalize_ed2k_records(records: Iterable[dict[str, Any]], *, scenario_id: str) -> list[dict[str, Any]]:
    """Normalizes tracing-harness eD2K TCP JSONL rows into compact oracle records."""

    normalized: list[dict[str, Any]] = []
    for record in records:
        flow = _clean_token(record.get("flow") or "unknown")
        phase = _clean_token(record.get("phase") or record.get("state_label") or "session")
        direction = _clean_token(record.get("direction") or "meta")
        opcode = _normalize_opcode(record.get("opcode"))
        opcode_name = _clean_token(record.get("opcode_name") or "NONE")
        payload_hex = str(record.get("payload_hex") or record.get("raw_hex") or "")
        entry = {
            "scenarioId": scenario_id,
            "recordType": "ed2k-state",
            "protocol": "ed2k",
            "transport": "tcp",
            "direction": direction,
            "flow": flow,
            "stateId": _clean_token(record.get("state_id") or f"{flow}.{phase}"),
            "stateLabel": phase,
            "transportMode": _clean_token(record.get("transport_mode") or "unknown"),
            "opcode": opcode,
            "opcodeName": opcode_name,
            "payloadLength": _read_int(record.get("payload_len") or record.get("raw_len")),
            "payloadDigest": _sha256_hex_digest(payload_hex),
        }
        normalized.append(entry)
    return sorted(normalized, key=_record_sort_key)


def summarize_state_sequences(records: Iterable[dict[str, Any]], *, scenario_id: str) -> list[dict[str, Any]]:
    """Builds compact state-machine sequence records from normalized eD2K rows."""

    traces: dict[str, list[str]] = defaultdict(list)
    for record in records:
        trace_key = _clean_token(record.get("trace_key") or f"{record.get('flow', 'unknown')}:redacted")
        traces[trace_key].append(_clean_token(record.get("state_id") or record.get("phase") or "unknown"))

    sequence_counter: Counter[str] = Counter(" -> ".join(states) for states in traces.values() if states)
    sequence_records = [
        {
            "scenarioId": scenario_id,
            "recordType": "state-sequence",
            "protocol": "ed2k",
            "transport": "tcp",
            "sequence": sequence,
            "count": count,
        }
        for sequence, count in sorted(sequence_counter.items())
    ]
    return sorted(sequence_records, key=_record_sort_key)


def validate_golden_manifest(path: Path) -> ProtocolGoldenValidation:
    """Validates a tracked protocol oracle golden manifest."""

    errors: list[str] = []
    payload = load_json(path)
    if not isinstance(payload, dict):
        return ProtocolGoldenValidation(("manifest must be a JSON object",))
    if payload.get("schemaVersion") != GOLDEN_SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {GOLDEN_SCHEMA_VERSION}")
    scenarios = payload.get("scenarios")
    records = payload.get("records")
    if not isinstance(scenarios, list) or not scenarios:
        errors.append("scenarios must be a non-empty list")
        scenarios = []
    if not isinstance(records, list) or not records:
        errors.append("records must be a non-empty list")
        records = []

    scenario_ids = _validate_scenarios(scenarios, errors)
    _validate_records(records, scenario_ids, errors)
    _validate_no_sensitive_payload(payload, errors)
    return ProtocolGoldenValidation(tuple(errors))


def render_validation_lines(validation: ProtocolGoldenValidation, path: Path) -> list[str]:
    """Renders a concise validation summary for operators and CI logs."""

    lines = [f"Protocol oracle golden manifest: {path}", f"Protocol oracle golden validation: {'PASS' if validation.passed else 'FAIL'}"]
    for error in validation.errors:
        lines.append(f"FAIL {error}")
    return lines


def write_normalized_manifest(path: Path, *, scenarios: list[dict[str, Any]], records: list[dict[str, Any]]) -> None:
    """Writes one normalized protocol oracle manifest."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schemaVersion": GOLDEN_SCHEMA_VERSION,
        "description": "Normalized Kad/eD2K protocol oracle evidence. Raw packet captures stay in generated reports.",
        "scenarios": sorted(scenarios, key=lambda item: str(item.get("scenarioId") or "")),
        "records": sorted(records, key=_record_sort_key),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compare_record_sets(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[str]:
    """Compares two normalized protocol record sets and returns human-readable differences."""

    left_counter = Counter(_stable_record_key(record) for record in left)
    right_counter = Counter(_stable_record_key(record) for record in right)
    lines: list[str] = []
    for key in sorted(set(left_counter) | set(right_counter)):
        left_count = left_counter.get(key, 0)
        right_count = right_counter.get(key, 0)
        if left_count != right_count:
            lines.append(f"record={key} left={left_count} right={right_count}")
    return lines


def pcap_tool_status() -> dict[str, str | None]:
    """Returns passive capture tool availability without starting a capture."""

    return {
        "dumpcap": shutil.which("dumpcap"),
        "tshark": shutil.which("tshark"),
        "pktmon": shutil.which("pktmon"),
    }


def build_dumpcap_command(*, output_path: Path, capture_filter: str, interface: str | None = None) -> tuple[str, ...]:
    """Builds a passive dumpcap command line for operator-run packet capture."""

    dumpcap = shutil.which("dumpcap")
    if dumpcap is None:
        raise RuntimeError("dumpcap is not available")
    command = [dumpcap, "-w", str(output_path), "-f", capture_filter]
    if interface:
        command.extend(["-i", interface])
    return tuple(command)


def run_validate_cli(argv: list[str] | None = None) -> int:
    """Runs the protocol oracle golden validator CLI."""

    parser = argparse.ArgumentParser(description="Validate tracked protocol oracle golden manifests.")
    parser.add_argument("--test-repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--manifest-path", type=Path)
    args = parser.parse_args(argv)
    manifest_path = (args.manifest_path or default_golden_path(args.test_repo_root)).resolve()
    validation = validate_golden_manifest(manifest_path)
    for line in render_validation_lines(validation, manifest_path):
        print(line)
    return 0 if validation.passed else 1


def run_normalize_cli(argv: list[str] | None = None) -> int:
    """Runs the tracing-harness JSONL normalizer CLI."""

    parser = argparse.ArgumentParser(description="Normalize tracing-harness protocol JSONL dumps into oracle records.")
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--udp-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--ed2k-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    records: list[dict[str, Any]] = []
    raw_ed2k_records: list[dict[str, Any]] = []
    for path in args.udp_jsonl:
        records.extend(normalize_udp_records(load_jsonl(path), scenario_id=args.scenario_id))
    for path in args.ed2k_jsonl:
        loaded = load_jsonl(path)
        raw_ed2k_records.extend(loaded)
        records.extend(normalize_ed2k_records(loaded, scenario_id=args.scenario_id))
    records.extend(summarize_state_sequences(raw_ed2k_records, scenario_id=args.scenario_id))
    write_normalized_manifest(
        args.output,
        scenarios=[
            {
                "scenarioId": args.scenario_id,
                "protocol": "mixed",
                "source": "tracing-harness",
            }
        ],
        records=records,
    )
    return 0


def run_compare_cli(argv: list[str] | None = None) -> int:
    """Runs the normalized oracle record comparator CLI."""

    parser = argparse.ArgumentParser(description="Compare two normalized protocol oracle manifests.")
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    args = parser.parse_args(argv)
    left = load_json(args.left)
    right = load_json(args.right)
    lines = compare_record_sets(left.get("records", []), right.get("records", []))
    if lines:
        for line in lines:
            print(line)
        return 1
    print("Protocol oracle records match")
    return 0


def run_pcap_cli(argv: list[str] | None = None) -> int:
    """Runs an operator-facing passive capture helper."""

    parser = argparse.ArgumentParser(description="Inspect or launch optional passive packet capture helpers.")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--capture-filter", default="tcp or udp")
    parser.add_argument("--interface")
    parser.add_argument("--print-command", action="store_true")
    args = parser.parse_args(argv)

    if args.status:
        print(json.dumps(pcap_tool_status(), indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless --status is used")
    command = build_dumpcap_command(output_path=args.output, capture_filter=args.capture_filter, interface=args.interface)
    if args.print_command:
        print(subprocess.list2cmdline(command))
        return 0
    return subprocess.call(command)


def _validate_scenarios(scenarios: list[Any], errors: list[str]) -> set[str]:
    scenario_ids: set[str] = set()
    for index, value in enumerate(scenarios):
        if not isinstance(value, dict):
            errors.append(f"scenarios[{index}] must be an object")
            continue
        scenario_id = value.get("scenarioId")
        protocol = value.get("protocol")
        if not isinstance(scenario_id, str) or not scenario_id:
            errors.append(f"scenarios[{index}].scenarioId must be a non-empty string")
            continue
        if scenario_id in scenario_ids:
            errors.append(f"duplicate scenarioId: {scenario_id}")
        scenario_ids.add(scenario_id)
        if protocol not in {"ed2k", "kad2", "mixed"}:
            errors.append(f"scenarios[{index}].protocol must be ed2k, kad2, or mixed")
    return scenario_ids


def _validate_records(records: list[Any], scenario_ids: set[str], errors: list[str]) -> None:
    previous_key: tuple[str, ...] | None = None
    seen_required = {"ed2k", "kad2"}
    observed_protocols: set[str] = set()
    for index, value in enumerate(records):
        if not isinstance(value, dict):
            errors.append(f"records[{index}] must be an object")
            continue
        scenario_id = value.get("scenarioId")
        if scenario_id not in scenario_ids:
            errors.append(f"records[{index}].scenarioId must reference a declared scenario")
        protocol = value.get("protocol")
        if protocol not in {"ed2k", "kad2", "server_udp", "client_udp"}:
            errors.append(f"records[{index}].protocol has unsupported value")
        else:
            observed_protocols.add(protocol)
        record_type = value.get("recordType")
        if record_type not in {"wire-vector", "udp-packet", "ed2k-state", "state-sequence"}:
            errors.append(f"records[{index}].recordType has unsupported value")
        digest = value.get("payloadDigest")
        if digest is not None and (not isinstance(digest, str) or DIGEST_RE.match(digest) is None):
            errors.append(f"records[{index}].payloadDigest is malformed")
        key = _record_sort_key(value)
        if previous_key is not None and key < previous_key:
            errors.append("records must be sorted by scenarioId, recordType, transport, direction, opcodeName, stateId")
            break
        previous_key = key
    missing_protocols = seen_required - observed_protocols
    for protocol in sorted(missing_protocols):
        errors.append(f"records must include at least one {protocol} scenario record")


def _validate_no_sensitive_payload(value: Any, errors: list[str], path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in SENSITIVE_FIELD_NAMES:
                errors.append(f"{child_path} is not allowed in tracked protocol goldens")
            _validate_no_sensitive_payload(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_sensitive_payload(child, errors, f"{path}[{index}]")
    elif isinstance(value, str) and IPV4_RE.search(value):
        errors.append(f"{path} contains an unredacted IPv4 address")


def _record_sort_key(record: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(record.get("scenarioId") or ""),
        str(record.get("recordType") or ""),
        str(record.get("transport") or ""),
        str(record.get("direction") or ""),
        str(record.get("opcodeName") or ""),
        str(record.get("flow") or ""),
        str(record.get("stateId") or ""),
        str(record.get("sequence") or ""),
    )


def _stable_record_key(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _normalize_opcode(value: Any) -> str:
    if value is None:
        return "NONE"
    if isinstance(value, int):
        return f"0x{value:02X}"
    text = str(value).strip()
    if not text or text.lower() == "null":
        return "NONE"
    if text.lower().startswith("0x"):
        return f"0x{int(text, 16):02X}"
    return f"0x{int(text):02X}"


def _clean_token(value: Any) -> str:
    text = str(value).strip()
    return text if text else "unknown"


def _read_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _first_hex_value(record: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and HEX_RE.match(value):
            return value
    return ""


def _sha256_hex_digest(hex_value: str) -> str:
    if not hex_value:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    if len(hex_value) % 2 != 0:
        raise ValueError("hex payload must have an even number of characters")
    return "sha256:" + hashlib.sha256(bytes.fromhex(hex_value)).hexdigest()


def _infer_udp_transport_mode(record: dict[str, Any]) -> str:
    wire_hex = str(record.get("wire_hex") or "")
    if len(wire_hex) < 2:
        return "unknown"
    first_byte = int(wire_hex[:2], 16)
    if first_byte in {0xE3, 0xE4, 0xE5, 0xA3, 0xC5, 0xD4}:
        return "plaintext"
    if (first_byte & 0x03) == 0x02:
        return "receiver_verify_key"
    return "node_id"


if __name__ == "__main__":
    raise SystemExit(run_validate_cli(sys.argv[1:]))
