from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from emule_test_harness.native_parity_inputs import (
    PathAuditResult,
    ProcessSnapshot,
    audit_client_processes,
    audit_open_handles,
    audit_process_references,
    compare_forbidden_root_fingerprints,
    fingerprint_forbidden_roots,
    find_handle_executable,
    load_ed2k_link_fixture,
    load_forbidden_roots_from_config,
    load_native_parity_config,
    load_shared_path_fixture,
    summarize_client_process_audit,
    summarize_forbidden_root_metadata_audit,
    summarize_native_parity_inputs,
    summarize_path_audit,
    validate_campaign_paths,
    windows_path_is_within,
)


def test_load_native_parity_config_resolves_relative_fixture_paths(tmp_path: Path) -> None:
    config = tmp_path / "inputs.local.json"
    config.write_text(
        json.dumps(
            {
                "native_parity": {
                    "ed2k_links_file": "links.txt",
                    "shared_paths_file": "paths.txt",
                    "capture_interface": "auto",
                    "forbidden_roots": ["Q:\\Retired"],
                }
            }
        ),
        encoding="utf-8",
    )

    loaded = load_native_parity_config(config)

    assert loaded.ed2k_links_file == (tmp_path / "links.txt").resolve()
    assert loaded.shared_paths_file == (tmp_path / "paths.txt").resolve()
    assert loaded.capture_interface == "auto"
    assert loaded.forbidden_roots == ("Q:\\Retired",)


def test_load_ed2k_link_fixture_preserves_fields(tmp_path: Path) -> None:
    fixture = tmp_path / "links.txt"
    fixture.write_text(
        "# operator-local fixture\n"
        "ed2k://|file|Alpha%20Document.pdf|12345|0123456789abcdef0123456789ABCDEF|"
        "h=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567|/\n"
        "ed2k://|file|Beta.bin|99|FEDCBA9876543210fedcba9876543210|/\n",
        encoding="utf-8",
    )

    links = load_ed2k_link_fixture(fixture)

    assert links[0].name == "Alpha Document.pdf"
    assert links[0].size == 12345
    assert links[0].ed2k_hash == "0123456789abcdef0123456789ABCDEF"
    assert links[0].aich_hash == "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    assert links[1].name == "Beta.bin"
    assert links[1].aich_hash is None


@pytest.mark.parametrize(
    "line, error",
    [
        ("https://example.invalid/file", "Invalid eD2K file link"),
        ("ed2k://|file|Alpha.bin|zero|" + "0" * 32 + "|/", "file size"),
        ("ed2k://|file|Alpha.bin|10|bad|/", "file hash"),
        ("ed2k://|file|Alpha.bin|10|" + "0" * 32 + "|h=bad|/", "AICH"),
    ],
)
def test_load_ed2k_link_fixture_rejects_invalid_rows_without_echoing_values(
    tmp_path: Path,
    line: str,
    error: str,
) -> None:
    fixture = tmp_path / "links.txt"
    fixture.write_text(line + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match=error) as caught:
        load_ed2k_link_fixture(fixture)

    assert line not in str(caught.value)


def test_load_shared_paths_normalizes_and_rejects_case_insensitive_duplicates(tmp_path: Path) -> None:
    fixture = tmp_path / "paths.txt"
    fixture.write_text("# shares\nC:\\Approved\\Alpha\\..\\Beta\nD:/Approved/Gamma\n", encoding="utf-8")

    assert load_shared_path_fixture(fixture) == ("C:\\Approved\\Beta", "D:\\Approved\\Gamma")

    fixture.write_text("C:\\Approved\\Beta\nc:\\approved\\beta\\\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Duplicate shared path"):
        load_shared_path_fixture(fixture)


def test_load_forbidden_roots_uses_only_operator_local_config(tmp_path: Path) -> None:
    config = tmp_path / "inputs.local.json"
    config.write_text(
        json.dumps(
            {
                "native_parity": {
                    "forbidden_roots": [
                        "Q:\\Legacy\\Binary",
                        "R:/Legacy/Incoming",
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    assert load_forbidden_roots_from_config(config) == (
        "Q:\\Legacy\\Binary",
        "R:\\Legacy\\Incoming",
    )

    config.write_text(
        json.dumps({"native_parity": {"forbidden_roots": ["Q:\\Legacy", "q:\\legacy\\"]}}),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="duplicates"):
        load_forbidden_roots_from_config(config)


def test_windows_containment_is_case_insensitive_and_component_aware() -> None:
    root = "Q:\\Legacy\\Incoming"

    assert windows_path_is_within("q:/legacy/incoming", root)
    assert windows_path_is_within("Q:\\LEGACY\\INCOMING\\nested\\file.part", root)
    assert not windows_path_is_within("Q:\\Legacy\\Incoming-old\\file.part", root)
    assert not windows_path_is_within("R:\\Legacy\\Incoming\\file.part", root)


def test_validate_campaign_paths_rejects_forbidden_descendants_without_path_leak() -> None:
    roots = ("Q:\\Private\\Denied",)

    allowed = validate_campaign_paths(
        {"profile": "C:\\Campaign\\Profile", "capture": "D:\\Campaign\\capture.pcapng"},
        roots,
    )
    assert [(entry.label, entry.path) for entry in allowed] == [
        ("profile", "C:\\Campaign\\Profile"),
        ("capture", "D:\\Campaign\\capture.pcapng"),
    ]

    with pytest.raises(RuntimeError) as caught:
        validate_campaign_paths({"incoming": "q:\\private\\denied\\incoming"}, roots)
    message = str(caught.value)
    assert "incoming" in message
    assert "root index 0" in message
    assert "Private" not in message


def test_process_audit_detects_executable_and_embedded_command_line_references() -> None:
    roots = ("Q:\\Denied", "R:\\Other")
    processes = (
        ProcessSnapshot(pid=10, name="first.exe", executable="q:\\denied\\first.exe"),
        ProcessSnapshot(
            pid=20,
            name="second.exe",
            executable="C:\\Allowed\\second.exe",
            command_line=("second.exe", "--incoming=R:\\Other\\Incoming"),
        ),
        ProcessSnapshot(pid=30, name="third.exe", executable="Q:\\Denied-old\\third.exe"),
    )

    result = audit_process_references(roots, processes=processes)

    assert result.available is True
    assert result.inspected_count == 3
    assert [(item.source, item.forbidden_root_index, item.pid) for item in result.findings] == [
        ("process_executable", 0, 10),
        ("process_command_line", 1, 20),
    ]
    assert summarize_path_audit(result) == {
        "available": True,
        "inspected_count": 3,
        "finding_count": 2,
        "finding_sources": {"process_command_line": 1, "process_executable": 1},
    }


def test_client_process_audit_finds_rust_and_mfc_and_allows_owned_pid() -> None:
    processes = (
        ProcessSnapshot(
            pid=10,
            name="emulebb-rust-diagnostics.exe",
            executable="C:\\Campaign\\emulebb-rust-diagnostics.exe",
        ),
        ProcessSnapshot(pid=20, name="eMule.exe", executable="D:\\Apps\\eMule.exe"),
        ProcessSnapshot(pid=30, name="emulebb.exe", executable="D:\\Apps\\emulebb.exe"),
        ProcessSnapshot(pid=40, name="python.exe", command_line=("python", "emulebb-rust.py")),
    )

    result = audit_client_processes(processes=processes, allowed_pids=(30,))

    assert result.available is True
    assert result.inspected_count == 4
    assert [(finding.pid, finding.client_family) for finding in result.findings] == [
        (10, "rust"),
        (20, "mfc"),
    ]
    summary = summarize_client_process_audit(result)
    assert summary == {
        "available": True,
        "inspected_count": 4,
        "finding_count": 2,
        "client_families": {"mfc": 1, "rust": 1},
    }
    rendered = json.dumps(summary)
    for sensitive in ("10", "20", "Campaign", "Apps", "emulebb-rust-diagnostics.exe", "eMule.exe"):
        assert sensitive not in rendered


def test_forbidden_root_fingerprint_detects_changes_without_exposing_paths(tmp_path: Path) -> None:
    protected = tmp_path / "operator-private-root"
    protected.mkdir()
    nested = protected / "private-name"
    nested.mkdir()
    payload = nested / "sensitive-title.part"
    payload.write_bytes(b"before")

    before = fingerprint_forbidden_roots((str(protected),))
    unchanged = fingerprint_forbidden_roots((str(protected),))
    unchanged_audit = compare_forbidden_root_fingerprints(before, unchanged)
    assert unchanged_audit.changed_root_indices == ()

    payload.write_bytes(b"after-write")
    after = fingerprint_forbidden_roots((str(protected),))
    audit = compare_forbidden_root_fingerprints(before, after)

    assert before[0].entry_count == 2
    assert before[0].directory_count == 1
    assert before[0].file_count == 1
    assert audit.changed_root_indices == (0,)
    summary = summarize_forbidden_root_metadata_audit(audit)
    assert summary == {
        "inspected_count": 1,
        "changed_root_count": 1,
        "changed_root_indices": [0],
    }
    rendered = json.dumps(summary)
    for sensitive in (str(protected), "operator-private-root", "private-name", "sensitive-title"):
        assert sensitive not in rendered


def test_forbidden_root_fingerprint_detects_missing_root_appearing(tmp_path: Path) -> None:
    protected = tmp_path / "initially-missing"

    before = fingerprint_forbidden_roots((str(protected),))
    assert before[0].exists is False
    protected.mkdir()
    after = fingerprint_forbidden_roots((str(protected),))

    assert after[0].exists is True
    assert compare_forbidden_root_fingerprints(before, after).changed_root_indices == (0,)


def test_handle_audit_is_optional_and_sanitizes_summary(tmp_path: Path) -> None:
    assert find_handle_executable(tmp_path / "missing-handle.exe") is None
    unavailable = audit_open_handles(("Q:\\Denied",), handle_executable=tmp_path / "missing-handle.exe")
    assert unavailable == PathAuditResult(available=False, inspected_count=0, findings=())

    executable = tmp_path / "handle.exe"
    executable.write_bytes(b"synthetic")
    commands: list[list[str]] = []

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="emulebb.exe pid: 321 type: File 7C: Q:\\Denied\\file.part\n",
            stderr="",
        )

    result = audit_open_handles(("Q:\\Denied",), handle_executable=executable, runner=runner)

    assert result.available is True
    assert result.findings[0].pid == 321
    assert commands[0][-1] == "Q:\\Denied"
    summary = summarize_path_audit(result)
    assert summary == {
        "available": True,
        "inspected_count": 1,
        "finding_count": 1,
        "finding_sources": {"open_handle": 1},
    }
    rendered = json.dumps(summary)
    assert "Denied" not in rendered
    assert "emulebb.exe" not in rendered
    assert "321" not in rendered


def test_native_input_summary_contains_counts_but_no_raw_values(tmp_path: Path) -> None:
    fixture = tmp_path / "links.txt"
    fixture.write_text(
        "ed2k://|file|Private%20Name.pdf|42|0123456789ABCDEF0123456789ABCDEF|"
        "h=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567|/\n",
        encoding="utf-8",
    )
    links = load_ed2k_link_fixture(fixture)

    summary = summarize_native_parity_inputs(
        links,
        ("C:\\Operator\\Share",),
        ("Q:\\Operator\\Denied",),
    )

    assert summary == {
        "ed2k_link_count": 1,
        "aich_link_count": 1,
        "shared_path_count": 1,
        "forbidden_root_count": 1,
    }
    rendered = json.dumps(summary)
    for sensitive in ("Private Name.pdf", "0123456789ABCDEF", "Operator", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        assert sensitive not in rendered


def test_native_harness_sources_do_not_embed_retired_operator_roots() -> None:
    repo_root = Path(__file__).resolve().parent.parent.parent
    sources = (
        repo_root / "scripts" / "soak-live-checkpoint.py",
        repo_root / "scripts" / "soak-scripted-capture.py",
        repo_root / "scripts" / "native-windows-parity-campaign.py",
    )
    rendered = "\n".join(path.read_text(encoding="utf-8") for path in sources).casefold()

    assert "h06t01" not in rendered
    assert "emule_incoming_loc" not in rendered
