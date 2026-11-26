from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from emule_test_harness import amule_client


@pytest.mark.parametrize("allow_browse", [False, True])
def test_configure_profile_writes_isolated_daemon_settings(tmp_path: Path, allow_browse: bool) -> None:
    config_dir = tmp_path / "profile" / "config"
    incoming_dir = tmp_path / "profile" / "incoming"
    temp_dir = tmp_path / "profile" / "temp"
    shared_dir = tmp_path / "shared"

    amule_client.configure_profile(
        config_dir=config_dir,
        incoming_dir=incoming_dir,
        temp_dir=temp_dir,
        shared_dir=shared_dir,
        nick="cl-amule-007",
        tcp_port=4662,
        udp_port=4672,
        ec_port=4712,
        ec_password="secret",
        allow_peer_browse=allow_browse,
    )

    text = (config_dir / "amule.conf").read_text(encoding="utf-8")
    assert "Nick=cl-amule-007" in text
    assert "Address=\n" in text
    assert "ConnectToKad=0" in text
    assert "ConnectToED2K=1" in text
    assert "NewVersionCheck=0" in text
    assert (config_dir / "lastversion").read_text(encoding="utf-8").splitlines() == ["3.0.1"]
    assert f"SeeShare={0 if allow_browse else 2}" in text
    assert f"MaxUpload={1024 if allow_browse else 0}" in text
    assert "ECAddress=127.0.0.1" in text
    assert "ECPort=4712" in text
    assert f"ECPassword={hashlib.md5(b'secret', usedforsecurity=False).hexdigest()}" in text
    assert str(shared_dir.resolve()) in (config_dir / "shareddir.dat").read_text(encoding="utf-8")
    assert (config_dir / "shareddir-explicit.dat").read_text(encoding="utf-8")
    assert (config_dir / "shareddir-recursive.dat").read_text(encoding="utf-8") == ""


def test_profile_snapshot_omits_ec_password(tmp_path: Path) -> None:
    amule_client.configure_profile(
        config_dir=tmp_path / "config",
        incoming_dir=tmp_path / "incoming",
        temp_dir=tmp_path / "temp",
        shared_dir=tmp_path / "shared",
        nick="client",
        tcp_port=4662,
        udp_port=4672,
        ec_port=4712,
        ec_password="secret",
    )

    snapshot = amule_client.profile_snapshot(tmp_path / "config")

    assert snapshot["eMule.Nick"] == "client"
    assert snapshot["ExternalConnect.ECPort"] == "4712"
    assert all("Password" not in key for key in snapshot)


def test_shared_file_hash_accepts_windows_paths() -> None:
    output = " > 0123456789ABCDEF0123456789ABCDEF\tC:\\shared\\fixture.bin\n > \tNormal - 0(0)\n"

    assert amule_client.shared_file_hash(output, "fixture.bin") == "0123456789abcdef0123456789abcdef"
    assert amule_client.shared_file_hash(output, "other.bin") is None


def test_shared_file_hash_rejects_duplicate_rows() -> None:
    output = "\n".join(
        [
            "0" * 32 + " C:\\one\\fixture.bin",
            "1" * 32 + " C:\\two\\fixture.bin",
        ]
    )

    with pytest.raises(RuntimeError, match="duplicate shared rows"):
        amule_client.shared_file_hash(output, "fixture.bin")


def test_file_link_encodes_name_and_uppercases_hash() -> None:
    assert amule_client.file_link("fixture with spaces.bin", 123, "ab" * 16) == (
        "ed2k://|file|fixture%20with%20spaces.bin|123|ABABABABABABABABABABABABABABABAB|/"
    )


def test_shared_file_count_accepts_prefixed_amulecmd_statistics_after_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter([subprocess.TimeoutExpired("amulecmd", 0.1), " >   Number of Shared Files: 100000\n"])

    def run_command(_exe, *, ec_port, ec_password, command, timeout_seconds):
        assert command == "Statistics"
        assert 0 < timeout_seconds <= 1
        response = next(responses)
        if isinstance(response, subprocess.TimeoutExpired):
            raise response
        return response

    monkeypatch.setattr(amule_client, "run_command", run_command)
    monkeypatch.setattr(amule_client.time, "sleep", lambda _seconds: None)
    amule_client.wait_for_shared_file_count(
        Path("amulecmd"), ec_port=4712, ec_password="fixture", expected=100_000, timeout_seconds=1,
    )


def test_shutdown_falls_back_when_the_ec_command_itself_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    command = Mock(side_effect=subprocess.TimeoutExpired("amulecmd", 15))
    monkeypatch.setattr(amule_client, "run_command", command)
    process = Mock()
    process.poll.return_value = None
    process.wait.return_value = -15

    with pytest.raises(RuntimeError, match="EC shutdown ended with TimeoutExpired"):
        amule_client.shutdown_daemon(process, Path("amulecmd"), ec_port=4712, ec_password="fixture")

    process.terminate.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=5.0)
    process.kill.assert_not_called()
