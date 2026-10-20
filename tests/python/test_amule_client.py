from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from emule_test_harness import amule_client


def test_configure_profile_writes_isolated_daemon_settings(tmp_path: Path) -> None:
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
    )

    text = (config_dir / "amule.conf").read_text(encoding="utf-8")
    assert "Nick=cl-amule-007" in text
    assert "Address=\n" in text
    assert "ConnectToKad=0" in text
    assert "ConnectToED2K=1" in text
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
