from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

from emule_test_harness import amule


def workspace_unit_root(name: str, request: pytest.FixtureRequest) -> Path:
    """Returns a predictable workspace-state scratch root for path-discipline tests."""

    root = Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "state" / "test-artifacts" / "unit-amule-harness" / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    request.addfinalizer(lambda: shutil.rmtree(root, ignore_errors=True))
    return root


def test_prepare_amule_profile_writes_isolated_config(request: pytest.FixtureRequest) -> None:
    root = workspace_unit_root("prepare-profile", request)
    profile_root = root / "artifacts" / "clients" / "cl-amule-004"
    profile = amule.prepare_amule_profile(
        root_dir=profile_root,
        profile_id="cl-amule-004",
        nick="cl-amule-004",
        tcp_port=41000,
        udp_port=41001,
        ec_port=41002,
        advertised_address="10.55.0.7",
    )

    config_text = (profile.config_dir / "amule.conf").read_text(encoding="utf-8")

    assert profile.root_dir == profile_root.resolve()
    assert profile.incoming_dir.is_dir()
    assert profile.temp_dir.is_dir()
    assert profile.logs_dir.is_dir()
    assert "Nick=cl-amule-004" in config_text
    assert "ConnectToED2K=1" in config_text
    assert "ConnectToKad=0" in config_text
    assert "MaxUpload=0" in config_text
    assert "MaxDownload=0" in config_text
    assert "SlotAllocation=16" in config_text
    assert "MaxConnections=1000" in config_text
    assert "MaxConnectionsPerFiveSeconds=100" in config_text
    assert "AcceptExternalConnections=1" in config_text
    assert "ECAddress=127.0.0.1" in config_text
    assert "ECPort=41002" in config_text
    assert f"ECPassword={hashlib.md5(b'cl-amule-004-ec-password').hexdigest()}" in config_text
    assert f"TempDir={amule.win_path_text(profile.temp_dir)}" in config_text
    assert f"IncomingDir={amule.win_path_text(profile.incoming_dir)}" in config_text


def test_amule_commands_pin_config_dir_and_ec_endpoint(tmp_path: Path, request: pytest.FixtureRequest) -> None:
    root = workspace_unit_root("commands", request)
    profile = amule.prepare_amule_profile(
        root_dir=root / "run" / "cl-amule-004",
        profile_id="cl-amule-004",
        nick="cl-amule-004",
        tcp_port=42000,
        udp_port=42001,
        ec_port=42002,
        advertised_address="10.55.0.8",
    )
    daemon = tmp_path / "bin" / "amuled.exe"
    control = tmp_path / "bin" / "amulecmd.exe"

    assert amule.build_amuled_command(daemon, profile) == [
        str(daemon.resolve()),
        f"--config-dir={profile.config_dir}",
        "--log-stdout",
    ]
    assert amule.build_amulecmd_command(control, profile, "Status") == [
        str(control.resolve()),
        "--host=127.0.0.1",
        "--port=42002",
        "--password=cl-amule-004-ec-password",
        "--command=Status",
    ]


def test_wait_for_shared_file_hash_parses_amulecmd_output(
    monkeypatch,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    root = workspace_unit_root("shared-hash", request)
    profile = amule.prepare_amule_profile(
        root_dir=root / "run" / "cl-amule-004",
        profile_id="cl-amule-004",
        nick="cl-amule-004",
        tcp_port=43000,
        udp_port=43001,
        ec_port=43002,
        advertised_address="10.55.0.9",
    )

    class Completed:
        returncode = 0
        stdout = (
            "This is amulecmd GIT\n\n"
            "Creating client...\n"
            "Succeeded! Connection established to aMule GIT\n"
            " > 0123456789ABCDEF0123456789ABCDEF C:\\share\\deterministic-amule-transfer.bin\n"
            " > \tAuto [Hi] - 0(0) / 0(0) - 0 bytes (0 bytes) - 0.00\n"
        )
        stderr = ""

    monkeypatch.setattr(amule, "run_amulecmd", lambda *_args, **_kwargs: Completed())

    row = amule.wait_for_shared_file_hash(
        tmp_path / "bin" / "amulecmd.exe",
        profile,
        "deterministic-amule-transfer.bin",
        1.0,
    )

    assert row["hash"] == "0123456789abcdef0123456789abcdef"
    assert amule.build_file_link("fixture.bin", 123, str(row["hash"])) == (
        "ed2k://|file|fixture.bin|123|0123456789abcdef0123456789abcdef|/"
    )


def test_build_server_link_validates_ed2k_endpoint() -> None:
    assert amule.build_server_link(" 10.55.0.1 ", 4661) == "ed2k://|server|10.55.0.1|4661|/"

    with pytest.raises(ValueError, match="address"):
        amule.build_server_link(" ", 4661)
    with pytest.raises(ValueError, match="port"):
        amule.build_server_link("10.55.0.1", 0)
