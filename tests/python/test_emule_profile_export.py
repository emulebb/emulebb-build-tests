from __future__ import annotations

import struct
from pathlib import Path

import pytest

from emule_test_harness import emule_profile_export, mfc_known_met


def _tag_string(name_id: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return (
        bytes([mfc_known_met.TAGTYPE_STRING])
        + struct.pack("<H", 1)
        + bytes([name_id])
        + struct.pack("<H", len(raw))
        + raw
    )


def _tag_uint64(name_id: int, value: int) -> bytes:
    return (
        bytes([mfc_known_met.TAGTYPE_UINT64])
        + struct.pack("<H", 1)
        + bytes([name_id])
        + struct.pack("<Q", value)
    )


def _write_known_met(path: Path) -> None:
    tags = [
        _tag_string(mfc_known_met.FT_FILENAME, "sample.bin"),
        _tag_uint64(mfc_known_met.FT_FILESIZE, 1024),
    ]
    record = (
        struct.pack("<I", 1_700_000_000)
        + bytes.fromhex("00112233445566778899aabbccddeeff")
        + struct.pack("<H", 0)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )
    path.write_bytes(bytes([mfc_known_met.MET_HEADER_I64TAGS]) + struct.pack("<I", 1) + record)


def _write_job(
    path: Path,
    *,
    source_profile: Path,
    output_manifest: Path,
    target_platform: str = "windows",
    mappings: list[tuple[str, str]] | None = None,
) -> None:
    text = f"""schema_version = 1

[source]
profile = '{source_profile.as_posix()}'
flavor = "auto"

[target]
platform = "{target_platform}"

[output]
manifest = '{output_manifest.as_posix()}'
"""
    for source, target in mappings or []:
        text += f"""
[[path_mappings]]
source = '{source}'
target = '{target}'
"""
    path.write_text(text, encoding="utf-8")


def _write_mfc_profile(profile: Path) -> Path:
    config = profile / "config"
    config.mkdir(parents=True)
    _write_known_met(config / "known.met")
    (config / "preferences.ini").write_text("IncomingDir=C:\\Incoming\r\n", encoding="utf-16")
    (config / "shareddir.dat").write_text(
        "# generated roots\r\nC:\\Shared\\One\r\nC:\\Shared\\Two\r\nD:\\Explicit\r\n",
        encoding="utf-16",
    )
    (config / "shareddir.monitored.dat").write_text(
        "; recursive roots\r\nC:\\Shared\r\n",
        encoding="utf-16",
    )
    (config / "shareddir.monitor-owned.dat").write_text(
        "# derived roots\r\nC:\\Shared\\One\r\nC:\\Shared\\Two\r\n",
        encoding="utf-16",
    )
    return config


def test_windows_export_discovers_compact_mfc_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "legacy-profile"
    _write_mfc_profile(profile)
    job_path = tmp_path / "import.toml"
    output = tmp_path / "manifest.json"
    _write_job(job_path, source_profile=profile, output_manifest=output)
    collapsed_inputs: list[list[str]] = []

    def record_collapse(roots: list[str]) -> list[str]:
        collapsed_inputs.append(roots)
        return roots

    monkeypatch.setattr(
        emule_profile_export.mfc_profile_import,
        "_collapse_stock_shareddir_roots",
        record_collapse,
    )

    manifest = emule_profile_export.build_export_manifest(
        emule_profile_export.load_export_job(job_path)
    )

    assert collapsed_inputs == [["D:\\Explicit"]]
    assert manifest["source"]["flavor"] == "mfc"
    assert [root["path"] for root in manifest["sharedRoots"]] == [
        "C:\\Incoming",
        "C:\\Shared",
        "D:\\Explicit",
    ]
    assert manifest["summary"]["importedKnownRecords"] == 1


def test_stock_export_accepts_config_dir_and_collapses_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "legacy-profile"
    config = _write_mfc_profile(profile)
    (config / "shareddir.monitored.dat").unlink()
    (config / "shareddir.monitor-owned.dat").unlink()
    job_path = tmp_path / "import.toml"
    output = tmp_path / "manifest.json"
    _write_job(job_path, source_profile=config, output_manifest=output)
    collapsed_inputs: list[list[str]] = []

    def record_collapse(roots: list[str]) -> list[str]:
        collapsed_inputs.append(roots)
        return ["C:\\Shared", "D:\\Explicit"]

    monkeypatch.setattr(
        emule_profile_export.mfc_profile_import,
        "_collapse_stock_shareddir_roots",
        record_collapse,
    )

    manifest = emule_profile_export.build_export_manifest(
        emule_profile_export.load_export_job(job_path)
    )

    assert collapsed_inputs == [["C:\\Shared\\One", "C:\\Shared\\Two", "D:\\Explicit"]]
    assert manifest["source"]["flavor"] == "stock"
    assert [root["path"] for root in manifest["sharedRoots"]] == [
        "C:\\Incoming",
        "C:\\Shared",
        "D:\\Explicit",
    ]


@pytest.mark.parametrize("target_platform", ["linux", "macos"])
def test_unix_export_uses_longest_prefix_mapping(
    tmp_path: Path,
    target_platform: str,
) -> None:
    profile = tmp_path / "legacy-profile"
    _write_mfc_profile(profile)
    job_path = tmp_path / "import.toml"
    _write_job(
        job_path,
        source_profile=profile,
        output_manifest=tmp_path / "manifest.json",
        target_platform=target_platform,
        mappings=[
            ("C:\\", "/mnt/c"),
            ("C:\\Shared", "/data/shared"),
            ("D:\\", "/mnt/d"),
        ],
    )

    manifest = emule_profile_export.build_export_manifest(
        emule_profile_export.load_export_job(job_path)
    )

    assert manifest["targetPlatform"] == "unix"
    assert [root["path"] for root in manifest["sharedRoots"]] == [
        "/mnt/c/Incoming",
        "/data/shared",
        "/mnt/d/Explicit",
    ]


def test_linux_export_rejects_unmapped_root(tmp_path: Path) -> None:
    profile = tmp_path / "legacy-profile"
    _write_mfc_profile(profile)
    job_path = tmp_path / "import.toml"
    _write_job(
        job_path,
        source_profile=profile,
        output_manifest=tmp_path / "manifest.json",
        target_platform="linux",
        mappings=[("C:\\", "/mnt/c")],
    )

    with pytest.raises(ValueError, match="requires a path mapping"):
        emule_profile_export.build_export_manifest(
            emule_profile_export.load_export_job(job_path)
        )


@pytest.mark.parametrize(
    ("target_platform", "target"),
    [
        ("windows", "D:\\imports\\..\\shared"),
        ("linux", "/data/imports/../shared"),
    ],
)
def test_job_rejects_mapping_target_traversal(
    tmp_path: Path,
    target_platform: str,
    target: str,
) -> None:
    profile = tmp_path / "legacy-profile"
    _write_mfc_profile(profile)
    job_path = tmp_path / "import.toml"
    _write_job(
        job_path,
        source_profile=profile,
        output_manifest=tmp_path / "manifest.json",
        target_platform=target_platform,
        mappings=[("C:\\", target)],
    )

    with pytest.raises(ValueError, match="must not contain traversal"):
        emule_profile_export.load_export_job(job_path)


def test_export_writes_configured_manifest_atomically(tmp_path: Path) -> None:
    profile = tmp_path / "legacy-profile"
    _write_mfc_profile(profile)
    job_path = tmp_path / "import.toml"
    output = tmp_path / "nested" / "manifest.json"
    _write_job(job_path, source_profile=profile, output_manifest=output)
    job = emule_profile_export.load_export_job(job_path)
    manifest = emule_profile_export.build_export_manifest(job)

    written = emule_profile_export.export_manifest(job, manifest)

    assert written == output
    assert output.is_file()
    assert not output.with_name("manifest.json.tmp").exists()
