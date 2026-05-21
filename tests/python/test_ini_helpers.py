from __future__ import annotations

from pathlib import Path

from emule_test_harness.ini import (
    UTF16_LE_BOM,
    normalize_ini_newlines,
    parse_ini_values,
    patch_ini_value,
    read_ini_text,
    upsert_ini_section_value,
    write_utf16_ini_text,
)


def test_parse_ini_values_ignores_comments_sections_and_blank_lines() -> None:
    values = parse_ini_values(
        """
; comment
[Section]
Nick = eMule
Port=4662

InvalidLine
"""
    )

    assert values == {"Nick": "eMule", "Port": "4662"}


def test_patch_ini_value_replaces_existing_key_case_insensitively() -> None:
    patched = patch_ini_value("Nick=old\r\nPort=1\r\n", "nick", "new")

    assert "nick=new" in patched
    assert "Nick=old" not in patched
    assert "Port=1" in patched


def test_patch_ini_value_replaces_existing_key_with_windows_backslashes() -> None:
    patched = patch_ini_value("TempDir=C:\\old\\temp\\\r\nPort=1\r\n", "TempDir", "C:\\prj\\profile\\temp\\")

    assert "TempDir=C:\\prj\\profile\\temp\\" in patched
    assert "Port=1" in patched


def test_patch_ini_value_appends_missing_key_with_crlf() -> None:
    assert patch_ini_value("Nick=eMule", "Port", "4662") == "Nick=eMule\r\nPort=4662\r\n"


def test_read_ini_text_accepts_legacy_utf8(tmp_path: Path) -> None:
    path = tmp_path / "preferences.ini"
    path.write_bytes("[eMule]\nNick=legacy\n".encode("utf-8"))

    assert read_ini_text(path) == "[eMule]\nNick=legacy\n"


def test_write_utf16_ini_text_writes_bom_and_normalizes_crlf(tmp_path: Path) -> None:
    path = tmp_path / "preferences.ini"

    write_utf16_ini_text(path, "[eMule]\nNick=eMule\n\n")

    data = path.read_bytes()
    assert data.startswith(UTF16_LE_BOM)
    assert data == UTF16_LE_BOM + "[eMule]\r\nNick=eMule\r\n".encode("utf-16-le")
    assert read_ini_text(path) == "[eMule]\r\nNick=eMule\r\n"


def test_normalize_ini_newlines_collapses_final_blank_lines() -> None:
    assert normalize_ini_newlines("Nick=eMule\rPort=4662\n\n") == "Nick=eMule\r\nPort=4662\r\n"


def test_upsert_ini_section_value_updates_section_case_insensitively() -> None:
    patched = upsert_ini_section_value("[webserver]\r\nPort=1\r\n[eMule]\r\nNick=x\r\n", "WebServer", "port", "2")

    assert patched == "[webserver]\r\nport=2\r\n[eMule]\r\nNick=x\r\n"
