"""INI text and encoding helpers shared by Python harness tests."""

from __future__ import annotations

import re
from pathlib import Path

UTF16_LE_BOM = b"\xff\xfe"
UTF8_BOM = b"\xef\xbb\xbf"


def read_ini_text(path: Path) -> str:
    """Reads an INI file, accepting UTF-16LE BOM and legacy UTF-8 inputs."""

    data = path.read_bytes()
    if data.startswith(UTF16_LE_BOM):
        return data[len(UTF16_LE_BOM):].decode("utf-16-le")
    if data.startswith(UTF8_BOM):
        return data[len(UTF8_BOM):].decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def write_utf16_ini_text(path: Path, text: str) -> None:
    """Writes INI text as UTF-16LE with BOM for Windows Unicode profile APIs."""

    normalized = normalize_ini_newlines(text)
    path.write_bytes(UTF16_LE_BOM + normalized.encode("utf-16-le"))


def normalize_ini_newlines(text: str) -> str:
    """Normalizes INI text to CRLF with exactly one final newline."""

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    return "\r\n".join(lines) + "\r\n"


def parse_ini_values(text: str) -> dict[str, str]:
    """Parses simple top-level INI key/value rows into a dictionary."""

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[") or line.startswith(";") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def patch_ini_value(text: str, key: str, value: str) -> str:
    """Upserts one simple INI key while preserving existing surrounding text."""

    pattern = re.compile(rf"(?im)^(?P<key>{re.escape(key)})=.*$")
    replacement = f"{key}={value}"
    if pattern.search(text):
        return pattern.sub(lambda _match: replacement, text)
    suffix = "" if text.endswith("\n") else "\r\n"
    return f"{text}{suffix}{replacement}\r\n"


def upsert_ini_section_value(text: str, section: str, key: str, value: str) -> str:
    """Upserts one key/value pair inside a simple INI section."""

    section_header = f"[{section}]"
    lines = text.splitlines()
    output: list[str] = []
    inside_target = False
    inserted = False
    saw_section = False

    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if inside_target and not inserted:
                output.append(f"{key}={value}")
                inserted = True
            inside_target = stripped.lower() == section_header.lower()
            saw_section = saw_section or inside_target
            output.append(raw_line)
            continue

        if inside_target and raw_line.partition("=")[0].strip().lower() == key.lower():
            output.append(f"{key}={value}")
            inserted = True
            continue

        output.append(raw_line)

    if saw_section:
        if inside_target and not inserted:
            output.append(f"{key}={value}")
    else:
        if output and output[-1] != "":
            output.append("")
        output.append(section_header)
        output.append(f"{key}={value}")

    return "\r\n".join(output) + "\r\n"
