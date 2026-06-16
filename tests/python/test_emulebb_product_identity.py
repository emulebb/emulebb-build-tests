from __future__ import annotations

import re

from emule_test_harness.master_source import app_source_root


def read_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8-sig", errors="ignore")


def iter_rc_rows(text: str):
    current_id: str | None = None
    current_lines: list[str] = []
    id_re = re.compile(r"^\s*(IDS_[A-Za-z0-9_]+)\b")

    for line in text.splitlines():
        match = id_re.match(line)
        if match:
            if current_id is not None:
                yield current_id, "\n".join(current_lines)
            current_id = match.group(1)
            current_lines = [line]
        elif current_id is not None:
            current_lines.append(line)

    if current_id is not None:
        yield current_id, "\n".join(current_lines)


def test_new_default_profile_folders_use_emulebb_without_legacy_probe() -> None:
    preferences = read_source("Preferences.cpp")
    start = preferences.index("no registry default, check if we find a preferences.ini to use")
    end = preferences.index("case 2: //program directory", start)
    known_folder_block = preferences[start:end]

    assert '_T("eMuleBB\\\\")' in known_folder_block
    assert '_T("eMule\\\\")' not in known_folder_block


def test_public_rest_and_qbit_errors_use_emulebb_identity() -> None:
    rest = read_source("WebServerJson.cpp")
    qbit = read_source("WebServerQBitCompat.cpp")

    assert '{"name", "eMuleBB"}' in rest
    assert "eMuleBB is shutting down" in rest
    assert "eMuleBB is still starting" in rest
    assert "eMule REST API key is not configured" not in qbit
    assert "eMuleBB REST API key is not configured" in qbit


def test_targeted_english_resource_identity_uses_emulebb() -> None:
    rows = dict(iter_rc_rows(read_source("emule.rc")))
    target_ids = {
        "IDS_ABOUTBOX",
        "IDS_MAIN_EXIT",
        "IDS_MAIN_RESTART",
        "IDS_RESTARTING_EMULE",
        "IDS_CLOSEEMULE",
        "IDS_STARTUP_PROGRESS_STARTING",
        "IDS_WIZ1_WELCOME_ACTIONS",
        "IDS_EMULENOTIFICATION",
        "IDS_RUNNINGRESTRICTED",
        "IDS_NOPORTCHANGEPOSSIBLE",
        "IDS_SHAREEMULEWARNING",
        "IDS_WRN_INCFILE_EXISTS",
        "IDS_WIZZARDOBFUSCATION",
        "IDS_BIND_RESTART_REQUIRED",
        "IDS_CONNECTION_TT_VPN_GUARD",
        "IDS_BIND_EXIT_PREFIX",
        "IDS_VPN_GUARD_RUNTIME_INTERFACE_UNAVAILABLE",
    }

    for resource_id in target_ids:
        assert resource_id in rows
        assert "eMuleBB" in rows[resource_id]
        assert re.search(r"(?<![A-Za-z0-9_])eMule(?![A-Za-z0-9_])", rows[resource_id]) is None


def test_language_dll_metadata_uses_emulebb_product_identity() -> None:
    metadata = read_source("lang/lang.rc2")

    assert 'VALUE "CompanyName", "https://github.com/emulebb"' in metadata
    assert 'VALUE "FileDescription", "eMuleBB Language DLL"' in metadata
    assert 'VALUE "ProductName", "eMule broadband edition"' in metadata


def test_legacy_webserver_identity_surface_remains_frozen() -> None:
    webserver = read_source("WebServer.cpp")

    assert '#define HTTPInit "Server: eMule\\r\\nConnection: close\\r\\nContent-Type: text/html\\r\\n"' in webserver
    assert 'Out.Replace(_T("[eMuleAppName]"), _T("eMule"));' in webserver
