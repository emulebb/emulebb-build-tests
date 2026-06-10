from __future__ import annotations

import re
from pathlib import Path


def _app_source_dir() -> Path:
    return (
        Path(__file__).resolve().parents[4]
        / "workspaces"
        / "workspace"
        / "app"
        / "emulebb-main"
        / "srchybrid"
    )


def test_tools_menu_check_for_updates_runs_manual_version_check() -> None:
    app_source = _app_source_dir()
    menu_cmds = (app_source / "MenuCmds.h").read_text(encoding="utf-8", errors="ignore")
    emule_dlg = (app_source / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    resource_h = (app_source / "Resource.h").read_text(encoding="utf-8", errors="ignore")

    assert "#define MP_HM_CHECK_FOR_UPDATES\t10464" in menu_cmds
    assert "#define IDS_TOOLS_STATUS_CHECK_FOR_UPDATES 3334" in resource_h

    status_map = re.search(
        r"case MP_HM_CHECK_FOR_UPDATES:\s*"
        r"return IDS_TOOLS_STATUS_CHECK_FOR_UPDATES;",
        emule_dlg,
    )
    assert status_map is not None

    command_handler = re.search(
        r"case MP_HM_CHECK_FOR_UPDATES:\s*"
        r"DoVersioncheck\(true\);\s*"
        r"break;",
        emule_dlg,
    )
    assert command_handler is not None

    network_updates_block = re.search(
        r"networkUpdates\.AppendMenu\(MF_STRING, MP_HM_IPFILTER,.*?"
        r"networkUpdates\.AppendMenu\(uGeoLocationMenuFlags, MP_HM_GEOLOCATION_DOWNLOAD,",
        emule_dlg,
        re.DOTALL,
    )
    assert network_updates_block is not None
    assert (
        "networkUpdates.AppendMenu(MF_STRING, MP_HM_CHECK_FOR_UPDATES, "
        "GetResString(IDS_CHECK4UPDATE), _T(\"WEB\"));"
        in network_updates_block.group(0)
    )


def test_check_for_updates_status_string_is_release_localized() -> None:
    app_source = _app_source_dir()
    expected_id = "IDS_TOOLS_STATUS_CHECK_FOR_UPDATES"

    rc_files = [app_source / "emule.rc", *sorted((app_source / "lang").glob("*.rc"))]
    for rc_file in rc_files:
        rc_text = rc_file.read_text(encoding="utf-8-sig", errors="ignore")
        assert expected_id in rc_text, rc_file
