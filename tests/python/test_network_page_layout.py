from __future__ import annotations

import re

from emule_test_harness.master_source import app_source_root


def dialog_block(resource_text: str, dialog_id: str) -> str:
    match = re.search(rf"^{dialog_id}\s+DIALOGEX\b.*?\nEND\b", resource_text, flags=re.M | re.S)
    assert match is not None, f"{dialog_id} dialog block was not found"
    return match.group(0)


def control_rect(block: str, control_id: str) -> tuple[int, int, int, int]:
    for line in block.splitlines():
        if control_id not in line:
            continue
        tail = line.split(control_id, 1)[1]
        fields = [field.strip() for field in tail.split(",")]
        for index in range(len(fields) - 3):
            candidate = fields[index : index + 4]
            if all(re.fullmatch(r"-?\d+", field) for field in candidate):
                return tuple(int(field) for field in candidate)  # type: ignore[return-value]
    raise AssertionError(f"{control_id} was not found with coordinates")


def assert_right_edge_at_or_before(block: str, control_id: str, max_right: int) -> None:
    x, _y, width, _height = control_rect(block, control_id)
    assert x + width <= max_right, f"{control_id} right edge {x + width} exceeds {max_right}"


def test_server_page_right_column_is_widened_without_overlap() -> None:
    resource_text = (app_source_root() / "emule.rc").read_text(encoding="utf-8", errors="ignore")
    server = dialog_block(resource_text, "IDD_SERVER")

    for control_id in ("IDC_SSTATIC", "IDC_SSTATIC6", "IDC_MYINFO"):
        x, _y, width, _height = control_rect(server, control_id)
        assert x == 319
        assert width >= 187

    assert control_rect(server, "IDC_IPADDRESS")[2] >= 130
    assert control_rect(server, "IDC_SNAME")[2] >= 176
    assert control_rect(server, "IDC_SERVERMETURL")[2] >= 167
    assert control_rect(server, "IDC_MYINFOLIST")[2] >= 178

    for control_id in ("IDC_SERVLIST", "IDC_SPLITTER_SERVER", "IDC_TAB3", "IDC_LOGRESET", "IDC_SERVMSG", "IDC_LOGBOX", "IDC_DEBUG_LOG"):
        assert_right_edge_at_or_before(server, control_id, 315)


def test_kad_page_right_column_is_widened_without_overlap() -> None:
    resource_text = (app_source_root() / "emule.rc").read_text(encoding="utf-8", errors="ignore")
    kad = dialog_block(resource_text, "IDD_KADEMLIAWND")

    x, _y, width, _height = control_rect(kad, "IDC_BSSTATIC")
    assert x == 319
    assert width >= 187

    assert control_rect(kad, "IDC_FIREWALLCHECKBUTTON")[2] >= 122
    assert control_rect(kad, "IDC_BOOTSTRAPIP")[2] >= 117
    assert control_rect(kad, "IDC_BOOTSTRAPURL")[2] >= 161
    assert control_rect(kad, "IDC_RADCLIENTS")[2] >= 173
    assert control_rect(kad, "IDC_KAD_HISTOGRAM")[2] >= 187

    for control_id in ("IDC_CONTACTLIST", "IDC_KAD_LOOKUPGRAPH"):
        assert_right_edge_at_or_before(kad, control_id, 315)
