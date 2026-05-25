from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_buddy_button_subclass_callback_guards_missing_state() -> None:
    source = (app_source_root() / "BuddyButton.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (pfnOldWndProc == NULL) {" in source
    assert "return ::DefWindowProc(hWnd, uMessage, wParam, lParam);" in source
    assert "if (pBuddyData == NULL) {" in source
    assert "::SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)pfnOldWndProc);" in source
    assert "::RemoveProp(hWnd, s_szPropOldWndProc);" in source
    assert "if (lpNCCS != NULL)\n\t\t\t\tlpNCCS->rgrc[0].right -= pBuddyData->m_uButtonWidth;" in source
    assert "if (pBuddyData->m_hwndButton == NULL || !::IsWindow(pBuddyData->m_hwndButton))\n\t\t\t\tbreak;" in source


def test_add_buddy_button_rolls_back_half_installed_subclass() -> None:
    source = (app_source_root() / "BuddyButton.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (hwndEdit == NULL || hwndButton == NULL || !::IsWindow(hwndEdit) || !::IsWindow(hwndButton))\n\t\treturn;" in source
    assert "if (lpfnOldWndProc == NULL)\n\t\treturn;" in source
    assert "if (!::SetProp(hwndEdit, s_szPropOldWndProc, (HANDLE)lpfnOldWndProc)) {\n\t\t::SetWindowLongPtr(hwndEdit, GWLP_WNDPROC, (LONG_PTR)lpfnOldWndProc);\n\t\treturn;\n\t}" in source
    assert "if (!::SetProp(hwndEdit, s_szPropBuddyData, (HANDLE)pBuddyData)) {\n\t\tdelete pBuddyData;\n\t\t::RemoveProp(hwndEdit, s_szPropOldWndProc);\n\t\t::SetWindowLongPtr(hwndEdit, GWLP_WNDPROC, (LONG_PTR)lpfnOldWndProc);\n\t\treturn;\n\t}" in source
