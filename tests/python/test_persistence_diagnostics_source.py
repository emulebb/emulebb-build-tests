from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_preferences_load_failures_log_path_and_exception_details() -> None:
    source = (app_source_root() / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogWarning(_T("Failed to load path list \\"%s\\"%s"), (LPCTSTR)rstrFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Failed to load server.met address list \\"%s\\"%s"), (LPCTSTR)rstrFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Failed to load shared directory list \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source


def test_kad_preferences_failures_log_path_and_exception_details() -> None:
    source = (app_source_root() / "kademlia" / "kademlia" / "Prefs.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogError(_T("Failed to read Kad preferences file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("Failed to read Kad preferences file \\"%s\\" after an unexpected exception"), (LPCTSTR)m_sFilename);' in source
    assert 'DebugLogError(_T("Failed to write Kad preferences file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("Failed to write Kad preferences file \\"%s\\" after an unexpected exception"), (LPCTSTR)m_sFilename);' in source
    assert 'TRACE("Exception in CPrefs::ReadFile\\n");' not in source
    assert 'TRACE("Exception in CPrefs::WriteFile\\n");' not in source


def test_kad_contact_persistence_failures_log_path_and_exception_details() -> None:
    source = (app_source_root() / "kademlia" / "routing" / "RoutingZone.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogError(_T("Failed to read Kad contacts file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("Failed to write Kad contacts file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("CFileException in CRoutingZone::readFile"));' not in source
    assert 'AddDebugLogLine(false, _T("CFileException in CRoutingZone::writeFile"));' not in source
