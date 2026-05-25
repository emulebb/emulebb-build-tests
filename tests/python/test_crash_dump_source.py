from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_crash_handler_can_use_configured_full_dump_type() -> None:
    root = app_source_root()
    header = (root / "Mdump.h").read_text(encoding="utf-8", errors="ignore")
    source = (root / "Mdump.cpp").read_text(encoding="utf-8", errors="ignore")
    emule = (root / "Emule.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool bCaptureFullCrashDump;" in header
    assert "MINIDUMP_TYPE GetCrashDumpType(bool bFullMemoryDump)" in source
    assert "return bFullMemoryDump ? GetManualDumpType(true) : MiniDumpNormal;" in source
    assert "const MINIDUMP_TYPE eDumpType = GetCrashDumpType(theCrashDumper.bCaptureFullCrashDump);" in source
    assert "::MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, eDumpType, &ExInfo, NULL, NULL)" in source
    assert "::MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &ExInfo, NULL, NULL)" not in source
    assert 'GetProfileInt(_T("eMule"), _T("CaptureFullCrashDump"), 0) != 0' in emule


def test_capture_full_crash_dump_preference_is_persisted_and_exposed_in_tweaks() -> None:
    root = app_source_root()
    preferences_h = (root / "Preferences.h").read_text(encoding="utf-8", errors="ignore")
    preferences_cpp = (root / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")
    tweaks_h = (root / "PPgTweaks.h").read_text(encoding="utf-8", errors="ignore")
    tweaks_cpp = (root / "PPgTweaks.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "static bool\t\tm_bCaptureFullCrashDump;" in preferences_h
    assert "static bool\t\tGetCaptureFullCrashDump()" in preferences_h
    assert "static void\t\tSetCaptureFullCrashDump(bool bEnabled)" in preferences_h
    assert 'ini.WriteBool(_T("CaptureFullCrashDump"), m_bCaptureFullCrashDump);' in preferences_cpp
    assert 'SetCaptureFullCrashDump(ini.GetBool(_T("CaptureFullCrashDump"), GetDefaultCaptureFullCrashDump()));' in preferences_cpp

    assert "HTREEITEM m_htiCaptureFullCrashDump;" in tweaks_h
    assert "bool m_bCaptureFullCrashDump;" in tweaks_h
    assert 'return _T("Capture Full Dump");' in tweaks_cpp
    assert "m_htiCaptureFullCrashDump = m_ctrlTreeOptions.InsertCheckBox(GetCaptureFullCrashDumpLabel(), m_htiLoggingGroup, m_bCaptureFullCrashDump);" in tweaks_cpp
    assert "DDX_TreeCheck(pDX, IDC_EXT_OPTS, m_htiCaptureFullCrashDump, m_bCaptureFullCrashDump);" in tweaks_cpp
    assert "m_bCaptureFullCrashDump = thePrefs.GetCaptureFullCrashDump();" in tweaks_cpp
    assert "thePrefs.SetCaptureFullCrashDump(m_bCaptureFullCrashDump);" in tweaks_cpp
    assert "theCrashDumper.bCaptureFullCrashDump = thePrefs.GetCaptureFullCrashDump();" in tweaks_cpp
