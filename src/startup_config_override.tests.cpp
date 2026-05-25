#include "../third_party/doctest/doctest.h"

#include "StartupConfigOverride.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Startup config override accepts canonical absolute drive paths")
{
	CHECK(StartupConfigOverride::IsAbsoluteBaseDirPath(_T("C:\\profiles\\test-root")));
	CHECK(StartupConfigOverride::IsAbsoluteBaseDirPath(_T("C:\\profiles\\test-root\\")));
	CHECK(StartupConfigOverride::NormalizeBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\")));
	CHECK(StartupConfigOverride::GetConfigDirectoryFromBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\config\\")));
	CHECK(StartupConfigOverride::GetDataDirectoryFromBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\")));
	CHECK(StartupConfigOverride::GetTempDirectoryFromBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\Temp\\")));
	CHECK(StartupConfigOverride::GetIncomingDirectoryFromBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\Incoming\\")));
	CHECK(StartupConfigOverride::GetLogDirectoryFromBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\logs\\")));
	CHECK(StartupConfigOverride::GetExpansionDirectoryFromBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\")));
	CHECK(StartupConfigOverride::GetPreferencesIniPathFromBaseDir(_T("C:\\profiles\\test-root")) == CString(_T("C:\\profiles\\test-root\\config\\preferences.ini")));
}

TEST_CASE("Startup config override rejects non-canonical base paths")
{
	CHECK_FALSE(StartupConfigOverride::IsAbsoluteBaseDirPath(_T("\\\\server\\share\\profile")));
	CHECK_FALSE(StartupConfigOverride::IsAbsoluteBaseDirPath(_T("relative\\profile")));
	CHECK_FALSE(StartupConfigOverride::IsAbsoluteBaseDirPath(_T("C:\\profiles\\.\\test-root")));
	CHECK_FALSE(StartupConfigOverride::IsAbsoluteBaseDirPath(_T("C:\\profiles\\..\\test-root")));
	CHECK_FALSE(StartupConfigOverride::IsAbsoluteBaseDirPath(_T("C:/profiles/test-root")));
}
