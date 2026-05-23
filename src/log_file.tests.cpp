#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "LogArtifactNames.h"
#include "LogFileSeams.h"

#include <algorithm>
#include <vector>
#include <windows.h>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Log-file seam preserves long rotated backup names without MAX_PATH truncation")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x4C4F4721u));

	const std::wstring rawLogPath = fixture.MakeDirectoryChildPath(L"downloads odd-[log].log");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(1231u, 0xABCDu);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(rawLogPath, payload));

	CString strLogPath(rawLogPath.c_str());
	const CString strExpectedPrefix = strLogPath.Left(strLogPath.ReverseFind(_T('.')));

	const CString strRotatedPath = LogFileSeams::BuildRotatedLogFilePath(strLogPath, _T("20260411-150000"));
	const std::wstring rotatedPath(strRotatedPath.GetString());
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::MoveFileReplace(rawLogPath, rotatedPath));

	std::vector<BYTE> roundTrip;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(rotatedPath, roundTrip));
	std::vector<std::wstring> names;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::EnumerateFileNames(fixture.DirectoryPath(), names));

	CHECK(strLogPath.GetLength() > MAX_PATH);
	CHECK(strRotatedPath == strExpectedPrefix + CString(_T("-20260411-150000.log")));
	CHECK(roundTrip == payload);
	CHECK(std::find(names.begin(), names.end(), std::wstring(L"downloads odd-[log]-20260411-150000.log")) != names.end());
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(rotatedPath));
}

TEST_CASE("Log-file seam preserves extensionless and slash-separated rotation targets")
{
	CHECK(LogFileSeams::BuildRotatedLogFilePath(CString(_T("downloads")), _T("ts")) == CString(_T("downloads-ts")));
	CHECK(LogFileSeams::BuildRotatedLogFilePath(CString(_T("C:/logs/downloads.log")), _T("ts")) == CString(_T("C:/logs/downloads-ts.log")));
}

TEST_CASE("Log artifact names use strict lowercase kebab policy")
{
	SYSTEMTIME time = {};
	time.wYear = 2026;
	time.wMonth = 5;
	time.wDay = 23;
	time.wHour = 18;
	time.wMinute = 54;
	time.wSecond = 55;

	CHECK(CString(LogArtifactNames::MainLogFileName()) == CString(_T("emulebb.log")));
	CHECK(CString(LogArtifactNames::VerboseLogFileName()) == CString(_T("emulebb-verbose.log")));
	CHECK(CString(LogArtifactNames::CrtDebugLogFileName()) == CString(_T("emulebb-crt-debug.log")));
	CHECK(LogArtifactNames::BuildManualDumpFileName(time, 1234, false, 0) == CString(_T("emulebb-dump-20260523-185455-pid1234-mini.dmp")));
	CHECK(LogArtifactNames::BuildManualDumpFileName(time, 1234, true, 2) == CString(_T("emulebb-dump-20260523-185455-pid1234-full-02.dmp")));
	CHECK(LogArtifactNames::BuildCrashDumpFileName(time, 1234) == CString(_T("emulebb-crash-20260523-185455-pid1234.dmp")));
}

TEST_SUITE_END;
