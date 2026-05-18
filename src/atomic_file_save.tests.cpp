#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "AtomicFileSaveSeams.h"

#include <vector>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Atomic file save seam defines temp path and cleanup policy")
{
	CHECK(AtomicFileSaveSeams::BuildDefaultTempPath(CString(_T("C:\\config\\preferences.dat"))) == CString(_T("C:\\config\\preferences.dat.tmp")));
	CHECK(AtomicFileSaveSeams::GetReplaceFlags(false) == static_cast<DWORD>(MOVEFILE_REPLACE_EXISTING));
	CHECK(AtomicFileSaveSeams::GetReplaceFlags(true) == static_cast<DWORD>(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
	CHECK(AtomicFileSaveSeams::ShouldDeleteTempFileAfterSaveAttempt(true, false));
	CHECK_FALSE(AtomicFileSaveSeams::ShouldDeleteTempFileAfterSaveAttempt(false, false));
	CHECK_FALSE(AtomicFileSaveSeams::ShouldDeleteTempFileAfterSaveAttempt(true, true));
}

TEST_CASE("Atomic file save seam replaces target from completed temp file")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x41544Du));

	const std::wstring targetPath = fixture.MakeDirectoryChildPath(L"atomic-target.dat");
	const std::wstring tempPath = targetPath + L".tmp";
	const std::vector<BYTE> oldPayload = LongPathTestSupport::BuildDeterministicPayload(512u, 0x41544Du);
	const std::vector<BYTE> newPayload = LongPathTestSupport::BuildDeterministicPayload(1024u, 0x534156u);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(targetPath, oldPayload));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(tempPath, newPayload));

	DWORD dwLastError = ERROR_SUCCESS;
	CHECK(AtomicFileSaveSeams::TryReplaceTempFile(
		CString(tempPath.c_str()),
		CString(targetPath.c_str()),
		AtomicFileSaveSeams::GetReplaceFlags(true),
		&dwLastError));
	CHECK(dwLastError == ERROR_SUCCESS);
	CHECK_FALSE(LongPathSeams::PathExists(CString(tempPath.c_str())));

	std::vector<BYTE> roundTrip;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(targetPath, roundTrip));
	CHECK(roundTrip == newPayload);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(targetPath));
}

TEST_CASE("Atomic file save seam rejects empty replace paths")
{
	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(AtomicFileSaveSeams::TryReplaceTempFile(CString(), CString(_T("target")), AtomicFileSaveSeams::GetReplaceFlags(false), &dwLastError));
	CHECK(dwLastError == ERROR_INVALID_PARAMETER);

	dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(AtomicFileSaveSeams::TryReplaceTempFile(CString(_T("temp")), CString(), AtomicFileSaveSeams::GetReplaceFlags(false), &dwLastError));
	CHECK(dwLastError == ERROR_INVALID_PARAMETER);
}

TEST_SUITE_END;
