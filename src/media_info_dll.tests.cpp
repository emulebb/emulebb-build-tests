#include "../third_party/doctest/doctest.h"

#include "MediaInfoDllSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("MediaInfo DLL seam keeps the no-load marker explicit")
{
	CHECK(MediaInfoDllSeams::IsLoadingDisabled(_T("<noload>")));
	CHECK(MediaInfoDllSeams::IsLoadingDisabled(_T("<NOLOAD>")));
	CHECK_FALSE(MediaInfoDllSeams::IsLoadingDisabled(_T("MEDIAINFO.DLL")));
	CHECK_FALSE(MediaInfoDllSeams::IsLoadingDisabled(_T("")));
}

TEST_CASE("MediaInfo DLL seam enforces the release minimum version")
{
	CHECK_FALSE(MediaInfoDllSeams::IsCompatibleVersion(MAKEDLLVERULL(26, 0, 999, 999)));
	CHECK(MediaInfoDllSeams::IsCompatibleVersion(MAKEDLLVERULL(26, 1, 0, 0)));
	CHECK(MediaInfoDllSeams::IsCompatibleVersion(MAKEDLLVERULL(27, 0, 0, 0)));
}

TEST_CASE("MediaInfo DLL seam deduplicates absolute candidate paths")
{
	CStringArray paths;

	MediaInfoDllSeams::AddAbsoluteCandidatePath(paths, _T("C:\\MediaInfo\\MEDIAINFO.DLL"));
	MediaInfoDllSeams::AddAbsoluteCandidatePath(paths, _T("c:\\mediainfo\\mediainfo.dll"));
	MediaInfoDllSeams::AddAbsoluteCandidatePath(paths, _T("MEDIAINFO.DLL"));

	REQUIRE(paths.GetCount() == 1);
	CHECK(paths[0] == _T("C:\\MediaInfo\\MEDIAINFO.DLL"));
}

TEST_CASE("MediaInfo DLL seam resolves relative configured paths under the app folder")
{
	CStringArray paths;

	MediaInfoDllSeams::AddRelativeConfiguredCandidatePath(paths, _T("C:\\Program Files\\eMule"), _T("tools\\MediaInfo.dll"));
	MediaInfoDllSeams::AddRelativeConfiguredCandidatePath(paths, _T("C:\\Program Files\\eMule"), _T("D:\\Tools\\MediaInfo.dll"));

	REQUIRE(paths.GetCount() == 1);
	CHECK(paths[0] == _T("C:\\Program Files\\eMule\\tools\\MediaInfo.dll"));
}

TEST_CASE("MediaInfo DLL seam treats zero open result as failure")
{
	CHECK_FALSE(MediaInfoDllSeams::IsOpenSucceeded(0));
	CHECK(MediaInfoDllSeams::IsOpenSucceeded(1));
	CHECK(MediaInfoDllSeams::IsOpenSucceeded(42));
}

TEST_SUITE_END;
