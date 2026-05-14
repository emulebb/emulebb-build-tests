#include "../third_party/doctest/doctest.h"

#include "DownloadQueueAutoCatSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Download queue auto-category seam evaluates the first non-empty token")
{
	CHECK(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("movie")),
		CString(_T("Movie.Release.avi"))));
}

TEST_CASE("Download queue auto-category seam evaluates later pipe-delimited tokens")
{
	CHECK(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("ebook|movie|music")),
		CString(_T("New.Movie.Release.avi"))));
	CHECK_FALSE(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("ebook|music|archive")),
		CString(_T("New.Movie.Release.avi"))));
}

TEST_CASE("Download queue auto-category seam ignores empty pipe tokens")
{
	CHECK(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("|movie||")),
		CString(_T("New.Movie.Release.avi"))));
	CHECK_FALSE(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("|||")),
		CString(_T("New.Movie.Release.avi"))));
}

TEST_CASE("Download queue auto-category seam supports wildcard patterns")
{
	CHECK(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("*.avi")),
		CString(_T("New.Movie.Release.avi"))));
	CHECK(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("fake*release*")),
		CString(_T("Fake.Movie.Release.Candidate.mkv"))));
	CHECK_FALSE(DownloadQueueAutoCatSeams::MatchesNonRegexAutoCategory(
		CString(_T("*.iso")),
		CString(_T("New.Movie.Release.avi"))));
}

TEST_SUITE_END;
