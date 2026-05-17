#include "../third_party/doctest/doctest.h"

#include "DirectDownloadSeams.h"

#include <vector>

TEST_SUITE_BEGIN("parity");

TEST_CASE("DirectDownload seam rejects handle registration after owner cancellation")
{
	CHECK(DirectDownloadSeams::ShouldRegisterInternetHandleForCancellationState(false));
	CHECK_FALSE(DirectDownloadSeams::ShouldRegisterInternetHandleForCancellationState(true));
}

TEST_CASE("DirectDownload seam normalizes multiline link input")
{
	CHECK(DirectDownloadSeams::NormalizeDirectDownloadEditText(CString(_T("one\ntwo\r\nthree"))) == CString(_T("one\r\ntwo\r\nthree")));

	const std::vector<CString> tokens = DirectDownloadSeams::TokenizeDirectDownloadLinks(CString(_T(" ed2k://|file|a|1|h|/\r\n\ted2k://|file|b|2|h|/ ")));
	REQUIRE(tokens.size() == 2u);
	CHECK(tokens[0] == CString(_T("ed2k://|file|a|1|h|/")));
	CHECK(tokens[1] == CString(_T("ed2k://|file|b|2|h|/")));
}

TEST_CASE("DirectDownload seam preserves parser slash and category defaults")
{
	CHECK(DirectDownloadSeams::NormalizeDirectDownloadLinkToken(CString(_T("ed2k://|file|a|1|h|"))) == CString(_T("ed2k://|file|a|1|h|/")));
	CHECK(DirectDownloadSeams::NormalizeDirectDownloadLinkToken(CString(_T("ed2k://|file|a|1|h|/"))) == CString(_T("ed2k://|file|a|1|h|/")));
	CHECK(DirectDownloadSeams::NormalizeDirectDownloadCategorySelection(2, 4) == 2);
	CHECK(DirectDownloadSeams::NormalizeDirectDownloadCategorySelection(-1, 4) == 0);
	CHECK(DirectDownloadSeams::NormalizeDirectDownloadCategorySelection(4, 4) == 0);
	CHECK(DirectDownloadSeams::NormalizeDirectDownloadCategorySelection(2, 0) == 0);
}

TEST_SUITE_END();
