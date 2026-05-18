#include "../third_party/doctest/doctest.h"

#include "DirectDownloadSeams.h"
#include "HttpTransferSeams.h"

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

TEST_CASE("HTTP transfer profiles bound maintenance downloads by use case")
{
	const HttpTransferSeams::SRequestLimits release = HttpTransferSeams::GetRequestLimitsForProfile(HttpTransferSeams::ERequestProfile::ReleaseUpdateJson);
	CHECK(release.dwConnectTimeoutMs == 7000u);
	CHECK(release.dwSendTimeoutMs == 7000u);
	CHECK(release.dwReceiveTimeoutMs == 7000u);
	CHECK(release.ullTotalTimeoutMs == 7000ull);
	CHECK(release.ullMaxResponseBytes == HttpTransferSeams::KiB(512));

	const HttpTransferSeams::SRequestLimits serverMet = HttpTransferSeams::GetRequestLimitsForProfile(HttpTransferSeams::ERequestProfile::ServerMet);
	CHECK(serverMet.ullTotalTimeoutMs == 30000ull);
	CHECK(serverMet.ullMaxResponseBytes == HttpTransferSeams::MiB(2));

	const HttpTransferSeams::SRequestLimits nodesDat = HttpTransferSeams::GetRequestLimitsForProfile(HttpTransferSeams::ERequestProfile::NodesDat);
	CHECK(nodesDat.ullTotalTimeoutMs == 30000ull);
	CHECK(nodesDat.ullMaxResponseBytes == HttpTransferSeams::MiB(2));

	const HttpTransferSeams::SRequestLimits ipFilter = HttpTransferSeams::GetRequestLimitsForProfile(HttpTransferSeams::ERequestProfile::IPFilter);
	CHECK(ipFilter.ullTotalTimeoutMs == 180000ull);
	CHECK(ipFilter.ullMaxResponseBytes == HttpTransferSeams::MiB(64));

	const HttpTransferSeams::SRequestLimits geoDatabase = HttpTransferSeams::GetRequestLimitsForProfile(HttpTransferSeams::ERequestProfile::GeoDatabase);
	CHECK(geoDatabase.ullTotalTimeoutMs == 600000ull);
	CHECK(geoDatabase.ullMaxResponseBytes == HttpTransferSeams::MiB(192));

	const HttpTransferSeams::SRequestLimits generic = HttpTransferSeams::GetRequestLimitsForProfile(HttpTransferSeams::ERequestProfile::GenericFileDownload);
	CHECK(generic.ullTotalTimeoutMs == 300000ull);
	CHECK(generic.ullMaxResponseBytes == HttpTransferSeams::MiB(64));
}

TEST_CASE("HTTP transfer limit seams accept exact limits and reject overflow-safe growth")
{
	const ULONGLONG limit = HttpTransferSeams::MiB(2);
	CHECK(HttpTransferSeams::IsKnownContentLengthAllowed(0, limit));
	CHECK(HttpTransferSeams::IsKnownContentLengthAllowed(limit, limit));
	CHECK_FALSE(HttpTransferSeams::IsKnownContentLengthAllowed(limit + 1ull, limit));
	CHECK(HttpTransferSeams::IsKnownContentLengthAllowed(limit + 1ull, 0));

	CHECK_FALSE(HttpTransferSeams::WouldExceedResponseLimit(0, static_cast<DWORD>(limit), limit));
	CHECK_FALSE(HttpTransferSeams::WouldExceedResponseLimit(limit - 1ull, 1u, limit));
	CHECK(HttpTransferSeams::WouldExceedResponseLimit(limit, 1u, limit));
	CHECK(HttpTransferSeams::WouldExceedResponseLimit(limit + 1ull, 0u, limit));
	CHECK(HttpTransferSeams::WouldExceedResponseLimit(~0ull - 4ull, 8u, ~0ull));
	CHECK_FALSE(HttpTransferSeams::WouldExceedResponseLimit(~0ull - 4ull, 4u, ~0ull));
	CHECK_FALSE(HttpTransferSeams::WouldExceedResponseLimit(~0ull, 1u, 0));
}

TEST_SUITE_END();
