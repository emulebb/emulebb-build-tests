#include "../third_party/doctest/doctest.h"

#include "WebServerLegacySeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("WebServer legacy search seam validates historical file type tokens")
{
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Arc")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Audio")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Iso")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Doc")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Image")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Pro")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Video")));
	CHECK(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("EmuleCollection")));
	CHECK_FALSE(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("Program")));
	CHECK_FALSE(WebServerLegacySeams::IsLegacySearchFileTypeAllowed(_T("../Pro")));
	CHECK(WebServerLegacySeams::ShouldClearUnsupportedLegacySearchFileType(_T("Program")));
	CHECK_FALSE(WebServerLegacySeams::ShouldClearUnsupportedLegacySearchFileType(_T("Pro")));
}

TEST_CASE("WebServer legacy search seam preserves failure fallback policy")
{
	CHECK(WebServerLegacySeams::ShouldDeleteLegacySearchParamsAfterFailedStart());
	CHECK(WebServerLegacySeams::ShouldUseGenericLegacySearchErrorAfterException());
	CHECK(WebServerLegacySeams::ShouldFallbackToUncompressedResponseAfterGzipFailure());
}

TEST_CASE("WebServer legacy UI policy keeps REST transport independent from templates")
{
	CHECK(WebServerLegacySeams::ShouldStartWebTransport(true));
	CHECK_FALSE(WebServerLegacySeams::ShouldStartWebTransport(false));

	CHECK_FALSE(WebServerLegacySeams::ShouldLoadLegacyTemplates(true, false));
	CHECK(WebServerLegacySeams::ShouldLoadLegacyTemplates(true, true));
	CHECK_FALSE(WebServerLegacySeams::ShouldLoadLegacyTemplates(false, true));

	CHECK_FALSE(WebServerLegacySeams::ShouldServeLegacyWebUi(false));
	CHECK(WebServerLegacySeams::ShouldServeLegacyWebUi(true));
}

TEST_SUITE_END();
