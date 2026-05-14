#include "../third_party/doctest/doctest.h"

#include "WebServicesSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Web services seam parses trimmed service lines")
{
	WebServicesSeams::ParsedService parsed;
	REQUIRE(WebServicesSeams::TryParseServiceLine(
		_T("  Search Web for Clean Filename , https://duckduckgo.com/?q=#cleanfilename  \r\n"),
		parsed));

	CHECK(parsed.strMenuLabel == CString(_T("Search Web for Clean Filename")));
	CHECK(parsed.strUrl == CString(_T("https://duckduckgo.com/?q=#cleanfilename")));
	CHECK(parsed.bFileMacros);
}

TEST_CASE("Web services seam ignores comments and malformed lines")
{
	WebServicesSeams::ParsedService parsed;

	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T(""), parsed));
	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T("   \t\r\n"), parsed));
	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T("# comment"), parsed));
	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T("; comment"), parsed));
	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T("/ comment"), parsed));
	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T("No comma"), parsed));
	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T(",https://example.invalid"), parsed));
	CHECK_FALSE(WebServicesSeams::TryParseServiceLine(_T("Missing URL,"), parsed));
}

TEST_CASE("Web services seam distinguishes file-context and general actions")
{
	WebServicesSeams::ParsedService parsed;

	REQUIRE(WebServicesSeams::TryParseServiceLine(_T("Homepage,https://www.emule-project.com/"), parsed));
	CHECK_FALSE(parsed.bFileMacros);

	REQUIRE(WebServicesSeams::TryParseServiceLine(_T("Hash Search,https://example.invalid/?hash=#hashid&size=#filesize"), parsed));
	CHECK(parsed.bFileMacros);
	CHECK(WebServicesSeams::ContainsFileMacro(_T("https://example.invalid/?q=#filename")));
	CHECK(WebServicesSeams::ContainsFileMacro(_T("https://example.invalid/?q=#name")));
	CHECK(WebServicesSeams::ContainsFileMacro(_T("https://example.invalid/?q=#cleanname")));
	CHECK_FALSE(WebServicesSeams::ContainsFileMacro(_T("https://example.invalid/?q=filename")));
}

TEST_CASE("Web services seam declares the reserved menu range limit")
{
	CHECK(WebServicesSeams::kMaxWebServiceMenuEntries == 100u);
}

TEST_SUITE_END();
