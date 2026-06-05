#include "../third_party/doctest/doctest.h"

#include "ServerInfoSeams.h"

TEST_SUITE_BEGIN("server_info");

TEST_CASE("Server info drops empty and whitespace-only messages")
{
	CHECK(ServerInfoSeams::SplitServerInfoMessageLines(_T("")).empty());
	CHECK(ServerInfoSeams::SplitServerInfoMessageLines(_T("   \t  ")).empty());
	CHECK(ServerInfoSeams::SplitServerInfoMessageLines(_T("\r\n\n\r")).empty());
}

TEST_CASE("Server info splits multiline payloads and trims retained lines")
{
	const std::vector<CString> lines = ServerInfoSeams::SplitServerInfoMessageLines(_T("\r\n  hello \r\n\r\nworld\n\tlast line\t"));

	REQUIRE(lines.size() == 3);
	CHECK(lines[0] == CString(_T("hello")));
	CHECK(lines[1] == CString(_T("world")));
	CHECK(lines[2] == CString(_T("last line")));
}

TEST_CASE("Server info drops blank lines from server welcome payloads")
{
	const std::vector<CString> lines = ServerInfoSeams::SplitServerInfoMessageLines(
		_T("Welcome to eMule Security! <> www.emule-security.org\r\n")
		_T("\r\n")
		_T("Download Safe Serverlist > http://www.emule-security.org/serverlist/\r\n")
		_T("\r\n")
		_T("IP-filter > http://www.emule-security.org/e107_plugins/faq/faq.php?0.cat.2.1"));

	REQUIRE(lines.size() == 3);
	CHECK(lines[0] == CString(_T("Welcome to eMule Security! <> www.emule-security.org")));
	CHECK(lines[1] == CString(_T("Download Safe Serverlist > http://www.emule-security.org/serverlist/")));
	CHECK(lines[2] == CString(_T("IP-filter > http://www.emule-security.org/e107_plugins/faq/faq.php?0.cat.2.1")));
}

TEST_CASE("Server info preserves non-empty single-line message text after trimming")
{
	const std::vector<CString> lines = ServerInfoSeams::SplitServerInfoMessageLines(_T("  VPN Guard blocked: reason  "));

	REQUIRE(lines.size() == 1);
	CHECK(lines[0] == CString(_T("VPN Guard blocked: reason")));
}

TEST_SUITE_END();
