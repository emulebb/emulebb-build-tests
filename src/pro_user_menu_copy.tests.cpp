#include "doctest.h"

#include "ProUserMenuCopySeams.h"

TEST_SUITE_BEGIN("pro_user_menu_copy");

TEST_CASE("summary formatting preserves field order and omits missing fields")
{
	std::vector<ProUserMenuCopySeams::NamedField> fields;
	ProUserMenuCopySeams::AppendField(fields, _T("username"), _T("alice"));
	ProUserMenuCopySeams::AppendField(fields, _T("client"), CString());
	ProUserMenuCopySeams::AppendField(fields, _T("ip"), _T("203.0.113.10"));

	CHECK(ProUserMenuCopySeams::FormatSummary(fields) == _T("username=\"alice\"; ip=\"203.0.113.10\""));
}

TEST_CASE("file summary formatting preserves stable fields and omits missing details")
{
	CHECK(ProUserMenuCopySeams::FormatFileSummary(
		_T("sample.iso"),
		_T("0123456789ABCDEF0123456789ABCDEF"),
		_T("12345"),
		CString(),
		CString(),
		_T("C:\\Incoming\\sample.iso"),
		_T("ed2k://|file|sample.iso|12345|hash|/"))
		== _T("name=\"sample.iso\"; hash=\"0123456789ABCDEF0123456789ABCDEF\"; size=\"12345\"; path=\"C:\\Incoming\\sample.iso\"; link=\"ed2k://|file|sample.iso|12345|hash|/\""));
}

TEST_CASE("line joining keeps raw values one per line")
{
	std::vector<CString> values{ _T("first"), CString(), _T("second") };

	CHECK(ProUserMenuCopySeams::JoinLines(values) == _T("first\r\nsecond"));
}

TEST_CASE("copy field formatters use stable machine-readable values")
{
	CHECK(ProUserMenuCopySeams::FormatUInt64(1234567890123ULL) == _T("1234567890123"));
	CHECK(ProUserMenuCopySeams::FormatPercent(12.345) == _T("12.3%"));
}

TEST_SUITE_END();
