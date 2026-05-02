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

TEST_CASE("line joining keeps raw values one per line")
{
	std::vector<CString> values{ _T("first"), CString(), _T("second") };

	CHECK(ProUserMenuCopySeams::JoinLines(values) == _T("first\r\nsecond"));
}

TEST_SUITE_END();
