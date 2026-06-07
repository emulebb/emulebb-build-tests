#include "../third_party/doctest/doctest.h"

#include "ClientLibraryBrowseDisplaySeams.h"

#include <atlstr.h>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Client library browse marker follows View Shared Files availability")
{
	CHECK(ClientLibraryBrowseDisplaySeams::ShouldShowLibraryBrowseMarker(true, true, true));
	CHECK_FALSE(ClientLibraryBrowseDisplaySeams::ShouldShowLibraryBrowseMarker(false, true, true));
	CHECK_FALSE(ClientLibraryBrowseDisplaySeams::ShouldShowLibraryBrowseMarker(true, true, false));
	CHECK_FALSE(ClientLibraryBrowseDisplaySeams::ShouldShowLibraryBrowseMarker(true, false, true));
	CHECK_FALSE(ClientLibraryBrowseDisplaySeams::ShouldShowLibraryBrowseMarker(false, false, false));
}

TEST_CASE("Client library browse marker appends after display name only when available")
{
	CString strName(_T("peer"));
	ClientLibraryBrowseDisplaySeams::AppendLibraryBrowseMarker(strName, true, true, true);

#ifdef _UNICODE
	REQUIRE(strName.GetLength() == 7);
	CHECK(strName.Left(4) == _T("peer"));
	CHECK(strName[4] == _T(' '));
	CHECK(strName[5] == static_cast<TCHAR>(0xD83D));
	CHECK(strName[6] == static_cast<TCHAR>(0xDCC1));
#else
	CHECK(strName == _T("peer [files]"));
#endif

	CString strBlocked(_T("peer"));
	ClientLibraryBrowseDisplaySeams::AppendLibraryBrowseMarker(strBlocked, true, true, false);
	CHECK(strBlocked == _T("peer"));

	CString strUnknown(_T("(Unknown)"));
	ClientLibraryBrowseDisplaySeams::AppendLibraryBrowseMarker(strUnknown, false, true, true);
	CHECK(strUnknown == _T("(Unknown)"));
}

TEST_SUITE_END();
