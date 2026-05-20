#include "../third_party/doctest/doctest.h"

#include "DropTargetSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Drop target seam accepts only ED2K text drops")
{
	CHECK(DropTargetSeams::IsSupportedTextDrop(L"ed2k://|file|example.bin|1|0123456789ABCDEF0123456789ABCDEF|/"));
	CHECK(DropTargetSeams::IsSupportedTextDrop("  ed2k://|server|127.0.0.1|4661|/"));

	CHECK_FALSE(DropTargetSeams::IsSupportedTextDrop(L"magnet:?xt=urn:btih:0123456789abcdef"));
	CHECK_FALSE(DropTargetSeams::IsSupportedTextDrop("magnet:?xt=urn:ed2k:0123456789ABCDEF0123456789ABCDEF"));
	CHECK_FALSE(DropTargetSeams::IsSupportedTextDrop(L"C:\\Temp\\link.url"));
	CHECK_FALSE(DropTargetSeams::IsSupportedTextDrop(static_cast<const wchar_t*>(NULL)));
	CHECK_FALSE(DropTargetSeams::IsSupportedTextDrop(static_cast<const char*>(NULL)));
}

TEST_SUITE_END;
