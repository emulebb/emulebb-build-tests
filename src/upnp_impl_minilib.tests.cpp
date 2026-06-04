#include "../third_party/doctest/doctest.h"

#include "UPnPImplMiniLibSeams.h"

TEST_SUITE_BEGIN("parity");

#if defined(EMULEBB_TEST_HAVE_UPNP_MINILIB_SEAMS)
TEST_CASE("MiniUPnP seam accepts an existing mapping that already targets the requested LAN endpoint")
{
	CHECK(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "27198", "10.54.224.185", 27198));
	CHECK(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "27208", "10.54.224.185", 27208));
#if defined(EMULEBB_TEST_HAVE_UPNP_MINILIB_ADD_FAILURE_SEAM)
	CHECK(ShouldAcceptMiniUPnPExistingMappingAfterAddFailure(true, "10.54.224.185", "27198", "10.54.224.185", 27198));
#endif
}

TEST_CASE("MiniUPnP seam rejects missing or mismatched mapping targets")
{
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("", "27198", "10.54.224.185", 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "", "10.54.224.185", 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.186", "27198", "10.54.224.185", 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "27199", "10.54.224.185", 27198));
#if defined(EMULEBB_TEST_HAVE_UPNP_MINILIB_ADD_FAILURE_SEAM)
	CHECK_FALSE(ShouldAcceptMiniUPnPExistingMappingAfterAddFailure(true, "10.54.224.186", "27198", "10.54.224.185", 27198));
	CHECK_FALSE(ShouldAcceptMiniUPnPExistingMappingAfterAddFailure(true, "10.54.224.185", "27199", "10.54.224.185", 27198));
	CHECK_FALSE(ShouldAcceptMiniUPnPExistingMappingAfterAddFailure(false, "10.54.224.185", "27198", "10.54.224.185", 27198));
#endif
}

TEST_CASE("MiniUPnP seam rejects null inputs and formatting mismatches")
{
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest(nullptr, "27198", "10.54.224.185", 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", nullptr, "10.54.224.185", 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "27198", nullptr, 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "27198", "", 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "027198", "10.54.224.185", 27198));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "0", "10.54.224.185", 27198));
}

TEST_CASE("MiniUPnP seam accepts zero-port mappings only when both sides truly match")
{
	CHECK(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "0", "10.54.224.185", 0));
	CHECK_FALSE(DoesMiniUPnPMappingMatchRequest("10.54.224.185", "1", "10.54.224.185", 0));
}

TEST_CASE("MiniUPnP deletes only mappings created by the current process")
{
	CHECK(ShouldDeleteMiniUPnPPortMapping(27198, true));
	CHECK_FALSE(ShouldDeleteMiniUPnPPortMapping(27198, false));
	CHECK_FALSE(ShouldDeleteMiniUPnPPortMapping(0, true));
	CHECK_FALSE(ShouldDeleteMiniUPnPPortMapping(0, false));
}
#endif

TEST_SUITE_END;
