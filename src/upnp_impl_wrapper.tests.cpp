#include "../third_party/doctest/doctest.h"

#include "UPnPImplWrapperSeams.h"

TEST_SUITE_BEGIN("parity");

#if defined(EMULEBB_TEST_HAVE_UPNP_WRAPPER_SEAMS)
TEST_CASE("UPnP wrapper automatic mode tries UPnP IGD before PCP NAT-PMP")
{
	const NatMappingBackendOrder order = BuildNatMappingBackendOrder(NAT_MAPPING_BACKEND_MODE_AUTOMATIC);

	REQUIRE_EQ(order.uCount, 2u);
	CHECK_EQ(order.aeBackends[0], NAT_MAPPING_BACKEND_UPNP_IGD);
	CHECK_EQ(order.aeBackends[1], NAT_MAPPING_BACKEND_PCP_NATPMP);
}

TEST_CASE("UPnP wrapper IGD-only mode tries only UPnP IGD")
{
	const NatMappingBackendOrder order = BuildNatMappingBackendOrder(NAT_MAPPING_BACKEND_MODE_UPNP_IGD_ONLY);

	REQUIRE_EQ(order.uCount, 1u);
	CHECK_EQ(order.aeBackends[0], NAT_MAPPING_BACKEND_UPNP_IGD);
}

TEST_CASE("UPnP wrapper PCP NAT-PMP-only mode tries only PCP NAT-PMP")
{
	const NatMappingBackendOrder order = BuildNatMappingBackendOrder(NAT_MAPPING_BACKEND_MODE_PCP_NATPMP_ONLY);

	REQUIRE_EQ(order.uCount, 1u);
	CHECK_EQ(order.aeBackends[0], NAT_MAPPING_BACKEND_PCP_NATPMP);
}

TEST_CASE("UPnP wrapper unknown mode falls back to automatic order")
{
	const NatMappingBackendOrder order = BuildNatMappingBackendOrder(255);

	REQUIRE_EQ(order.uCount, 2u);
	CHECK_EQ(order.aeBackends[0], NAT_MAPPING_BACKEND_UPNP_IGD);
	CHECK_EQ(order.aeBackends[1], NAT_MAPPING_BACKEND_PCP_NATPMP);
}
#endif

TEST_SUITE_END;
