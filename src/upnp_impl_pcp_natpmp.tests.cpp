#include "../third_party/doctest/doctest.h"

#include "UPnPImplPcpNatPmpSeams.h"

TEST_SUITE_BEGIN("parity");

#if defined(EMULE_TEST_HAVE_UPNP_PCP_NATPMP_SEAMS)
TEST_CASE("PCP NAT-PMP discovery thread seam releases finished or stale wrappers")
{
	CHECK(ClassifyPcpNatPmpDiscoveryThreadWait(WAIT_OBJECT_0) == EPcpNatPmpDiscoveryThreadWaitAction::ReleaseFinished);
	CHECK(ClassifyPcpNatPmpDiscoveryThreadWait(WAIT_FAILED) == EPcpNatPmpDiscoveryThreadWaitAction::ReleaseAfterWaitFailure);
}

TEST_CASE("PCP NAT-PMP discovery thread seam keeps live wrappers")
{
	CHECK(ClassifyPcpNatPmpDiscoveryThreadWait(WAIT_TIMEOUT) == EPcpNatPmpDiscoveryThreadWaitAction::KeepWaiting);
	CHECK(ClassifyPcpNatPmpDiscoveryThreadWait(WAIT_ABANDONED) == EPcpNatPmpDiscoveryThreadWaitAction::KeepWaiting);
}
#endif

TEST_SUITE_END;
