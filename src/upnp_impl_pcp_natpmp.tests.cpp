#include "../third_party/doctest/doctest.h"

#include "UPnPDiscoveryThreadSeams.h"
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

#if defined(EMULE_TEST_HAVE_UPNP_DISCOVERY_THREAD_SEAMS)
TEST_CASE("Shared UPnP discovery seam classifies cooperative stop waits")
{
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_OBJECT_0) == UPnPDiscoveryThreadSeams::EStopWaitAction::ReleaseFinished);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_FAILED) == UPnPDiscoveryThreadSeams::EStopWaitAction::ReleaseAfterWaitFailure);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_TIMEOUT) == UPnPDiscoveryThreadSeams::EStopWaitAction::WaitCooperatively);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_ABANDONED) == UPnPDiscoveryThreadSeams::EStopWaitAction::WaitCooperatively);
}

TEST_CASE("Shared UPnP discovery seam uses interlocked abort flags")
{
	volatile LONG nAbortFlag = 0;

	CHECK_FALSE(UPnPDiscoveryThreadSeams::IsAbortRequested(nAbortFlag));
	UPnPDiscoveryThreadSeams::RequestAbort(nAbortFlag);
	CHECK(UPnPDiscoveryThreadSeams::IsAbortRequested(nAbortFlag));
	UPnPDiscoveryThreadSeams::ClearAbort(nAbortFlag);
	CHECK_FALSE(UPnPDiscoveryThreadSeams::IsAbortRequested(nAbortFlag));
}
#endif

TEST_SUITE_END;
