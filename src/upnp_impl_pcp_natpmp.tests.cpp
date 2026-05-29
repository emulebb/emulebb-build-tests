#include "../third_party/doctest/doctest.h"

#include "UPnPDiscoveryThreadSeams.h"

TEST_SUITE_BEGIN("parity");

#if defined(EMULEBB_TEST_HAVE_UPNP_DISCOVERY_THREAD_SEAMS)
TEST_CASE("Shared UPnP discovery seam classifies nonblocking reap waits")
{
	CHECK(UPnPDiscoveryThreadSeams::ClassifyNonblockingWait(WAIT_OBJECT_0) == UPnPDiscoveryThreadSeams::ENonblockingWaitAction::ReleaseFinished);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyNonblockingWait(WAIT_FAILED) == UPnPDiscoveryThreadSeams::ENonblockingWaitAction::ReleaseAfterWaitFailure);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyNonblockingWait(WAIT_TIMEOUT) == UPnPDiscoveryThreadSeams::ENonblockingWaitAction::KeepWaiting);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyNonblockingWait(WAIT_ABANDONED) == UPnPDiscoveryThreadSeams::ENonblockingWaitAction::KeepWaiting);
}

TEST_CASE("Shared UPnP discovery seam classifies cooperative stop waits")
{
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_OBJECT_0) == UPnPDiscoveryThreadSeams::EStopWaitAction::ReleaseFinished);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_FAILED) == UPnPDiscoveryThreadSeams::EStopWaitAction::ReleaseAfterWaitFailure);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_TIMEOUT) == UPnPDiscoveryThreadSeams::EStopWaitAction::WaitCooperatively);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyStopWait(WAIT_ABANDONED) == UPnPDiscoveryThreadSeams::EStopWaitAction::WaitCooperatively);
}

TEST_CASE("Shared UPnP discovery seam classifies owner-lifetime waits")
{
	CHECK(UPnPDiscoveryThreadSeams::ClassifyOwnerLifetimeWait(WAIT_OBJECT_0) == UPnPDiscoveryThreadSeams::EOwnerLifetimeWaitAction::ReleaseFinished);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyOwnerLifetimeWait(WAIT_FAILED) == UPnPDiscoveryThreadSeams::EOwnerLifetimeWaitAction::ReleaseAfterWaitFailure);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyOwnerLifetimeWait(WAIT_TIMEOUT) == UPnPDiscoveryThreadSeams::EOwnerLifetimeWaitAction::ReleaseAfterWaitFailure);
	CHECK(UPnPDiscoveryThreadSeams::ClassifyOwnerLifetimeWait(WAIT_ABANDONED) == UPnPDiscoveryThreadSeams::EOwnerLifetimeWaitAction::ReleaseAfterWaitFailure);
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

TEST_CASE("Shared UPnP discovery seam classifies suspended-worker resume results")
{
	CHECK(UPnPDiscoveryThreadSeams::DidResumeDiscoveryThread(0));
	CHECK(UPnPDiscoveryThreadSeams::DidResumeDiscoveryThread(4));
	CHECK_FALSE(UPnPDiscoveryThreadSeams::DidResumeDiscoveryThread(static_cast<DWORD>(-1)));
}
#endif

TEST_SUITE_END;
