#include "../third_party/doctest/doctest.h"

#include "kademlia/kademlia/KadIndexedLoadThreadSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Kad indexed load thread seam classifies launch results")
{
	int fakeThread = 0;

	CHECK(KadIndexedLoadThreadSeams::ClassifyLoadThreadLaunch(&fakeThread)
		== KadIndexedLoadThreadSeams::ELoadThreadLaunchAction::StartWorker);
	CHECK(KadIndexedLoadThreadSeams::ClassifyLoadThreadLaunch(nullptr)
		== KadIndexedLoadThreadSeams::ELoadThreadLaunchAction::DiscardWithoutStore);
}

TEST_CASE("Kad indexed load thread shutdown waits only for active incomplete loads")
{
	CHECK(KadIndexedLoadThreadSeams::ShouldWaitForLoadThreadShutdown(true, false));
	CHECK_FALSE(KadIndexedLoadThreadSeams::ShouldWaitForLoadThreadShutdown(false, false));
	CHECK_FALSE(KadIndexedLoadThreadSeams::ShouldWaitForLoadThreadShutdown(true, true));
	CHECK_FALSE(KadIndexedLoadThreadSeams::ShouldWaitForLoadThreadShutdown(false, true));
}

TEST_SUITE_END;
