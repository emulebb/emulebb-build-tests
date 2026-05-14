#include "../third_party/doctest/doctest.h"

#include "UploadQueueSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Upload queue seam classifies only active non-retired entries with a client as live")
{
	CHECK_EQ(ClassifyUploadQueueEntryAccess(true, false, true), uploadQueueEntryLive);
	CHECK_EQ(ClassifyUploadQueueEntryAccess(true, true, true), uploadQueueEntryRetired);
	CHECK_EQ(ClassifyUploadQueueEntryAccess(true, false, false), uploadQueueEntryRetired);
	CHECK_EQ(ClassifyUploadQueueEntryAccess(false, false, true), uploadQueueEntryMissing);
}

TEST_CASE("Upload queue seam reclaims retired entries only after pending IO drains")
{
	CHECK(CanReclaimUploadQueueEntry(true, 0));
	CHECK_FALSE(CanReclaimUploadQueueEntry(true, 1));
	CHECK_FALSE(CanReclaimUploadQueueEntry(false, 0));
}

TEST_CASE("Upload queue timer diagnostics count only loops slower than the interval budget")
{
	CHECK_EQ(kUploadTimerSlowLoopThresholdMs, static_cast<std::uint32_t>(100u));
	CHECK_FALSE(ShouldCountSlowUploadTimerLoop(100u));
	CHECK(ShouldCountSlowUploadTimerLoop(101u));
	CHECK_FALSE(ShouldCountSlowUploadTimerLoop(1u, 0u));
}

TEST_SUITE_END;
