#include "../third_party/doctest/doctest.h"

#include "UploadDiskIOThreadSeams.h"
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

#if defined(EMULE_TEST_HAVE_RETIRED_UPLOAD_ENTRY_PENDING_IO_WARNING_SEAM)
TEST_CASE("Upload queue seam warns only for retired entries with old pending IO")
{
	CHECK_EQ(kRetiredUploadEntryPendingIoWarningMs, static_cast<std::uint64_t>(30000u));
	CHECK_FALSE(ShouldWarnRetiredUploadEntryPendingIo(false, 1, 40000u, 1u, 0u));
	CHECK_FALSE(ShouldWarnRetiredUploadEntryPendingIo(true, 0, 40000u, 1u, 0u));
	CHECK_FALSE(ShouldWarnRetiredUploadEntryPendingIo(true, 1, 1000u, 0u, 0u));
	CHECK_FALSE(ShouldWarnRetiredUploadEntryPendingIo(true, 1, 29999u, 1u, 0u, 30000u));
	CHECK(ShouldWarnRetiredUploadEntryPendingIo(true, 1, 30001u, 1u, 0u, 30000u));
	CHECK_FALSE(ShouldWarnRetiredUploadEntryPendingIo(true, 1, 45001u, 1u, 30001u, 30000u, 30000u));
	CHECK(ShouldWarnRetiredUploadEntryPendingIo(true, 1, 60001u, 1u, 30001u, 30000u, 30000u));
}
#endif

TEST_CASE("Upload queue timer diagnostics count only loops slower than the interval budget")
{
	CHECK_EQ(kUploadTimerSlowLoopThresholdMs, static_cast<std::uint32_t>(100u));
	CHECK_FALSE(ShouldCountSlowUploadTimerLoop(100u));
	CHECK(ShouldCountSlowUploadTimerLoop(101u));
	CHECK_FALSE(ShouldCountSlowUploadTimerLoop(1u, 0u));
}

TEST_CASE("Upload queue presentation cadence is owned by the transfer display timer")
{
	CHECK(GetTransferDisplayRefreshTimerDelayMs(0u) == 0u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(500u) == 500u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(2000u) == 2000u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(10000u) == 10000u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(750u) == 2000u);
}

TEST_CASE("Upload disk IO seam bounds pending overlapped reads before Windows quota failure")
{
	CHECK(UploadDiskIOThreadSeams::CanIssuePendingUploadRead(0, 0));
	CHECK(UploadDiskIOThreadSeams::CanIssuePendingUploadRead(
		UploadDiskIOThreadSeams::kMaxPendingReadBlocksPerClient - 1,
		UploadDiskIOThreadSeams::kMaxPendingReadBlocksPerThread - 1));
	CHECK_FALSE(UploadDiskIOThreadSeams::CanIssuePendingUploadRead(
		UploadDiskIOThreadSeams::kMaxPendingReadBlocksPerClient,
		0));
	CHECK_FALSE(UploadDiskIOThreadSeams::CanIssuePendingUploadRead(
		0,
		UploadDiskIOThreadSeams::kMaxPendingReadBlocksPerThread));
	CHECK_FALSE(UploadDiskIOThreadSeams::CanIssuePendingUploadRead(-1, 0));
}

TEST_SUITE_END;
