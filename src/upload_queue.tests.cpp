#include "../third_party/doctest/doctest.h"

#include "UploadQueueSeams.h"
#if __has_include("UploadDiskIOThreadSeams.h")
#include "UploadDiskIOThreadSeams.h"
#define EMULEBB_TEST_HAVE_UPLOAD_DISK_IO_PENDING_READ_SEAMS 1
#endif

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

#if defined(EMULEBB_TEST_HAVE_RETIRED_UPLOAD_ENTRY_PENDING_IO_WARNING_SEAM)
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

TEST_CASE("Upload queue admission ignores peers held in slow-upload cooldown")
{
	CHECK(IsUploadQueueAdmissionCandidate(false));
	CHECK_FALSE(IsUploadQueueAdmissionCandidate(true));
}

TEST_CASE("Upload queue attempts admission only with an eligible waiting candidate unless direct admission allows empty queue")
{
	CHECK(ShouldAttemptUploadSlotAdmission(true, true, false));
	CHECK(ShouldAttemptUploadSlotAdmission(true, false, false));
	CHECK(ShouldAttemptUploadSlotAdmission(false, false, true));
	CHECK_FALSE(ShouldAttemptUploadSlotAdmission(false, true, false));
	CHECK_FALSE(ShouldAttemptUploadSlotAdmission(false, false, false));
}

TEST_CASE("Upload queue direct admission bypasses only cooldown-only waiting lists")
{
	CHECK(ShouldDirectAdmitBehindCooldownOnlyWaitingList(false, false));
	CHECK_FALSE(ShouldDirectAdmitBehindCooldownOnlyWaitingList(true, false));
	CHECK_FALSE(ShouldDirectAdmitBehindCooldownOnlyWaitingList(false, true));
	CHECK_FALSE(ShouldDirectAdmitBehindCooldownOnlyWaitingList(true, true));
}

TEST_CASE("Upload queue retry cooldown applies only to non-friend peers with live IP cooldowns")
{
	CHECK(ShouldApplyUploadRetryCooldown(false, 0x01020304u, 1000u, 2000u));
	CHECK_FALSE(ShouldApplyUploadRetryCooldown(true, 0x01020304u, 1000u, 2000u));
	CHECK_FALSE(ShouldApplyUploadRetryCooldown(false, 0u, 1000u, 2000u));
	CHECK_FALSE(ShouldApplyUploadRetryCooldown(false, 0x01020304u, 2000u, 2000u));
	CHECK_FALSE(ShouldApplyUploadRetryCooldown(false, 0x01020304u, 3000u, 2000u));
}

TEST_CASE("Upload queue cools down failed upload admissions only for non-friend peers with an IP")
{
	CHECK(ShouldCooldownFailedUploadAdmission(true, false, 0x01020304u));
	CHECK_FALSE(ShouldCooldownFailedUploadAdmission(false, false, 0x01020304u));
	CHECK_FALSE(ShouldCooldownFailedUploadAdmission(true, true, 0x01020304u));
	CHECK_FALSE(ShouldCooldownFailedUploadAdmission(true, false, 0u));
}

TEST_CASE("Broadband idle upload recycling requires an empty local send pipeline")
{
	CHECK(ShouldRecycleIdleBroadbandUploadSlot(true, true, false, 0u, 0u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(false, true, false, 0u, 0u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, false, false, 0u, 0u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, true, true, 0u, 0u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, true, false, 1u, 0u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, true, false, 0u, 1u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, true, false, 0u, 0u, 1, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, true, false, 0u, 0u, 0, 1, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, true, false, 0u, 0u, 0, 0, 1, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleIdleBroadbandUploadSlot(true, true, false, 0u, 0u, 0, 0, 0, 9999u, 10000u));
}

TEST_CASE("Broadband no-request recycling bypasses slow warmup only for drained slots")
{
	CHECK(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 0, 0, 0, 10000u, true, 10000u, 10000u));
	CHECK(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 0, 0, 0, 10000u, false, 0u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(false, false, 0u, 0u, 0, 0, 0, 10000u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, true, 0u, 0u, 0, 0, 0, 10000u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 1u, 0u, 0, 0, 0, 10000u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 1u, 0, 0, 0, 10000u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 1, 0, 0, 10000u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 0, 1, 0, 10000u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 0, 0, 1, 10000u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 0, 0, 0, 9999u, true, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 0, 0, 0, 10000u, true, 9999u, 10000u));
	CHECK_FALSE(ShouldRecycleNoRequestBroadbandUploadSlot(true, false, 0u, 0u, 0, 0, 0, 10000u, true, 0u, 10000u));
}

TEST_CASE("Broadband no-request cooldown covers drained sessions")
{
	CHECK(ShouldCooldownNoRequestUploadRecycle(false));
	CHECK_FALSE(ShouldCooldownNoRequestUploadRecycle(true));

	CHECK_FALSE(IsProductiveNoRequestUploadRecycle(kProductiveNoRequestCooldownPayloadBytes - 1u));
	CHECK(IsProductiveNoRequestUploadRecycle(kProductiveNoRequestCooldownPayloadBytes));

	CHECK(GetNoRequestUploadRetryCooldownSeconds(10u, false) == 10u);
	CHECK(GetNoRequestUploadRetryCooldownSeconds(kNoRequestUploadCooldownMaxSeconds, false) == kNoRequestUploadCooldownMaxSeconds);
	CHECK(GetNoRequestUploadRetryCooldownSeconds(120u, false) == kNoRequestUploadCooldownMaxSeconds);
	CHECK(GetNoRequestUploadRetryCooldownSeconds(120u, true) == 120u);
	CHECK(GetNoRequestUploadRetryCooldownSeconds(120u, true, true) == kNoRequestUploadCooldownMaxSeconds);
}

TEST_CASE("Upload queue clears retry cooldown only when queued peers request valid blocks")
{
	CHECK(ShouldClearUploadRetryCooldownOnQueuedRequest(true, true, true, true));
	CHECK_FALSE(ShouldClearUploadRetryCooldownOnQueuedRequest(false, true, true, true));
	CHECK_FALSE(ShouldClearUploadRetryCooldownOnQueuedRequest(true, false, true, true));
	CHECK_FALSE(ShouldClearUploadRetryCooldownOnQueuedRequest(true, true, false, true));
	CHECK_FALSE(ShouldClearUploadRetryCooldownOnQueuedRequest(true, true, true, false));
}

TEST_CASE("Upload queue clears no-request cooldown only once per cooldown window")
{
	CHECK(ShouldAllowNoRequestCooldownClear(false, false));
	CHECK(ShouldAllowNoRequestCooldownClear(false, true));
	CHECK(ShouldAllowNoRequestCooldownClear(true, false));
	CHECK_FALSE(ShouldAllowNoRequestCooldownClear(true, true));

	CHECK(ShouldAllowUploadRetryCooldownClear(false, false));
	CHECK(ShouldAllowUploadRetryCooldownClear(false, true));
	CHECK(ShouldAllowUploadRetryCooldownClear(true, false));
	CHECK_FALSE(ShouldAllowUploadRetryCooldownClear(true, true));
}

TEST_CASE("Broadband stalled upload recycling requires queued work and replacement pressure")
{
	CHECK(HasStalledUploadReplacementPressure(true, 12, 12));
	CHECK(HasStalledUploadReplacementPressure(false, 11, 12));
	CHECK_FALSE(HasStalledUploadReplacementPressure(false, 12, 12));

	CHECK(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, true, 0u, 1u, 0, 0, 0, 10000u, 10000u));
	CHECK(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, true, 0u, 0u, 1, 0, 0, 10000u, 10000u));
	CHECK(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, true, 0u, 0u, 0, 0, 1, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(false, true, false, true, 0u, 1u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(true, false, false, true, 0u, 1u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(true, true, true, true, 0u, 1u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, false, 0u, 1u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, true, 1u, 1u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, true, 0u, 0u, 0, 1, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, true, 0u, 0u, 0, 0, 0, 10000u, 10000u));
	CHECK_FALSE(ShouldRecycleStalledBroadbandUploadSlot(true, true, false, true, 0u, 1u, 0, 0, 0, 9999u, 10000u));
}

TEST_CASE("Upload queue cools down only short low-payload disconnect churn")
{
	CHECK(ShouldCooldownShortFailedUploadSlot(true, false, false, 1000u, 0u));
	CHECK(ShouldCooldownShortFailedUploadSlot(true, false, false, kShortFailedUploadCooldownMaxAgeMs, kShortFailedUploadCooldownMaxPayloadBytes));
	CHECK(ShouldCooldownShortFailedUploadSlot(true, true, false, kShortFailedUploadCooldownMaxAgeMs + 1u, 0u));
	CHECK(ShouldCooldownShortFailedUploadSlot(true, true, false, kRemoteCancelledUploadCooldownMaxAgeMs, kShortFailedUploadCooldownMaxPayloadBytes));
	CHECK_FALSE(ShouldCooldownShortFailedUploadSlot(false, false, false, 1000u, 0u));
	CHECK_FALSE(ShouldCooldownShortFailedUploadSlot(true, false, true, 1000u, 0u));
	CHECK_FALSE(ShouldCooldownShortFailedUploadSlot(true, false, false, kShortFailedUploadCooldownMaxAgeMs + 1u, 0u));
	CHECK_FALSE(ShouldCooldownShortFailedUploadSlot(true, true, false, kRemoteCancelledUploadCooldownMaxAgeMs + 1u, 0u));
	CHECK_FALSE(ShouldCooldownShortFailedUploadSlot(true, true, false, 1000u, kShortFailedUploadCooldownMaxPayloadBytes + 1u));
}

TEST_CASE("Upload queue cools down only short no-socket upload churn")
{
	CHECK(ShouldCooldownNoSocketUploadSlot(true, false, 0x01020304u, 1000u, 0u));
	CHECK(ShouldCooldownNoSocketUploadSlot(true, false, 0x01020304u, kShortFailedUploadCooldownMaxAgeMs, kShortFailedUploadCooldownMaxPayloadBytes));
	CHECK_FALSE(ShouldCooldownNoSocketUploadSlot(false, false, 0x01020304u, 1000u, 0u));
	CHECK_FALSE(ShouldCooldownNoSocketUploadSlot(true, true, 0x01020304u, 1000u, 0u));
	CHECK_FALSE(ShouldCooldownNoSocketUploadSlot(true, false, 0u, 1000u, 0u));
	CHECK_FALSE(ShouldCooldownNoSocketUploadSlot(true, false, 0x01020304u, kShortFailedUploadCooldownMaxAgeMs + 1u, 0u));
	CHECK_FALSE(ShouldCooldownNoSocketUploadSlot(true, false, 0x01020304u, 1000u, kShortFailedUploadCooldownMaxPayloadBytes + 1u));
}

TEST_CASE("Upload queue keeps productive limited sessions during broadband underfill")
{
	CHECK(ShouldRotateBroadbandLimitedUploadSession(true, false, 100000u, 50000u));
	CHECK(ShouldRotateBroadbandLimitedUploadSession(true, true, 49999u, 50000u));
	CHECK_FALSE(ShouldRotateBroadbandLimitedUploadSession(false, false, 100000u, 50000u));
	CHECK_FALSE(ShouldRotateBroadbandLimitedUploadSession(true, true, 50000u, 50000u));
	CHECK_FALSE(ShouldRotateBroadbandLimitedUploadSession(true, true, 100000u, 50000u));
}

TEST_CASE("Upload queue presentation cadence is owned by the unified desktop timer")
{
#ifdef EMULEBB_TEST_HAVE_UNIFIED_DESKTOP_PRESENTATION_TIMER
	CHECK(GetDesktopPresentationTimerDelayMs(0u) == 10000u);
	CHECK(GetDesktopPresentationTimerDelayMs(500u) == 500u);
	CHECK(GetDesktopPresentationTimerDelayMs(2000u) == 2000u);
	CHECK(GetDesktopPresentationTimerDelayMs(10000u) == 10000u);
	CHECK(GetDesktopPresentationTimerDelayMs(750u) == 2000u);
#else
	MESSAGE("Unified desktop presentation timer helpers are not available in this workspace.");
#endif
}

TEST_CASE("Upload disk IO seam bounds pending overlapped reads before Windows quota failure")
{
#ifdef EMULEBB_TEST_HAVE_UPLOAD_DISK_IO_PENDING_READ_SEAMS
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
#else
	MESSAGE("Upload disk IO pending-read helpers are not available in this workspace.");
#endif
}

TEST_SUITE_END;
