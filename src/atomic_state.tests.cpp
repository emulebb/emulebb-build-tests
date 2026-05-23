#include "../third_party/doctest/doctest.h"

#include "../include/TestSupport.h"

#include <atomic>
#include <memory>
#include <string>

#include "AppStateSeams.h"
#include "AtomicStateSeams.h"
#include "DisplayRefreshSeams.h"
#include "SharedFileListSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Display refresh mask atomically merges new bits without losing the previous state")
{
	std::atomic<LONG> nPendingMask(0);

	CHECK(AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_DOWNLOAD_LIST) == 0);
	CHECK(nPendingMask.load() == DISPLAY_REFRESH_DOWNLOAD_LIST);

	CHECK(AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_CLIENT_LIST) == DISPLAY_REFRESH_DOWNLOAD_LIST);
	CHECK(nPendingMask.load() == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_CLIENT_LIST));

	CHECK(AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_DOWNLOAD_LIST) == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_CLIENT_LIST));
	CHECK(nPendingMask.load() == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_CLIENT_LIST));
}

TEST_CASE("Display refresh helper queues only when work is off the main thread")
{
	CHECK_FALSE(ShouldQueueDisplayRefresh(77u, 77u));
	CHECK_FALSE(ShouldQueueDisplayRefresh(77u, 0u));
	CHECK(ShouldQueueDisplayRefresh(41u, 77u));
}

TEST_CASE("Display refresh helper respects force and the randomized throttle window")
{
	CHECK_FALSE(ShouldRunDisplayRefresh(false, 199u, 100u, 100u, 0u));
	CHECK(ShouldRunDisplayRefresh(false, 200u, 100u, 100u, 0u));
	CHECK_FALSE(ShouldRunDisplayRefresh(false, 249u, 100u, 100u, 50u));
	CHECK(ShouldRunDisplayRefresh(false, 250u, 100u, 100u, 50u));
	CHECK(ShouldRunDisplayRefresh(true, 101u, 100u, 100u, 50u));
}

#if defined(EMULE_TEST_HAVE_DISPLAY_REFRESH_OWNED_POST)
TEST_CASE("Desktop UI refresh intervals use the supported System Informer values")
{
	CHECK(NormalizeDesktopUiRefreshIntervalMs(0u) == 0u);
	CHECK(NormalizeDesktopUiRefreshIntervalMs(500u) == 500u);
	CHECK(NormalizeDesktopUiRefreshIntervalMs(1000u) == 1000u);
	CHECK(NormalizeDesktopUiRefreshIntervalMs(2000u) == 2000u);
	CHECK(NormalizeDesktopUiRefreshIntervalMs(5000u) == 5000u);
	CHECK(NormalizeDesktopUiRefreshIntervalMs(10000u) == 10000u);

	CHECK(NormalizeDesktopUiRefreshIntervalMs(750u) == 2000u);
	CHECK(NormalizeDesktopUiRefreshIntervalMs(60000u) == 2000u);
}

TEST_CASE("Desktop UI refresh intervals throttle non-forced list refreshes")
{
	CHECK_FALSE(ShouldRunPreferenceAlignedDisplayRefresh(false, 10100u, 100u, 0u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(true, 101u, 100u, 0u));
	CHECK_FALSE(ShouldRunPreferenceAlignedDisplayRefresh(false, 599u, 100u, 500u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(false, 600u, 100u, 500u));
	CHECK_FALSE(ShouldRunPreferenceAlignedDisplayRefresh(false, 1099u, 100u, 1000u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(false, 1100u, 100u, 1000u));
	CHECK_FALSE(ShouldRunPreferenceAlignedDisplayRefresh(false, 2099u, 100u, 2000u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(false, 2100u, 100u, 2000u));
	CHECK_FALSE(ShouldRunPreferenceAlignedDisplayRefresh(false, 5099u, 100u, 5000u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(false, 5100u, 100u, 5000u));
	CHECK_FALSE(ShouldRunPreferenceAlignedDisplayRefresh(false, 10099u, 100u, 10000u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(false, 10100u, 100u, 10000u));

	CHECK_FALSE(ShouldRunPreferenceAlignedDisplayRefresh(false, 2099u, 100u, 750u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(false, 2100u, 100u, 750u));
	CHECK(ShouldRunPreferenceAlignedDisplayRefresh(true, 101u, 100u, 10000u));
}

TEST_CASE("Transfer display timer uses the normalized desktop refresh cadence")
{
	CHECK(GetTransferDisplayRefreshTimerDelayMs(0u) == 0u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(500u) == 500u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(1000u) == 1000u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(2000u) == 2000u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(5000u) == 5000u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(10000u) == 10000u);
	CHECK(GetTransferDisplayRefreshTimerDelayMs(750u) == 2000u);
}

TEST_CASE("Transfer display refresh state pauses when the UI should not present updates")
{
	CHECK(ResolveTransferDisplayRefreshState(false, false, true, true, false, true) == TRANSFER_DISPLAY_REFRESH_RUNNING);
	CHECK(ResolveTransferDisplayRefreshState(true, false, true, true, false, true) == TRANSFER_DISPLAY_REFRESH_PAUSED);
	CHECK(ResolveTransferDisplayRefreshState(false, true, true, true, false, true) == TRANSFER_DISPLAY_REFRESH_PAUSED);
	CHECK(ResolveTransferDisplayRefreshState(false, false, false, true, false, true) == TRANSFER_DISPLAY_REFRESH_PAUSED);
	CHECK(ResolveTransferDisplayRefreshState(false, false, true, false, false, true) == TRANSFER_DISPLAY_REFRESH_PAUSED);
	CHECK(ResolveTransferDisplayRefreshState(false, false, true, true, true, true) == TRANSFER_DISPLAY_REFRESH_PAUSED);
	CHECK(ResolveTransferDisplayRefreshState(false, false, true, true, false, false) == TRANSFER_DISPLAY_REFRESH_PAUSED);
}

TEST_CASE("Transfer-rate presentation remains lightweight and visible-window scoped")
{
	CHECK(GetTransferRateDisplayRefreshTimerDelayMs() == 1000u);
	CHECK(ShouldRefreshTransferRatePresentation(false, true));
	CHECK_FALSE(ShouldRefreshTransferRatePresentation(true, true));
	CHECK_FALSE(ShouldRefreshTransferRatePresentation(false, false));
}

TEST_CASE("Transfer display mask keeps hidden-list work pending")
{
	const uint32_t allTransferLists =
		DISPLAY_REFRESH_DOWNLOAD_LIST
		| DISPLAY_REFRESH_UPLOAD_LIST
		| DISPLAY_REFRESH_DOWNLOAD_CLIENTS
		| DISPLAY_REFRESH_QUEUE_LIST
		| DISPLAY_REFRESH_CLIENT_LIST
		| DISPLAY_REFRESH_TRANSFER_SUMMARY;

	CHECK(FilterVisibleTransferDisplayRefreshMask(allTransferLists, TRANSFER_DISPLAY_REFRESH_PAUSED, true, true, true, true, true, true, true) == DISPLAY_REFRESH_NONE);
	CHECK(FilterVisibleTransferDisplayRefreshMask(allTransferLists, TRANSFER_DISPLAY_REFRESH_RUNNING, false, true, true, true, true, true, true) == DISPLAY_REFRESH_NONE);
	CHECK(FilterVisibleTransferDisplayRefreshMask(allTransferLists, TRANSFER_DISPLAY_REFRESH_RUNNING, true, false, true, true, true, true, true) == DISPLAY_REFRESH_NONE);

	const uint32_t onlyDownloadsVisible = FilterVisibleTransferDisplayRefreshMask(
		allTransferLists,
		TRANSFER_DISPLAY_REFRESH_RUNNING,
		true,
		true,
		true,
		false,
		false,
		false,
		false);
	CHECK(onlyDownloadsVisible == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_TRANSFER_SUMMARY));

	const uint32_t secondaryPaneVisible = FilterVisibleTransferDisplayRefreshMask(
		allTransferLists,
		TRANSFER_DISPLAY_REFRESH_RUNNING,
		true,
		true,
		false,
		false,
		true,
		false,
		false);
	CHECK(secondaryPaneVisible == (DISPLAY_REFRESH_DOWNLOAD_CLIENTS | DISPLAY_REFRESH_TRANSFER_SUMMARY));
	CHECK((allTransferLists & ~secondaryPaneVisible) == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_UPLOAD_LIST | DISPLAY_REFRESH_QUEUE_LIST | DISPLAY_REFRESH_CLIENT_LIST));
}

TEST_CASE("Explicit transfer display refresh includes only visible lists while running")
{
	const uint32_t visibleDownloadsAndUploads = BuildExplicitTransferDisplayRefreshMask(
		TRANSFER_DISPLAY_REFRESH_RUNNING,
		true,
		true,
		true,
		true,
		false,
		false,
		false);
	CHECK(visibleDownloadsAndUploads == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_UPLOAD_LIST | DISPLAY_REFRESH_TRANSFER_SUMMARY));

	CHECK(BuildExplicitTransferDisplayRefreshMask(
		TRANSFER_DISPLAY_REFRESH_PAUSED,
		true,
		true,
		true,
		true,
		true,
		true,
		true) == DISPLAY_REFRESH_NONE);
}

TEST_CASE("Producer transfer refresh requests stay on the shared timer cadence")
{
	CHECK(BuildQueuedTransferDisplayRefreshMask(DISPLAY_REFRESH_DOWNLOAD_LIST, false) == DISPLAY_REFRESH_DOWNLOAD_LIST);
	CHECK(BuildQueuedTransferDisplayRefreshMask(DISPLAY_REFRESH_DOWNLOAD_LIST, true) == DISPLAY_REFRESH_DOWNLOAD_LIST);
	CHECK(BuildQueuedTransferDisplayRefreshMask(DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_DOWNLOAD_CLIENTS, true) == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_DOWNLOAD_CLIENTS));
}

TEST_CASE("Forced transfer refreshes flush only when there is visible work")
{
	CHECK_FALSE(ShouldFlushForcedTransferDisplayRefresh(false, DISPLAY_REFRESH_DOWNLOAD_LIST));
	CHECK_FALSE(ShouldFlushForcedTransferDisplayRefresh(true, DISPLAY_REFRESH_NONE));
	CHECK(ShouldFlushForcedTransferDisplayRefresh(true, DISPLAY_REFRESH_DOWNLOAD_LIST));
}

TEST_CASE("Transfer refresh resort policy tracks volatile transfer sort columns")
{
	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOADS, 0));
	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOADS, 1));
	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOADS, 14));
	CHECK(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOADS, 4));
	CHECK(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOADS, 10));

	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_UPLOADS, 0));
	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_UPLOADS, 19));
	CHECK(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_UPLOADS, 2));
	CHECK(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_UPLOADS, 20));

	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOAD_CLIENTS, 2));
	CHECK(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOAD_CLIENTS, 3));

	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_QUEUE, 20));
	CHECK(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_QUEUE, 4));

	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_CLIENTS, 0));
	CHECK(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_CLIENTS, 2));
	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(static_cast<ETransferDisplayListKind>(999), 2));
	CHECK_FALSE(IsTransferRefreshSensitiveSortColumn(TRANSFER_DISPLAY_LIST_DOWNLOADS, -1));
}

TEST_CASE("Display refresh post helper consumes payloads when delivery is unavailable")
{
	std::unique_ptr<CPartFileDisplayUpdateRequest> pRequest(new CPartFileDisplayUpdateRequest{});
	CHECK_FALSE(PostOwnedDisplayRefreshRequest(NULL, WM_APP + 5, pRequest));
	CHECK_FALSE(static_cast<bool>(pRequest));

	std::unique_ptr<CPartFileDisplayUpdateRequest> pEmptyRequest;
	CHECK_FALSE(PostOwnedDisplayRefreshRequest(reinterpret_cast<HWND>(static_cast<INT_PTR>(17)), WM_APP + 6, pEmptyRequest));
	CHECK_FALSE(static_cast<bool>(pEmptyRequest));
}

TEST_CASE("Display refresh mask exchange drains the queued bits and clears the pending state")
{
	std::atomic<LONG> nPendingMask(0);

	AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_UPLOAD_LIST);
	AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_QUEUE_LIST);

	CHECK(nPendingMask.exchange(0) == (DISPLAY_REFRESH_UPLOAD_LIST | DISPLAY_REFRESH_QUEUE_LIST));
	CHECK(nPendingMask.load() == 0);
}

TEST_CASE("Display refresh mask drains selected visible bits without dropping hidden work")
{
	std::atomic<LONG> nPendingMask(0);

	AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_DOWNLOAD_LIST);
	AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_CLIENT_LIST);
	AccumulatePendingDisplayMask(nPendingMask, DISPLAY_REFRESH_QUEUE_LIST);

	CHECK(DrainPendingDisplayMask(nPendingMask, DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_CLIENT_LIST) == (DISPLAY_REFRESH_DOWNLOAD_LIST | DISPLAY_REFRESH_CLIENT_LIST));
	CHECK(nPendingMask.load() == DISPLAY_REFRESH_QUEUE_LIST);
	CHECK(DrainPendingDisplayMask(nPendingMask, DISPLAY_REFRESH_DOWNLOAD_LIST) == 0);
	CHECK(nPendingMask.load() == DISPLAY_REFRESH_QUEUE_LIST);
}
#endif

TEST_CASE("App state helpers preserve the running and closing classifications")
{
	CHECK_FALSE(IsAppStateRunning(APP_STATE_STARTING));
	CHECK_FALSE(IsAppStateClosing(APP_STATE_STARTING));
	CHECK(IsAppStateRunning(APP_STATE_RUNNING));
	CHECK(IsAppStateRunning(APP_STATE_ASKCLOSE));
	CHECK_FALSE(IsAppStateClosing(APP_STATE_ASKCLOSE));
	CHECK(IsAppStateClosing(APP_STATE_SHUTTINGDOWN));
	CHECK(IsAppStateClosing(APP_STATE_DONE));
}

TEST_CASE("App lifecycle helpers expose the REST lifecycle contract")
{
	const SAppLifecycleStatus starting = BuildAppLifecycleStatus(APP_STATE_STARTING, false, false);
	CHECK(std::string(starting.pszState) == "starting");
	CHECK_FALSE(starting.bStartupComplete);
	CHECK_FALSE(starting.bCoreReady);
	CHECK_FALSE(starting.bSharedFilesReady);
	CHECK(starting.bAcceptingRest);
	CHECK_FALSE(starting.bAcceptingMutations);
	CHECK_FALSE(starting.bShutdownInProgress);
	CHECK_FALSE(ShouldRejectRestCommandForLifecycle(starting, false));
	CHECK(ShouldRejectRestCommandForLifecycle(starting, true));

	const SAppLifecycleStatus runningBeforeStartupComplete = BuildAppLifecycleStatus(APP_STATE_RUNNING, false, false);
	CHECK(std::string(runningBeforeStartupComplete.pszState) == "starting");
	CHECK_FALSE(runningBeforeStartupComplete.bStartupComplete);
	CHECK(runningBeforeStartupComplete.bCoreReady);
	CHECK_FALSE(runningBeforeStartupComplete.bSharedFilesReady);
	CHECK(runningBeforeStartupComplete.bAcceptingRest);
	CHECK_FALSE(runningBeforeStartupComplete.bAcceptingMutations);
	CHECK_FALSE(runningBeforeStartupComplete.bShutdownInProgress);
	CHECK_FALSE(ShouldRejectRestCommandForLifecycle(runningBeforeStartupComplete, false));
	CHECK(ShouldRejectRestCommandForLifecycle(runningBeforeStartupComplete, true));

	const SAppLifecycleStatus running = BuildAppLifecycleStatus(APP_STATE_RUNNING, true, true);
	CHECK(std::string(running.pszState) == "running");
	CHECK(running.bStartupComplete);
	CHECK(running.bCoreReady);
	CHECK(running.bSharedFilesReady);
	CHECK(running.bAcceptingRest);
	CHECK(running.bAcceptingMutations);
	CHECK_FALSE(running.bShutdownInProgress);
	CHECK_FALSE(ShouldRejectRestCommandForLifecycle(running, false));
	CHECK_FALSE(ShouldRejectRestCommandForLifecycle(running, true));

	const SAppLifecycleStatus askClose = BuildAppLifecycleStatus(APP_STATE_ASKCLOSE, true, true);
	CHECK(std::string(askClose.pszState) == "running");
	CHECK(askClose.bAcceptingRest);
	CHECK(askClose.bAcceptingMutations);

	const SAppLifecycleStatus shuttingDown = BuildAppLifecycleStatus(APP_STATE_SHUTTINGDOWN, true, true);
	CHECK(std::string(shuttingDown.pszState) == "shuttingdown");
	CHECK_FALSE(shuttingDown.bAcceptingRest);
	CHECK_FALSE(shuttingDown.bAcceptingMutations);
	CHECK(shuttingDown.bShutdownInProgress);
	CHECK(ShouldRejectRestCommandForLifecycle(shuttingDown, false));
	CHECK(ShouldRejectRestCommandForLifecycle(shuttingDown, true));

	const SAppLifecycleStatus done = BuildAppLifecycleStatus(APP_STATE_DONE, true, true);
	CHECK(std::string(done.pszState) == "done");
	CHECK_FALSE(done.bAcceptingRest);
	CHECK(done.bShutdownInProgress);
}

TEST_CASE("Atomic long flag helpers consume one raised request and then reset cleanly")
{
	std::atomic<LONG> nFlag(0);

	CHECK_FALSE(ConsumeAtomicLongFlag(nFlag));

	SetAtomicLongFlag(nFlag, TRUE);
	CHECK(ConsumeAtomicLongFlag(nFlag));
	CHECK_FALSE(ConsumeAtomicLongFlag(nFlag));
}

TEST_CASE("Shared file auto-rescan dirty flag reports dirty after set and clean after clear")
{
	std::atomic<LONG> nDirtyFlag(0);

	CHECK_FALSE(SharedFileListSeams::IsAutoRescanDirtyFlagSet(nDirtyFlag));
	SharedFileListSeams::MarkAutoRescanDirtyFlag(nDirtyFlag);
	CHECK(SharedFileListSeams::IsAutoRescanDirtyFlagSet(nDirtyFlag));
	SharedFileListSeams::ClearAutoRescanDirtyFlag(nDirtyFlag);
	CHECK_FALSE(SharedFileListSeams::IsAutoRescanDirtyFlagSet(nDirtyFlag));
}
