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
