#include "../third_party/doctest/doctest.h"
#include "../include/LongPathTestSupport.h"
#if defined(__has_include)
#if __has_include("SharedDirectoryOps.h")
#include "SharedDirectoryOps.h"
#define EMULEBB_TESTS_HAS_SHARED_DIRECTORY_OPS 1
#endif
#if __has_include("SharedFileIntakePolicy.h")
#include "SharedFileIntakePolicy.h"
#define EMULEBB_TESTS_HAS_SHARED_FILE_INTAKE_POLICY 1
#endif
#if __has_include("SharedStartupCachePolicy.h")
#include "SharedStartupCachePolicy.h"
#define EMULEBB_TESTS_HAS_SHARED_STARTUP_CACHE_POLICY 1
#endif
#if __has_include("LongPathSeams.h")
#include "LongPathSeams.h"
#define EMULEBB_TESTS_HAS_LONG_PATH_SEAMS 1
#endif
#if __has_include("SharedFilesWndSeams.h")
#include "SharedFilesWndSeams.h"
#define EMULEBB_TESTS_HAS_SHARED_FILES_WND_SEAMS 1
#endif
#if __has_include("SharedFilesCtrlSeams.h")
#include "SharedFilesCtrlSeams.h"
#define EMULEBB_TESTS_HAS_SHARED_FILES_CTRL_SEAMS 1
#endif
#if __has_include("SharedDirectoryMonitorSeams.h")
#include "SharedDirectoryMonitorSeams.h"
#ifndef EMULEBB_TESTS_HAS_SHARED_DIRECTORY_MONITOR_SEAMS
#define EMULEBB_TESTS_HAS_SHARED_DIRECTORY_MONITOR_SEAMS 1
#endif
#endif
#endif
#include "SharedFileListSeams.h"

TEST_SUITE_BEGIN("parity");

#ifdef EMULEBB_TESTS_HAS_SHARED_DIRECTORY_OPS
bool EqualPaths(const CString &rstrDir1, const CString &rstrDir2)
{
	return PathHelpers::ArePathsEquivalent(rstrDir1, rstrDir2);
}
#endif

namespace
{
#ifdef EMULEBB_TESTS_HAS_SHARED_DIRECTORY_OPS
int CountEquivalentPaths(const CStringList &rList, const CString &rstrPath)
{
	int nMatches = 0;
	for (POSITION pos = rList.GetHeadPosition(); pos != NULL;) {
		if (EqualPaths(rList.GetNext(pos), rstrPath))
			++nMatches;
	}
	return nMatches;
}

int CountPaths(const CStringList &rList)
{
	int nCount = 0;
	for (POSITION pos = rList.GetHeadPosition(); pos != NULL;)
		(void)rList.GetNext(pos), ++nCount;
	return nCount;
}
#endif
}

TEST_CASE("Shared file list accepts files from shared directories")
{
	CHECK(SharedFileListSeams::CanAddSharedFile(false, true, false));
}

TEST_CASE("Shared file list accepts explicitly single-shared files outside shared directories")
{
	CHECK(SharedFileListSeams::CanAddSharedFile(false, false, true));
}

TEST_CASE("Shared file list accepts part files outside shared directories")
{
	CHECK(SharedFileListSeams::CanAddSharedFile(true, false, false));
}

#ifdef EMULEBB_TESTS_HAS_SHARED_FILE_LIST_PUBLISH_BATCH_SEAMS
TEST_CASE("Shared file list batches eD2K publish UI refreshes only for multiple changed rows")
{
	CHECK_FALSE(SharedFileListSeams::ShouldBatchPublishedED2KUiRefresh(0u));
	CHECK_FALSE(SharedFileListSeams::ShouldBatchPublishedED2KUiRefresh(1u));
	CHECK(SharedFileListSeams::ShouldBatchPublishedED2KUiRefresh(2u));
	CHECK(SharedFileListSeams::ShouldBatchPublishedED2KUiRefresh(200u));
}
#endif

#ifdef EMULEBB_TESTS_HAS_SHARED_FILE_LIST_ASYNC_HASH_SEAMS
TEST_CASE("Shared file hash worker allows only a bounded UI completion backlog")
{
	CHECK(SharedFileListSeams::ShouldStartSharedHashJob({ true, true, 0u }));
	CHECK(SharedFileListSeams::ShouldStartSharedHashJob({
		true,
		true,
		SharedFileListSeams::kSharedHashPendingCompletionBacklogMax - 1u
	}));
	CHECK_FALSE(SharedFileListSeams::ShouldStartSharedHashJob({
		true,
		true,
		SharedFileListSeams::kSharedHashPendingCompletionBacklogMax
	}));
	CHECK_FALSE(SharedFileListSeams::ShouldStartSharedHashJob({ false, true, 0u }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartSharedHashJob({ true, false, 0u }));
}

TEST_CASE("Shared hash shutdown wait stays bounded by the configured budget")
{
	CHECK(SharedFileListSeams::ShouldKeepWaitingForSharedHashWorkerShutdown({ 0ui64, 5000ui64 }));
	CHECK(SharedFileListSeams::ShouldKeepWaitingForSharedHashWorkerShutdown({ 4999ui64, 5000ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldKeepWaitingForSharedHashWorkerShutdown({ 5000ui64, 5000ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldKeepWaitingForSharedHashWorkerShutdown({ 7500ui64, 5000ui64 }));
}

TEST_CASE("Startup-cache save shutdown wait stays bounded by the configured budget")
{
	CHECK(SharedFileListSeams::ShouldKeepWaitingForStartupCacheSaveShutdown({ 0ui64, 5000ui64 }));
	CHECK(SharedFileListSeams::ShouldKeepWaitingForStartupCacheSaveShutdown({ 4999ui64, 5000ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldKeepWaitingForStartupCacheSaveShutdown({ 5000ui64, 5000ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldKeepWaitingForStartupCacheSaveShutdown({ 7500ui64, 5000ui64 }));
}

TEST_CASE("Shared-file shutdown polling uses one bounded sleep policy")
{
	CHECK_EQ(SharedFileListSeams::kSharedHashShutdownWaitMs, 5000u);
	CHECK_EQ(SharedFileListSeams::kStartupCacheSaveShutdownWaitMs, 5000u);
	CHECK_EQ(SharedFileListSeams::kSharedShutdownPollIntervalMs, 15u);

	CHECK(SharedFileListSeams::ShouldKeepWaitingForSharedShutdownPoll({ 0ui64, 5000ui64, 15u }));
	CHECK(SharedFileListSeams::ShouldKeepWaitingForSharedShutdownPoll({ 4999ui64, 5000ui64, 15u }));
	CHECK_FALSE(SharedFileListSeams::ShouldKeepWaitingForSharedShutdownPoll({ 5000ui64, 5000ui64, 15u }));

	CHECK_EQ(SharedFileListSeams::GetSharedShutdownPollSleepMs({ 0ui64, 5000ui64, 15u }), 15u);
	CHECK_EQ(SharedFileListSeams::GetSharedShutdownPollSleepMs({ 4990ui64, 5000ui64, 15u }), 10u);
	CHECK_EQ(SharedFileListSeams::GetSharedShutdownPollSleepMs({ 5000ui64, 5000ui64, 15u }), 0u);
	CHECK_EQ(SharedFileListSeams::GetSharedShutdownPollSleepMs({ 100ui64, 5000ui64, 0u }), 0u);
}

TEST_CASE("Shared hash UI drain post retries do not sleep after the final attempt")
{
	CHECK_EQ(SharedFileListSeams::kSharedHashCompletionPostRetries, 20u);
	CHECK_EQ(SharedFileListSeams::kSharedHashCompletionPostRetryDelayMs, 25u);

	CHECK(SharedFileListSeams::ShouldRetrySharedHashDrainPost(0u, SharedFileListSeams::kSharedHashCompletionPostRetries));
	CHECK(SharedFileListSeams::ShouldRetrySharedHashDrainPost(18u, SharedFileListSeams::kSharedHashCompletionPostRetries));
	CHECK_FALSE(SharedFileListSeams::ShouldRetrySharedHashDrainPost(19u, SharedFileListSeams::kSharedHashCompletionPostRetries));
	CHECK_FALSE(SharedFileListSeams::ShouldRetrySharedHashDrainPost(0u, 1u));
}

TEST_CASE("Shutdown skips shared startup-cache persistence after interrupted hashing")
{
	CHECK(SharedFileListSeams::ShouldPersistStartupCacheOnShutdown(false));
	CHECK_FALSE(SharedFileListSeams::ShouldPersistStartupCacheOnShutdown(true));
}

TEST_CASE("Startup-cache save scheduling waits until deferred hashing has drained")
{
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSave({ true, false, false, true, 14999ui64, 0ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSave({ true, false, false, true, 15000ui64, 0ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSave({ true, false, false, true, 60000ui64, 0ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSave({ true, false, false, false, 14999ui64, 0ui64 }));
	CHECK(SharedFileListSeams::ShouldStartStartupCacheSave({ true, false, false, false, 15000ui64, 0ui64 }));
}

TEST_CASE("Startup-cache save starts immediately after startup hashing drains")
{
	CHECK(SharedFileListSeams::ShouldStartStartupCacheSaveAfterHashDrain({ true, false, false, false }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSaveAfterHashDrain({ false, false, false, false }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSaveAfterHashDrain({ true, true, false, false }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSaveAfterHashDrain({ true, false, true, false }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSaveAfterHashDrain({ true, false, false, true }));
}

TEST_CASE("Startup-cache save scheduling stays blocked while closing, clean, or already saving")
{
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSave({ false, false, false, false, 20000ui64, 0ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSave({ true, true, false, false, 20000ui64, 0ui64 }));
	CHECK_FALSE(SharedFileListSeams::ShouldStartStartupCacheSave({ true, false, true, false, 20000ui64, 0ui64 }));
}

TEST_CASE("Startup-cache save post failures retry unless shutdown already abandoned the result")
{
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSavePostFailureAction({ false, false }),
		SharedFileListSeams::StartupCacheSavePostFailureAction::RetryLater);
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSavePostFailureAction({ true, false }),
		SharedFileListSeams::StartupCacheSavePostFailureAction::DiscardPersistedResultAndClearDirty);
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSavePostFailureAction({ false, true }),
		SharedFileListSeams::StartupCacheSavePostFailureAction::DiscardPersistedResultAndClearDirty);
}

TEST_CASE("Startup-cache save completion clears dirty state only after a full successful apply")
{
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSaveCompletionAction({ true, false, true, true, false }),
		SharedFileListSeams::StartupCacheSaveCompletionAction::DiscardPersistedResultAndClearDirty);
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSaveCompletionAction({ false, true, true, true, false }),
		SharedFileListSeams::StartupCacheSaveCompletionAction::DiscardPersistedResultAndClearDirty);
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSaveCompletionAction({ false, false, true, true, false }),
		SharedFileListSeams::StartupCacheSaveCompletionAction::ApplyResultAndClearDirty);
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSaveCompletionAction({ false, false, true, false, false }),
		SharedFileListSeams::StartupCacheSaveCompletionAction::ApplyResultAndRemainDirty);
	CHECK_EQ(
		SharedFileListSeams::GetStartupCacheSaveCompletionAction({ false, false, true, true, true }),
		SharedFileListSeams::StartupCacheSaveCompletionAction::ApplyResultAndRemainDirty);
}

TEST_CASE("Shared hash completion delivery keeps results for UI retry unless shutdown owns the object")
{
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashCompletionDeliveryAction({ false, false, true }),
		SharedFileListSeams::SharedHashCompletionDeliveryAction::PostDirect);
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashCompletionDeliveryAction({ false, false, false }),
		SharedFileListSeams::SharedHashCompletionDeliveryAction::QueueForUiRetry);
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashCompletionDeliveryAction({ true, false, false }),
		SharedFileListSeams::SharedHashCompletionDeliveryAction::DropResult);
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashCompletionDeliveryAction({ false, true, false }),
		SharedFileListSeams::SharedHashCompletionDeliveryAction::DropResult);
}

TEST_CASE("Shared hash drain continuation cannot strand deferred results after post failure")
{
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashDrainContinuationAction({ false, false, false, false }),
		SharedFileListSeams::SharedHashDrainContinuationAction::Complete);
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashDrainContinuationAction({ true, false, false, true }),
		SharedFileListSeams::SharedHashDrainContinuationAction::WaitForPostedDrain);
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashDrainContinuationAction({ true, false, false, false }),
		SharedFileListSeams::SharedHashDrainContinuationAction::DrainInlineFallback);
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashDrainContinuationAction({ true, true, false, false }),
		SharedFileListSeams::SharedHashDrainContinuationAction::Complete);
	CHECK_EQ(
		SharedFileListSeams::GetSharedHashDrainContinuationAction({ true, false, true, false }),
		SharedFileListSeams::SharedHashDrainContinuationAction::Complete);
}

TEST_CASE("Part-file hash worker drops results during shutdown or missing UI")
{
	CHECK_EQ(
		SharedFileListSeams::GetPartFileHashWorkerPostAction({ false, true }),
		SharedFileListSeams::PartFileHashWorkerPostAction::PostToUi);
	CHECK_EQ(
		SharedFileListSeams::GetPartFileHashWorkerPostAction({ true, true }),
		SharedFileListSeams::PartFileHashWorkerPostAction::DropResult);
	CHECK_EQ(
		SharedFileListSeams::GetPartFileHashWorkerPostAction({ false, false }),
		SharedFileListSeams::PartFileHashWorkerPostAction::DropResult);
	CHECK(SharedFileListSeams::CanPartFileHashWorkerTouchPartFile(false, true));
	CHECK_FALSE(SharedFileListSeams::CanPartFileHashWorkerTouchPartFile(true, true));
	CHECK_FALSE(SharedFileListSeams::CanPartFileHashWorkerTouchPartFile(false, false));
}

TEST_CASE("Shared hash shutdown invalidates warm caches only when hashing work was interrupted")
{
	CHECK_FALSE(SharedFileListSeams::ShouldInvalidateStartupCacheAfterSharedHashShutdown({ false, false, false }));
	CHECK(SharedFileListSeams::ShouldInvalidateStartupCacheAfterSharedHashShutdown({ true, false, false }));
	CHECK(SharedFileListSeams::ShouldInvalidateStartupCacheAfterSharedHashShutdown({ false, true, false }));
	CHECK(SharedFileListSeams::ShouldInvalidateStartupCacheAfterSharedHashShutdown({ false, false, true }));
}
#endif

#ifdef EMULEBB_TESTS_HAS_SHARED_FILES_CTRL_SEAMS
TEST_CASE("Shared files moved-index range covers only rotated rows")
{
	SharedFilesCtrlSeams::VisibleIndexRange range = SharedFilesCtrlSeams::GetMovedVisibleIndexRange(10, 40, 100);
	CHECK(range.bValid);
	CHECK_EQ(range.iFirst, 10);
	CHECK_EQ(range.iLast, 40);

	range = SharedFilesCtrlSeams::GetMovedVisibleIndexRange(40, 10, 100);
	CHECK(range.bValid);
	CHECK_EQ(range.iFirst, 10);
	CHECK_EQ(range.iLast, 40);
}

TEST_CASE("Shared files moved-index range rejects no-op and out-of-bounds moves")
{
	CHECK_FALSE(SharedFilesCtrlSeams::GetMovedVisibleIndexRange(-1, 2, 10).bValid);
	CHECK_FALSE(SharedFilesCtrlSeams::GetMovedVisibleIndexRange(2, -1, 10).bValid);
	CHECK_FALSE(SharedFilesCtrlSeams::GetMovedVisibleIndexRange(2, 10, 10).bValid);
	CHECK_FALSE(SharedFilesCtrlSeams::GetMovedVisibleIndexRange(2, 2, 10).bValid);
	CHECK_FALSE(SharedFilesCtrlSeams::GetMovedVisibleIndexRange(0, 0, 0).bValid);
}
#endif

#ifdef EMULEBB_TESTS_HAS_SHARED_FILES_WND_SEAMS
TEST_CASE("Shared files splitter range scales with dialog width instead of capping at the legacy maximum")
{
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(50, 900), SharedFilesWndSeams::kMinTreeWidth);
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(999, 900), SharedFilesWndSeams::GetSplitterRangeMax(900));
	CHECK(SharedFilesWndSeams::GetSplitterRangeMax(900) > 350);
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(500, 900), 500);
}

TEST_CASE("Shared files splitter keeps a usable right pane in narrow windows")
{
	CHECK_EQ(SharedFilesWndSeams::GetSplitterRangeMax(180), SharedFilesWndSeams::kMinTreeWidth);
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(999, 180), SharedFilesWndSeams::kMinTreeWidth);
}

TEST_CASE("Shared files reload defers only while shared hashing is active")
{
	CHECK(SharedFilesWndSeams::ShouldDeferReloadForSharedHashing(true));
	CHECK_FALSE(SharedFilesWndSeams::ShouldDeferReloadForSharedHashing(false));
}

TEST_CASE("Shared files startup-deferred list reload waits for hash drain")
{
	CHECK_FALSE(SharedFilesWndSeams::ShouldRunStartupDeferredListReload(false, false));
	CHECK_FALSE(SharedFilesWndSeams::ShouldRunStartupDeferredListReload(false, true));
	CHECK_FALSE(SharedFilesWndSeams::ShouldRunStartupDeferredListReload(true, true));
	CHECK(SharedFilesWndSeams::ShouldRunStartupDeferredListReload(true, false));
}

TEST_CASE("Shared files deferred reload coalesces shared-only work and lets full tree reload win")
{
	SharedFilesWndSeams::ReloadDeferralState state = {};
	CHECK_FALSE(SharedFilesWndSeams::HasDeferredReload(state));

	state = SharedFilesWndSeams::AddDeferredReloadRequest(state, false);
	CHECK_FALSE(state.bFullTreeReload);
	CHECK(state.bSharedFilesReload);
	CHECK(SharedFilesWndSeams::HasDeferredReload(state));

	state = SharedFilesWndSeams::AddDeferredReloadRequest(state, true);
	CHECK(state.bFullTreeReload);
	CHECK_FALSE(state.bSharedFilesReload);

	state = SharedFilesWndSeams::AddDeferredReloadRequest(state, false);
	CHECK(state.bFullTreeReload);
	CHECK_FALSE(state.bSharedFilesReload);
}
#endif

#ifdef EMULEBB_TESTS_HAS_SHARED_DIRECTORY_MONITOR_SEAMS
TEST_CASE("Shared-directory monitor falls back to full reconciliation without a trusted journal")
{
	using SharedDirectoryMonitorSeams::EMonitoredRootCatchupMode;

	CHECK(SharedDirectoryMonitorSeams::GetStartupCatchupMode(false, false, false) == EMonitoredRootCatchupMode::None);
	CHECK(SharedDirectoryMonitorSeams::GetStartupCatchupMode(true, false, false) == EMonitoredRootCatchupMode::FullReconcile);
	CHECK(SharedDirectoryMonitorSeams::GetStartupCatchupMode(true, true, false) == EMonitoredRootCatchupMode::FullReconcile);
	CHECK(SharedDirectoryMonitorSeams::GetStartupCatchupMode(true, true, true) == EMonitoredRootCatchupMode::JournalDelta);
}

TEST_CASE("Shared-directory monitor persists only trusted NTFS journal checkpoints")
{
	CHECK(SharedDirectoryMonitorSeams::ShouldPersistJournalState(true, 10u, 20));
	CHECK_FALSE(SharedDirectoryMonitorSeams::ShouldPersistJournalState(false, 10u, 20));
	CHECK_FALSE(SharedDirectoryMonitorSeams::ShouldPersistJournalState(true, 0u, 20));
	CHECK_FALSE(SharedDirectoryMonitorSeams::ShouldPersistJournalState(true, 10u, 0));
}
#endif

#ifdef EMULEBB_TESTS_HAS_SHARED_DIRECTORY_OPS
TEST_CASE("Shared directory recursion dedupes non-recursive junction aliases by filesystem identity")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10001u));

	const std::wstring targetPath = fixture.MakeDirectoryChildPath(L"real-target");
	const std::wstring aliasPath = fixture.MakeDirectoryChildPath(L"alias-target");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(targetPath));
	if (!LongPathTestSupport::CreateDirectoryJunction(aliasPath, targetPath))
		return;

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(targetPath.c_str()), false, [](const CString &) { return true; }));
	CHECK_FALSE(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(aliasPath.c_str()), false, [](const CString &) { return true; }));
	CHECK_EQ(CountPaths(sharedDirectories), 1);
	CHECK(CountEquivalentPaths(sharedDirectories, CString(targetPath.c_str())) + CountEquivalentPaths(sharedDirectories, CString(aliasPath.c_str())) == 1);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(aliasPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(targetPath));
}

TEST_CASE("Shared directory object lookup recognizes junction aliases already in a canonical list")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10007u));

	const std::wstring targetPath = fixture.MakeDirectoryChildPath(L"real-target");
	const std::wstring aliasPath = fixture.MakeDirectoryChildPath(L"alias-target");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(targetPath));
	if (!LongPathTestSupport::CreateDirectoryJunction(aliasPath, targetPath))
		return;

	CStringList sharedDirectories;
	sharedDirectories.AddTail(CString(targetPath.c_str()));
	CHECK(SharedDirectoryOps::ListContainsEquivalentDirectoryObject(sharedDirectories, CString(aliasPath.c_str())));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(aliasPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(targetPath));
}

TEST_CASE("Shared directory recursion keeps only one child path when a junction aliases the same target")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10002u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring targetPath = fixture.MakeDirectoryChildPath(L"real-child");
	const std::wstring aliasPath = fixture.MakeDirectoryChildPath(L"alias-child");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(targetPath));
	if (!LongPathTestSupport::CreateDirectoryJunction(aliasPath, targetPath))
		return;

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(rootPath.c_str()), true, [](const CString &) { return true; }));
	CHECK_EQ(CountPaths(sharedDirectories), 2);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(rootPath.c_str())), 1);
	CHECK(CountEquivalentPaths(sharedDirectories, CString(targetPath.c_str())) + CountEquivalentPaths(sharedDirectories, CString(aliasPath.c_str())) == 1);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(aliasPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(targetPath));
}

TEST_CASE("Shared directory recursion stops junction loops by filesystem identity")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10003u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring childPath = fixture.MakeDirectoryChildPath(L"loop-child");
	const std::wstring loopPath = childPath + L"\\back-to-root";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(childPath));
	if (!LongPathTestSupport::CreateDirectoryJunction(loopPath, rootPath))
		return;

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(rootPath.c_str()), true, [](const CString &) { return true; }));
	CHECK_EQ(CountPaths(sharedDirectories), 2);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(rootPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(childPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(loopPath.c_str())), 0);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(loopPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(childPath));
}

TEST_CASE("Monitored shared roots promote mounted-folder volume boundaries to independent roots")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10005u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring plainChildPath = fixture.MakeDirectoryChildPath(L"plain-child");
	const std::wstring mountedChildPath = fixture.MakeDirectoryChildPath(L"mounted-child");
	const std::wstring mountedGrandchildPath = mountedChildPath + L"\\grandchild";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(plainChildPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(mountedChildPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(mountedGrandchildPath));

	const CString strMountedChildKey(SharedDirectoryOps::MakeSharedDirectoryLookupKey(CString(mountedChildPath.c_str())));
	const auto resolveVolumeKey = [strMountedChildKey](const CString &rstrDirectory, CString &rstrVolumeKey) -> bool {
		const CString strDirectoryKey(SharedDirectoryOps::MakeSharedDirectoryLookupKey(rstrDirectory));
		rstrVolumeKey = strDirectoryKey.Left(strMountedChildKey.GetLength()).CompareNoCase(strMountedChildKey) == 0
			? CString(_T("\\\\?\\Volume{mounted-child}\\"))
			: CString(_T("\\\\?\\Volume{parent}\\"));
		return true;
	};

	CStringList monitoredRoots;
	CStringList monitorOwnedDirs;
	SharedDirectoryOps::AddMonitoredSharedRoot(
		monitoredRoots,
		monitorOwnedDirs,
		CString(rootPath.c_str()),
		[](const CString &) { return true; },
		resolveVolumeKey);

	CHECK_EQ(CountEquivalentPaths(monitoredRoots, CString(rootPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(monitoredRoots, CString(mountedChildPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(monitoredRoots, CString(plainChildPath.c_str())), 0);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, CString(plainChildPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, CString(mountedChildPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, CString(mountedGrandchildPath.c_str())), 1);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(mountedGrandchildPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(mountedChildPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(plainChildPath));
}

TEST_CASE("Monitored shared roots keep same-volume recursive trees under one root")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10006u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring childPath = fixture.MakeDirectoryChildPath(L"same-volume-child");
	const std::wstring grandchildPath = childPath + L"\\grandchild";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(childPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(grandchildPath));

	const auto resolveVolumeKey = [](const CString &, CString &rstrVolumeKey) -> bool {
		rstrVolumeKey = _T("\\\\?\\Volume{same}\\");
		return true;
	};

	CStringList monitoredRoots;
	CStringList monitorOwnedDirs;
	SharedDirectoryOps::AddMonitoredSharedRoot(
		monitoredRoots,
		monitorOwnedDirs,
		CString(rootPath.c_str()),
		[](const CString &) { return true; },
		resolveVolumeKey);

	CHECK_EQ(CountPaths(monitoredRoots), 1);
	CHECK_EQ(CountEquivalentPaths(monitoredRoots, CString(rootPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, CString(childPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, CString(grandchildPath.c_str())), 1);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(grandchildPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(childPath));
}

TEST_CASE("Monitor-owned cleanup preserves retained promoted roots when an ancestor downgrades")
{
	CStringList monitorOwnedDirs;
	monitorOwnedDirs.AddTail(_T("C:\\shared\\mounted\\"));
	monitorOwnedDirs.AddTail(_T("C:\\shared\\mounted\\child\\"));
	monitorOwnedDirs.AddTail(_T("C:\\shared\\plain\\"));

	CStringList downgradedRoots;
	downgradedRoots.AddTail(_T("C:\\shared\\"));

	CStringList retainedMonitoredRoots;
	retainedMonitoredRoots.AddTail(_T("C:\\shared\\mounted\\"));

	CHECK(SharedDirectoryOps::RemoveMonitorOwnedDirectoriesForDowngradedRoots(monitorOwnedDirs, downgradedRoots, retainedMonitoredRoots));
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, _T("C:\\shared\\mounted\\")), 1);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, _T("C:\\shared\\mounted\\child\\")), 1);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, _T("C:\\shared\\plain\\")), 0);
}

TEST_CASE("Monitor-owned cleanup removes promoted-root subtree when that root downgrades")
{
	CStringList monitorOwnedDirs;
	monitorOwnedDirs.AddTail(_T("C:\\shared\\mounted\\"));
	monitorOwnedDirs.AddTail(_T("C:\\shared\\mounted\\child\\"));
	monitorOwnedDirs.AddTail(_T("C:\\shared\\plain\\"));

	CStringList downgradedRoots;
	downgradedRoots.AddTail(_T("C:\\shared\\mounted\\"));

	CStringList retainedMonitoredRoots;
	retainedMonitoredRoots.AddTail(_T("C:\\shared\\"));

	CHECK(SharedDirectoryOps::RemoveMonitorOwnedDirectoriesForDowngradedRoots(monitorOwnedDirs, downgradedRoots, retainedMonitoredRoots));
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, _T("C:\\shared\\mounted\\")), 0);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, _T("C:\\shared\\mounted\\child\\")), 0);
	CHECK_EQ(CountEquivalentPaths(monitorOwnedDirs, _T("C:\\shared\\plain\\")), 1);
}

TEST_CASE("Shared directory lookup key vector supports repeated monitored-root containment checks")
{
	CStringList monitoredRoots;
	monitoredRoots.AddTail(_T("C:\\shared\\"));
	monitoredRoots.AddTail(_T("D:\\media\\mounted\\"));

	std::vector<CString> rootKeys;
	SharedDirectoryOps::BuildSharedDirectoryLookupKeyVector(monitoredRoots, rootKeys);

	CHECK_EQ(rootKeys.size(), static_cast<size_t>(2u));
	CHECK(SharedDirectoryOps::ContainsSharedDirectoryLookupKey(rootKeys, SharedDirectoryOps::MakeSharedDirectoryLookupKey(_T("C:\\shared\\"))));
	CHECK_FALSE(SharedDirectoryOps::ContainsSharedDirectoryLookupKey(rootKeys, SharedDirectoryOps::MakeSharedDirectoryLookupKey(_T("C:\\shared\\nested\\"))));
	CHECK(SharedDirectoryOps::IsDirectoryKeySameOrDescendantOfAny(rootKeys, SharedDirectoryOps::MakeSharedDirectoryLookupKey(_T("C:\\shared\\"))));
	CHECK(SharedDirectoryOps::IsDirectoryKeySameOrDescendantOfAny(rootKeys, SharedDirectoryOps::MakeSharedDirectoryLookupKey(_T("C:\\shared\\nested\\"))));
	CHECK(SharedDirectoryOps::IsDirectoryKeySameOrDescendantOfAny(rootKeys, SharedDirectoryOps::MakeSharedDirectoryLookupKey(_T("D:\\media\\mounted\\child\\"))));
	CHECK_FALSE(SharedDirectoryOps::IsDirectoryKeySameOrDescendantOfAny(rootKeys, SharedDirectoryOps::MakeSharedDirectoryLookupKey(_T("C:\\shared-sibling\\"))));
	CHECK_FALSE(SharedDirectoryOps::IsDirectoryKeySameOrDescendantOfAny(rootKeys, SharedDirectoryOps::MakeSharedDirectoryLookupKey(_T("D:\\media\\"))));
}

#if defined(EMULEBB_TESTS_HAS_SHARED_DIRECTORY_OPS) && defined(EMULEBB_TESTS_HAS_SHARED_FILE_INTAKE_POLICY)
TEST_CASE("Shared directory recursion skips built-in and configured ignored directory names")
{
	SharedFileIntakePolicy::ScopedUserRuleOverride restoreRules;
	SharedFileIntakePolicy::ClearUserRules();

	SharedFileIntakePolicy::IgnoreRule rule = {};
	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("skip-me"), rule));
	std::vector<SharedFileIntakePolicy::IgnoreRule> userRules;
	userRules.push_back(rule);
	SharedFileIntakePolicy::ReplaceUserRules(userRules);

	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10004u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring keepPath = fixture.MakeDirectoryChildPath(L"keep-me");
	const std::wstring vcsPath = fixture.MakeDirectoryChildPath(L".git");
	const std::wstring configuredPath = fixture.MakeDirectoryChildPath(L"skip-me");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(keepPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(vcsPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(configuredPath));

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(rootPath.c_str()), true, [](const CString &) { return true; }));
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(rootPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(keepPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(vcsPath.c_str())), 0);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(configuredPath.c_str())), 0);
	CHECK(CountPaths(sharedDirectories) >= 2);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(configuredPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(vcsPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(keepPath));
}
#endif
#endif

#ifdef EMULEBB_TESTS_HAS_SHARED_FILE_LIST_PATH_SEAMS
TEST_CASE("Shared file list matches explicit shared files across prefixed and DOS 8.3 spellings")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 301u, 0x515151u));

	const CString strLongPath(fixture.FilePath().c_str());
	const CString strPrefixedPath(LongPathTestSupport::PreparePathForLongPath(fixture.FilePath()).c_str());
	CHECK(SharedFileListSeams::MatchesExplicitSharedFilePath(strLongPath, strPrefixedPath));

	std::wstring shortAlias;
	if (!LongPathTestSupport::TryGetShortPathAlias(fixture.FilePath(), shortAlias))
		return;

	CHECK(SharedFileListSeams::MatchesExplicitSharedFilePath(strLongPath, CString(shortAlias.c_str())));
}

TEST_CASE("Shared file list contains child files across canonicalized directory spellings")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 302u, 0x616161u));

	const CString strDirectory(PathHelpers::EnsureTrailingSeparator(CString(fixture.DirectoryPath().c_str())));
	const CString strFilePath(fixture.FilePath().c_str());
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strDirectory, strFilePath));

	std::wstring shortAlias;
	if (!LongPathTestSupport::TryGetShortPathAlias(fixture.DirectoryPath(), shortAlias))
		return;

	const CString strShortDirectory(PathHelpers::EnsureTrailingSeparator(CString(shortAlias.c_str())));
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strShortDirectory, strFilePath));
}

TEST_CASE("Shared file list preserves exact trailing dot and trailing space names across canonical path spellings")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x717273u));

	const std::wstring directoryPath = fixture.DirectoryPath() + L"\\shared-dir. ";
	const std::wstring filePath = directoryPath + L"\\shared-file ";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(directoryPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(filePath, LongPathTestSupport::BuildDeterministicPayload(211u, 0x818283u)));

	const CString strDirectory(PathHelpers::EnsureTrailingSeparator(CString(directoryPath.c_str())));
	const CString strFilePath(CString(filePath.c_str()));
	const CString strPrefixedDirectory(PathHelpers::EnsureTrailingSeparator(CString(LongPathTestSupport::PreparePathForLongPath(directoryPath).c_str())));
	const CString strPrefixedFile(CString(LongPathTestSupport::PreparePathForLongPath(filePath).c_str()));

	CHECK(SharedFileListSeams::ContainsSharedChildPath(strDirectory, strFilePath));
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strPrefixedDirectory, strFilePath));
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strDirectory, strPrefixedFile));
	CHECK(SharedFileListSeams::MatchesExplicitSharedFilePath(strFilePath, strPrefixedFile));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(filePath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(directoryPath));
}
#endif

TEST_CASE("Shared file list rejects complete files that are neither directory-shared nor explicitly shared")
{
	CHECK_FALSE(SharedFileListSeams::CanAddSharedFile(false, false, false));
}

TEST_CASE("Shared file auto-reload schedules only when the stable snapshot allows it")
{
	const SharedFileListSeams::AutoReloadScheduleState state = {
		true,
		false,
		false,
		true,
		false,
		true
	};

	CHECK(SharedFileListSeams::ShouldScheduleAutoReload(state));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ false, false, false, true, false, true }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, true, false, true, false, true }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, true, true, false, true }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, false, false, true, true }));
}

TEST_CASE("Shared file auto-reload accepts fallback polling as a valid dirty-work trigger")
{
	CHECK(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, false, true, true, false }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, false, true, false, false }));
}

TEST_CASE("Shared file import yield only applies to active full-part imports")
{
	CHECK(SharedFileListSeams::ShouldYieldAfterImportProgress(true, true, true));
	CHECK_FALSE(SharedFileListSeams::ShouldYieldAfterImportProgress(false, true, true));
	CHECK_FALSE(SharedFileListSeams::ShouldYieldAfterImportProgress(true, false, true));
	CHECK_FALSE(SharedFileListSeams::ShouldYieldAfterImportProgress(true, true, false));
	CHECK(SharedFileListSeams::kImportPartProgressYieldMs == 100);
}

#ifdef EMULEBB_TESTS_HAS_SHARED_STARTUP_CACHE_POLICY
TEST_CASE("Shared startup cache policy rejects malformed blocks and lookup misses wholesale")
{
	CHECK(SharedStartupCachePolicy::ShouldRejectWholeCacheOnMalformedBlock());
	CHECK(SharedStartupCachePolicy::ShouldRescanDirectoryOnCachedLookupMiss());
}

TEST_CASE("Shared startup cache only persists stable directories without pending hashes")
{
	CHECK(SharedStartupCachePolicy::CanPersistDirectorySnapshot(false));
	CHECK_FALSE(SharedStartupCachePolicy::CanPersistDirectorySnapshot(true));
}

TEST_CASE("Shared startup cache verification requires structural validity and matching directory state")
{
	SharedStartupCachePolicy::DirectoryRecord record = {};
	record.strDirectoryPath = CString(L"C:\\share\\");
	record.bHasIdentity = true;
	record.utcDirectoryDate = 1234;
	record.uCachedFileCount = 1;
	record.files.push_back({ CString(L"file.bin"), 55, 66u });

	CHECK(SharedStartupCachePolicy::IsStructurallyValid(record));
	CHECK(SharedStartupCachePolicy::MatchesVerifiedDirectoryState(record, true, true, 1234));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesVerifiedDirectoryState(record, false, true, 1234));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesVerifiedDirectoryState(record, true, false, 1234));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesVerifiedDirectoryState(record, true, true, 9999));

	record.uCachedFileCount = 2;
	CHECK_FALSE(SharedStartupCachePolicy::IsStructurallyValid(record));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesVerifiedDirectoryState(record, true, true, 1234));
}

#ifdef EMULEBB_SHARED_STARTUP_CACHE_POLICY_HAS_NTFS_FAST_PATH
TEST_CASE("Shared startup cache trusted NTFS mode requires a volume guard and directory reference")
{
	SharedStartupCachePolicy::DirectoryRecord record = {};
	record.strDirectoryPath = CString(L"C:\\share\\");
	record.eValidationMode = SharedStartupCachePolicy::ValidationMode::LocalNtfsJournalFastPath;
	record.volumeRecord.strVolumeKey = CString(L"\\\\?\\volume{test}\\");
	record.volumeRecord.ullVolumeSerialNumber = 77u;
	record.volumeRecord.ullUsnJournalId = 88u;
	record.volumeRecord.llJournalCheckpointUsn = 99;
	record.directoryFileReference = LongPathSeams::MakeUsnFileReferenceFromUInt64(123u);
	record.uCachedFileCount = 1;
	record.files.push_back({ CString(L"file.bin"), 55, 66u });

	CHECK(SharedStartupCachePolicy::IsStructurallyValid(record));
	CHECK(SharedStartupCachePolicy::UsesTrustedNtfsFastPath(record));

	record.directoryFileReference = LongPathSeams::UsnFileReference{};
	CHECK_FALSE(SharedStartupCachePolicy::IsStructurallyValid(record));
	CHECK_FALSE(SharedStartupCachePolicy::UsesTrustedNtfsFastPath(record));
}

TEST_CASE("Shared startup cache trusted NTFS volume guard rejects journal resets and range loss")
{
	SharedStartupCachePolicy::VolumeRecord record = {};
	record.strVolumeKey = CString(L"\\\\?\\volume{test}\\");
	record.ullVolumeSerialNumber = 77u;
	record.ullUsnJournalId = 88u;
	record.llJournalCheckpointUsn = 100;

	CHECK(SharedStartupCachePolicy::MatchesTrustedNtfsVolumeGuard(record, true, CString(L"\\\\?\\volume{test}\\"), 77u, 88u, 90, 150));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesTrustedNtfsVolumeGuard(record, false, CString(L"\\\\?\\volume{test}\\"), 77u, 88u, 90, 150));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesTrustedNtfsVolumeGuard(record, true, CString(L"\\\\?\\volume{other}\\"), 77u, 88u, 90, 150));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesTrustedNtfsVolumeGuard(record, true, CString(L"\\\\?\\volume{test}\\"), 78u, 88u, 90, 150));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesTrustedNtfsVolumeGuard(record, true, CString(L"\\\\?\\volume{test}\\"), 77u, 89u, 90, 150));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesTrustedNtfsVolumeGuard(record, true, CString(L"\\\\?\\volume{test}\\"), 77u, 88u, 101, 150));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesTrustedNtfsVolumeGuard(record, true, CString(L"\\\\?\\volume{test}\\"), 77u, 88u, 90, 99));
}
#endif

TEST_CASE("Shared startup cache verification also requires matching file date and size")
{
	SharedStartupCachePolicy::FileRecord record = {};
	record.strLeafName = CString(L"file.bin");
	record.utcFileDate = 55;
	record.ullFileSize = 66u;

	CHECK(SharedStartupCachePolicy::MatchesVerifiedFileState(record, true, 55, 66u));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesVerifiedFileState(record, false, 55, 66u));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesVerifiedFileState(record, true, 56, 66u));
	CHECK_FALSE(SharedStartupCachePolicy::MatchesVerifiedFileState(record, true, 55, 67u));
}

TEST_CASE("Shared startup cache generic inventory validation requires an exact file set")
{
	std::vector<SharedStartupCachePolicy::FileRecord> cached = {
		{ CString(L"beta.bin"), 22, 200u },
		{ CString(L"alpha.bin"), 11, 100u }
	};
	std::vector<SharedStartupCachePolicy::FileRecord> current = {
		{ CString(L"alpha.bin"), 11, 100u },
		{ CString(L"beta.bin"), 22, 200u }
	};
	CHECK(SharedStartupCachePolicy::FileRecordSetsMatchForInventoryValidation(cached, current));

	current.push_back({ CString(L"gamma.bin"), 33, 300u });
	CHECK_FALSE(SharedStartupCachePolicy::FileRecordSetsMatchForInventoryValidation(cached, current));

	current = cached;
	current.pop_back();
	CHECK_FALSE(SharedStartupCachePolicy::FileRecordSetsMatchForInventoryValidation(cached, current));

	current = cached;
	current[0].ullFileSize += 1u;
	CHECK_FALSE(SharedStartupCachePolicy::FileRecordSetsMatchForInventoryValidation(cached, current));

	current = cached;
	current[0].strLeafName = CString(L"BETA.bin");
	CHECK_FALSE(SharedStartupCachePolicy::FileRecordSetsMatchForInventoryValidation(cached, current));
}
#endif

#if defined(EMULEBB_TESTS_HAS_LONG_PATH_SEAMS) && defined(EMULEBB_LONG_PATH_SEAMS_HAS_NTFS_JOURNAL_HELPERS)
TEST_CASE("Long path seams parse V2 V3 and V4 USN record identities")
{
	{
		USN_RECORD_V2 record = {};
		USN_RECORD_COMMON_HEADER *pHeader = reinterpret_cast<USN_RECORD_COMMON_HEADER *>(&record);
		pHeader->MajorVersion = 2;
		pHeader->RecordLength = sizeof(record);
		record.FileReferenceNumber = 0x1122334455667788ull;
		record.ParentFileReferenceNumber = 0x8877665544332211ull;
		record.Usn = 123;

		LongPathSeams::UsnFileReference fileReference = {};
		LongPathSeams::UsnFileReference parentReference = {};
		LONGLONG llUsn = 0;
		DWORD dwError = ERROR_SUCCESS;
		REQUIRE(LongPathSeams::TryParseUsnRecordIdentity(reinterpret_cast<const USN_RECORD_COMMON_HEADER *>(&record), sizeof(record), fileReference, &parentReference, &llUsn, &dwError));
		CHECK(fileReference == LongPathSeams::MakeUsnFileReferenceFromUInt64(record.FileReferenceNumber));
		CHECK(parentReference == LongPathSeams::MakeUsnFileReferenceFromUInt64(record.ParentFileReferenceNumber));
		CHECK(llUsn == record.Usn);
	}

	{
		USN_RECORD_V3 record = {};
		USN_RECORD_COMMON_HEADER *pHeader = reinterpret_cast<USN_RECORD_COMMON_HEADER *>(&record);
		pHeader->MajorVersion = 3;
		pHeader->RecordLength = sizeof(record);
		for (int i = 0; i < 16; ++i) {
			record.FileReferenceNumber.Identifier[i] = static_cast<BYTE>(i + 1);
			record.ParentFileReferenceNumber.Identifier[i] = static_cast<BYTE>(0xF0 + i);
		}
		record.Usn = 456;

		LongPathSeams::UsnFileReference fileReference = {};
		LongPathSeams::UsnFileReference parentReference = {};
		LONGLONG llUsn = 0;
		DWORD dwError = ERROR_SUCCESS;
		REQUIRE(LongPathSeams::TryParseUsnRecordIdentity(reinterpret_cast<const USN_RECORD_COMMON_HEADER *>(&record), sizeof(record), fileReference, &parentReference, &llUsn, &dwError));
		CHECK(fileReference == LongPathSeams::MakeUsnFileReferenceFromFileId128(record.FileReferenceNumber));
		CHECK(parentReference == LongPathSeams::MakeUsnFileReferenceFromFileId128(record.ParentFileReferenceNumber));
		CHECK(llUsn == record.Usn);
	}

	{
		USN_RECORD_V4 record = {};
		USN_RECORD_COMMON_HEADER *pHeader = reinterpret_cast<USN_RECORD_COMMON_HEADER *>(&record);
		pHeader->MajorVersion = 4;
		pHeader->RecordLength = sizeof(record);
		for (int i = 0; i < 16; ++i) {
			record.FileReferenceNumber.Identifier[i] = static_cast<BYTE>(0x10 + i);
			record.ParentFileReferenceNumber.Identifier[i] = static_cast<BYTE>(0x80 + i);
		}
		record.Usn = 789;

		LongPathSeams::UsnFileReference fileReference = {};
		LongPathSeams::UsnFileReference parentReference = {};
		LONGLONG llUsn = 0;
		DWORD dwError = ERROR_SUCCESS;
		REQUIRE(LongPathSeams::TryParseUsnRecordIdentity(reinterpret_cast<const USN_RECORD_COMMON_HEADER *>(&record), sizeof(record), fileReference, &parentReference, &llUsn, &dwError));
		CHECK(fileReference == LongPathSeams::MakeUsnFileReferenceFromFileId128(record.FileReferenceNumber));
		CHECK(parentReference == LongPathSeams::MakeUsnFileReferenceFromFileId128(record.ParentFileReferenceNumber));
		CHECK(llUsn == record.Usn);
	}
}

TEST_CASE("Long path seams resolve the containing local volume instead of guessing from the drive root")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 64u, 0xB0FF01u));

	LongPathSeams::ResolvedVolumeContext context = {};
	DWORD dwError = ERROR_SUCCESS;
	REQUIRE(LongPathSeams::TryResolveContainingVolumeContext(CString(fixture.DirectoryPath().c_str()), context, &dwError));
	CHECK_FALSE(context.strMountRoot.empty());
	CHECK_FALSE(context.strVolumeGuidPath.empty());
	CHECK_FALSE(context.strVolumeKey.empty());
	CHECK(context.bIsLocal);
}

TEST_CASE("Long path seams resolve mounted-folder volumes to the mounted root instead of the parent drive")
{
	const CString strMountedRoot(L"C:\\M\\H20T00\\");
	if (::GetFileAttributesW(strMountedRoot) == INVALID_FILE_ATTRIBUTES)
		return;

	LongPathSeams::ResolvedVolumeContext rootContext = {};
	DWORD dwError = ERROR_SUCCESS;
	REQUIRE(LongPathSeams::TryResolveContainingVolumeContext(strMountedRoot, rootContext, &dwError));
	CHECK(CString(rootContext.strMountRoot.c_str()).CompareNoCase(strMountedRoot) == 0);
	CHECK(CString(rootContext.strVolumeGuidPath.c_str()).Find(L"\\\\?\\Volume{") == 0);
	CHECK(CString(rootContext.strMountRoot.c_str()).CompareNoCase(L"C:\\") != 0);

	LongPathSeams::ResolvedVolumeContext trimmedRootContext = {};
	REQUIRE(LongPathSeams::TryResolveContainingVolumeContext(PathHelpers::TrimTrailingSeparator(strMountedRoot), trimmedRootContext, &dwError));
	CHECK(CString(trimmedRootContext.strMountRoot.c_str()).CompareNoCase(strMountedRoot) == 0);
	CHECK(trimmedRootContext.strVolumeKey == rootContext.strVolumeKey);

	LongPathSeams::ResolvedVolumeContext childContext = {};
	REQUIRE(LongPathSeams::TryResolveContainingVolumeContext(strMountedRoot + L"probe", childContext, &dwError));
	CHECK(CString(childContext.strMountRoot.c_str()).CompareNoCase(strMountedRoot) == 0);
	CHECK(childContext.strVolumeKey == rootContext.strVolumeKey);
}

TEST_CASE("Long path seams mark cached NTFS directories dirty through one journal delta scan")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 64u, 0xB10001u));

	LongPathSeams::NtfsJournalVolumeState volumeState = {};
	DWORD dwError = ERROR_SUCCESS;
	if (!LongPathSeams::TryGetLocalNtfsJournalVolumeState(CString(fixture.DirectoryPath().c_str()), volumeState, &dwError))
		return;

	LongPathSeams::NtfsDirectoryJournalState directoryState = {};
	REQUIRE(LongPathSeams::TryGetNtfsDirectoryJournalState(CString(fixture.DirectoryPath().c_str()), directoryState, &dwError));

	std::unordered_set<LongPathSeams::UsnFileReference, LongPathSeams::UsnFileReferenceHasher> trackedDirectoryRefs = { directoryState.fileReference };
	std::unordered_set<LongPathSeams::UsnFileReference, LongPathSeams::UsnFileReferenceHasher> changedDirectoryRefs;
	CHECK(LongPathSeams::TryCollectChangedDirectoryFileReferences(CString(fixture.DirectoryPath().c_str()), volumeState.ullUsnJournalId, volumeState.llNextUsn, trackedDirectoryRefs, changedDirectoryRefs, &dwError));
	CHECK(changedDirectoryRefs.empty());

	const std::wstring addedPath = fixture.MakeDirectoryChildPath(L"journal-delta.bin");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(addedPath, LongPathTestSupport::BuildDeterministicPayload(17u, 0xB10002u)));
	::Sleep(50);

	changedDirectoryRefs.clear();
	CHECK(LongPathSeams::TryCollectChangedDirectoryFileReferences(CString(fixture.DirectoryPath().c_str()), volumeState.ullUsnJournalId, volumeState.llNextUsn, trackedDirectoryRefs, changedDirectoryRefs, &dwError));
	CHECK(changedDirectoryRefs.find(directoryState.fileReference) != changedDirectoryRefs.end());

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(addedPath));
}
#endif

TEST_SUITE_END;
