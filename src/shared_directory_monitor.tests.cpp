#include "../third_party/doctest/doctest.h"

#include "SharedDirectoryMonitorSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Shared-directory monitor shutdown releases resources only after a known thread exit")
{
	using namespace SharedDirectoryMonitorSeams;

	CHECK(DidMonitorThreadExit(StopWaitResult{false, WAIT_OBJECT_0}));
	CHECK(ShouldReleaseMonitorResources(StopWaitResult{false, WAIT_OBJECT_0}));
	CHECK_FALSE(ShouldLogAbandonedMonitorResources(StopWaitResult{false, WAIT_OBJECT_0}));

	CHECK(DidMonitorThreadExit(StopWaitResult{true, WAIT_OBJECT_0}));
	CHECK(ShouldReleaseMonitorResources(StopWaitResult{true, WAIT_OBJECT_0}));
	CHECK_FALSE(ShouldLogAbandonedMonitorResources(StopWaitResult{true, WAIT_OBJECT_0}));

	CHECK_FALSE(DidMonitorThreadExit(StopWaitResult{true, WAIT_TIMEOUT}));
	CHECK_FALSE(ShouldReleaseMonitorResources(StopWaitResult{true, WAIT_TIMEOUT}));
	CHECK(ShouldLogAbandonedMonitorResources(StopWaitResult{true, WAIT_TIMEOUT}));

	CHECK_FALSE(DidMonitorThreadExit(StopWaitResult{true, WAIT_FAILED}));
	CHECK_FALSE(ShouldReleaseMonitorResources(StopWaitResult{true, WAIT_FAILED}));
	CHECK(ShouldLogAbandonedMonitorResources(StopWaitResult{true, WAIT_FAILED}));
}

TEST_CASE("Shared-directory monitor startup and wait seams classify ownership boundaries")
{
	using namespace SharedDirectoryMonitorSeams;

	CHECK_EQ(kMonitorShutdownWaitMs, 30000u);
	CHECK(GetMonitorWatcherCapacity() >= 1);

	CHECK(AreStartupEventsReady(reinterpret_cast<HANDLE>(1), reinterpret_cast<HANDLE>(2)));
	CHECK_FALSE(AreStartupEventsReady(NULL, reinterpret_cast<HANDLE>(2)));
	CHECK_FALSE(AreStartupEventsReady(reinterpret_cast<HANDLE>(1), NULL));

	CHECK(DidResumeMonitorThread(0));
	CHECK(DidResumeMonitorThread(1));
	CHECK_FALSE(DidResumeMonitorThread(static_cast<DWORD>(-1)));

	CHECK(CanWaitForMonitorHandles(2));
	CHECK(CanWaitForMonitorHandles(MAXIMUM_WAIT_OBJECTS));
	CHECK_FALSE(CanWaitForMonitorHandles(1));
	CHECK_FALSE(CanWaitForMonitorHandles(MAXIMUM_WAIT_OBJECTS + 1));
}

TEST_CASE("Shared-directory monitor wait classification separates stop wake watcher and failed waits")
{
	using namespace SharedDirectoryMonitorSeams;

	MonitorWaitResult result = ClassifyMonitorWaitResult(WAIT_OBJECT_0, 6);
	CHECK(result.eAction == EMonitorWaitAction::Stop);

	result = ClassifyMonitorWaitResult(WAIT_OBJECT_0 + 1, 6);
	CHECK(result.eAction == EMonitorWaitAction::Wake);

	result = ClassifyMonitorWaitResult(WAIT_OBJECT_0 + 2, 6);
	CHECK(result.eAction == EMonitorWaitAction::Watcher);
	CHECK(result.uWatcherIndex == 0);
	CHECK_FALSE(result.bDirectoryEvent);

	result = ClassifyMonitorWaitResult(WAIT_OBJECT_0 + 3, 6);
	CHECK(result.eAction == EMonitorWaitAction::Watcher);
	CHECK(result.uWatcherIndex == 0);
	CHECK(result.bDirectoryEvent);

	result = ClassifyMonitorWaitResult(WAIT_OBJECT_0 + 5, 6);
	CHECK(result.eAction == EMonitorWaitAction::Watcher);
	CHECK(result.uWatcherIndex == 1);
	CHECK(result.bDirectoryEvent);

	CHECK(ClassifyMonitorWaitResult(WAIT_OBJECT_0 + 6, 6).eAction == EMonitorWaitAction::Ignore);
	CHECK(ClassifyMonitorWaitResult(WAIT_ABANDONED_0, 6).eAction == EMonitorWaitAction::Ignore);
	CHECK(ClassifyMonitorWaitResult(WAIT_FAILED, 6).eAction == EMonitorWaitAction::Failed);
	CHECK(ClassifyMonitorWaitResult(WAIT_OBJECT_0, 1).eAction == EMonitorWaitAction::Failed);
}

TEST_CASE("Shared-directory monitor journal persistence uses durable replace and removes failed temp files")
{
	using namespace SharedDirectoryMonitorSeams;

	CHECK_EQ(GetJournalReplaceFlags(), static_cast<DWORD>(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
	CHECK_FALSE(ShouldDeleteJournalTempFile(false, false));
	CHECK_FALSE(ShouldDeleteJournalTempFile(true, true));
	CHECK(ShouldDeleteJournalTempFile(true, false));
}

TEST_SUITE_END;
