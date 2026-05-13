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

TEST_CASE("Shared-directory monitor journal persistence uses durable replace and removes failed temp files")
{
	using namespace SharedDirectoryMonitorSeams;

	CHECK_EQ(GetJournalReplaceFlags(), static_cast<DWORD>(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
	CHECK_FALSE(ShouldDeleteJournalTempFile(false, false));
	CHECK_FALSE(ShouldDeleteJournalTempFile(true, true));
	CHECK(ShouldDeleteJournalTempFile(true, false));
}

TEST_SUITE_END;
