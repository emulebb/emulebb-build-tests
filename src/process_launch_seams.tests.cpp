#include "doctest.h"

#include "ProcessLaunchSeams.h"

TEST_SUITE_BEGIN("process_launch");

TEST_CASE("Process launch seam classifies bounded wait outcomes")
{
	CHECK(ProcessLaunchSeams::ClassifyProcessWaitResult(WAIT_OBJECT_0) == ProcessLaunchSeams::EProcessWaitResult::Completed);
	CHECK(ProcessLaunchSeams::ClassifyProcessWaitResult(WAIT_TIMEOUT) == ProcessLaunchSeams::EProcessWaitResult::TimedOut);
	CHECK(ProcessLaunchSeams::ClassifyProcessWaitResult(WAIT_FAILED) == ProcessLaunchSeams::EProcessWaitResult::Failed);
	CHECK(ProcessLaunchSeams::ClassifyProcessWaitResult(WAIT_ABANDONED) == ProcessLaunchSeams::EProcessWaitResult::Other);
}

TEST_CASE("Process launch seam keeps external process waits bounded")
{
	CHECK(ProcessLaunchSeams::kElevatedPowerShellActionTimeoutMs >= 5u * 60u * 1000u);
	CHECK(ProcessLaunchSeams::kArchiveRecoveryPreviewTimeoutMs >= 5u * 60u * 1000u);
	CHECK(ProcessLaunchSeams::kTimedOutProcessTerminateWaitMs <= 5u * 1000u);
}

TEST_CASE("Process launch seam result objects default to non-started success-neutral state")
{
	const ProcessLaunchSeams::DetachedLaunchResult detached;
	CHECK_FALSE(detached.Started);
	CHECK(detached.LastError == ERROR_SUCCESS);

	const ProcessLaunchSeams::BoundedProcessResult bounded;
	CHECK_FALSE(bounded.Started);
	CHECK(bounded.WaitResult == ProcessLaunchSeams::EProcessWaitResult::Other);
	CHECK(bounded.LastError == ERROR_SUCCESS);
	CHECK(bounded.ExitCode == ERROR_SUCCESS);
}

TEST_SUITE_END();
