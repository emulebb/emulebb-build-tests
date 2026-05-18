#include "../third_party/doctest/doctest.h"

#include "HelperThreadLaunchSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Helper thread launch seam classifies AfxBeginThread results")
{
	int fakeThread = 0;

	CHECK(HelperThreadLaunchSeams::DidStartThread(&fakeThread));
	CHECK_FALSE(HelperThreadLaunchSeams::DidStartThread(nullptr));
}

TEST_CASE("IOCP helper shutdown skips waits when launch failed")
{
	CHECK(HelperThreadLaunchSeams::ClassifyIocpShutdown(false, false) == HelperThreadLaunchSeams::IocpShutdownAction::NoOp);
	CHECK(HelperThreadLaunchSeams::ClassifyIocpShutdown(false, true) == HelperThreadLaunchSeams::IocpShutdownAction::NoOp);
}

TEST_CASE("IOCP helper shutdown waits without posting before the port is ready")
{
	CHECK(HelperThreadLaunchSeams::ClassifyIocpShutdown(true, false) == HelperThreadLaunchSeams::IocpShutdownAction::WaitOnly);
	CHECK(HelperThreadLaunchSeams::ClassifyIocpShutdown(true, true) == HelperThreadLaunchSeams::IocpShutdownAction::SignalAndWait);
}

TEST_CASE("IOCP helper shutdown request sets stop state only for started workers")
{
	volatile LONG nStopRequested = 0;
	volatile LONG nRunState = 1;

	CHECK(HelperThreadLaunchSeams::RequestIocpShutdown(nStopRequested, nRunState, 0, false, NULL) == HelperThreadLaunchSeams::IocpShutdownAction::NoOp);
	CHECK(HelperThreadLaunchSeams::IsFlagSet(nStopRequested));
	CHECK(HelperThreadLaunchSeams::GetState(nRunState) == 1);

	HelperThreadLaunchSeams::ClearFlag(nStopRequested);
	CHECK(HelperThreadLaunchSeams::RequestIocpShutdown(nStopRequested, nRunState, 0, true, NULL) == HelperThreadLaunchSeams::IocpShutdownAction::WaitOnly);
	CHECK(HelperThreadLaunchSeams::IsFlagSet(nStopRequested));
	CHECK(HelperThreadLaunchSeams::GetState(nRunState) == 0);
}

TEST_CASE("IOCP helper wakeups require a started live worker with a ready port")
{
	CHECK(HelperThreadLaunchSeams::CanPostIocpWork(true, false, true, true));
	CHECK_FALSE(HelperThreadLaunchSeams::CanPostIocpWork(false, false, true, true));
	CHECK_FALSE(HelperThreadLaunchSeams::CanPostIocpWork(true, true, true, true));
	CHECK_FALSE(HelperThreadLaunchSeams::CanPostIocpWork(true, false, false, true));
	CHECK_FALSE(HelperThreadLaunchSeams::CanPostIocpWork(true, false, true, false));
}

TEST_CASE("IOCP helper loop and deferred wake decisions preserve stop key semantics")
{
	CHECK(HelperThreadLaunchSeams::ShouldWaitForIocpWorkerCompletion(false, 1, 0));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldWaitForIocpWorkerCompletion(true, 1, 0));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldWaitForIocpWorkerCompletion(false, 0, 0));

	CHECK(HelperThreadLaunchSeams::ShouldProcessIocpWorkerCompletion(TRUE, 1));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldProcessIocpWorkerCompletion(FALSE, 1));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldProcessIocpWorkerCompletion(TRUE, 0));

	CHECK(HelperThreadLaunchSeams::ShouldPostIocpWakeAfterNewData(1, true));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldPostIocpWakeAfterNewData(0, true));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldPostIocpWakeAfterNewData(1, false));
}

TEST_CASE("IOCP helper owns completion port handles")
{
	HANDLE hPort = NULL;
	DWORD dwLastError = ERROR_SUCCESS;

	REQUIRE(HelperThreadLaunchSeams::TryCreateIocpPort(hPort, dwLastError));
	CHECK(hPort != NULL);
	CHECK(dwLastError == ERROR_SUCCESS);

	HelperThreadLaunchSeams::CloseIocpPort(hPort);
	CHECK(hPort == NULL);

	HelperThreadLaunchSeams::CloseIocpPort(hPort);
	CHECK(hPort == NULL);
}

TEST_CASE("Event helper shutdown only waits when thread launch succeeded")
{
	CHECK(HelperThreadLaunchSeams::ShouldWaitForEventThreadShutdown(true));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldWaitForEventThreadShutdown(false));
}

TEST_CASE("Helper thread shutdown wait seam classifies bounded wait results")
{
	CHECK(HelperThreadLaunchSeams::ClassifyShutdownWait(WAIT_OBJECT_0) == HelperThreadLaunchSeams::ShutdownWaitAction::Finished);
	CHECK(HelperThreadLaunchSeams::ClassifyShutdownWait(WAIT_TIMEOUT) == HelperThreadLaunchSeams::ShutdownWaitAction::TimedOut);
	CHECK(HelperThreadLaunchSeams::ClassifyShutdownWait(WAIT_FAILED) == HelperThreadLaunchSeams::ShutdownWaitAction::Failed);
	CHECK(HelperThreadLaunchSeams::ClassifyShutdownWait(WAIT_ABANDONED) == HelperThreadLaunchSeams::ShutdownWaitAction::Failed);
}

TEST_CASE("Helper thread flags and states use interlocked accessors")
{
	volatile LONG nFlag = 0;
	volatile LONG nState = 0;

	CHECK_FALSE(HelperThreadLaunchSeams::IsFlagSet(nFlag));
	HelperThreadLaunchSeams::SetFlag(nFlag);
	CHECK(HelperThreadLaunchSeams::IsFlagSet(nFlag));
	HelperThreadLaunchSeams::ClearFlag(nFlag);
	CHECK_FALSE(HelperThreadLaunchSeams::IsFlagSet(nFlag));

	HelperThreadLaunchSeams::SetState(nState, 2);
	CHECK(HelperThreadLaunchSeams::GetState(nState) == 2);
	CHECK(HelperThreadLaunchSeams::ExchangeState(nState, 3) == 2);
	CHECK(HelperThreadLaunchSeams::GetState(nState) == 3);
}

TEST_SUITE_END;
