#include "../third_party/doctest/doctest.h"

#include "HelperThreadLaunchSeams.h"

namespace
{
struct FakeSuspendedThread
{
	BOOL m_bAutoDelete = TRUE;
	DWORD dwResumeResult = 0;

	DWORD ResumeThread()
	{
		return dwResumeResult;
	}
};

struct DeletableSuspendedThread
{
	BOOL m_bAutoDelete = TRUE;
	DWORD dwResumeResult = 0;
	bool *pbDeleted = nullptr;

	DWORD ResumeThread()
	{
		return dwResumeResult;
	}

	~DeletableSuspendedThread()
	{
		if (pbDeleted != nullptr)
			*pbDeleted = true;
	}
};

struct FakeWaitEvent
{
	HANDLE hEvent = NULL;
	int nLockCount = 0;

	explicit FakeWaitEvent(bool bSignaled)
		: hEvent(::CreateEvent(NULL, TRUE, bSignaled ? TRUE : FALSE, NULL))
	{
	}

	explicit FakeWaitEvent(HANDLE hInvalidEvent)
		: hEvent(hInvalidEvent)
	{
	}

	~FakeWaitEvent()
	{
		if (hEvent != NULL && hEvent != INVALID_HANDLE_VALUE)
			::CloseHandle(hEvent);
	}

	operator HANDLE() const
	{
		return hEvent;
	}

	BOOL Lock()
	{
		++nLockCount;
		return TRUE;
	}
};
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Helper thread launch seam classifies AfxBeginThread results")
{
	int fakeThread = 0;

	CHECK(HelperThreadLaunchSeams::DidStartThread(&fakeThread));
	CHECK_FALSE(HelperThreadLaunchSeams::DidStartThread(nullptr));
}

TEST_CASE("Helper thread launch seam classifies suspended resume results")
{
	int fakeThread = 0;

	CHECK(HelperThreadLaunchSeams::DidResumeThread(0));
	CHECK(HelperThreadLaunchSeams::DidResumeThread(2));
	CHECK_FALSE(HelperThreadLaunchSeams::DidResumeThread(static_cast<DWORD>(-1)));

	CHECK(HelperThreadLaunchSeams::ClassifySuspendedThreadResume(nullptr, 0) == HelperThreadLaunchSeams::SuspendedThreadResumeAction::LaunchFailed);
	CHECK(HelperThreadLaunchSeams::ClassifySuspendedThreadResume(&fakeThread, 0) == HelperThreadLaunchSeams::SuspendedThreadResumeAction::Resumed);
	CHECK(HelperThreadLaunchSeams::ClassifySuspendedThreadResume(&fakeThread, static_cast<DWORD>(-1)) == HelperThreadLaunchSeams::SuspendedThreadResumeAction::ResumeFailed);
}

TEST_CASE("Helper thread launch seam resumes auto-delete workers without taking ownership")
{
	FakeSuspendedThread thread;
	DWORD dwLastError = ERROR_SUCCESS;

	CHECK(HelperThreadLaunchSeams::ResumeAutoDeleteSuspendedThread(&thread, dwLastError));
	CHECK(dwLastError == ERROR_SUCCESS);
	CHECK(thread.m_bAutoDelete == TRUE);

	thread.dwResumeResult = static_cast<DWORD>(-1);
	CHECK_FALSE(HelperThreadLaunchSeams::ResumeAutoDeleteSuspendedThread(&thread, dwLastError));
	CHECK(thread.m_bAutoDelete == TRUE);
}

TEST_CASE("Helper thread launch seam owns suspended workers and releases resume failures")
{
	bool bDeleted = false;
	DeletableSuspendedThread *pThread = new DeletableSuspendedThread;
	pThread->pbDeleted = &bDeleted;
	DeletableSuspendedThread *pOwnedThread = nullptr;
	DWORD dwLastError = ERROR_SUCCESS;

	CHECK(HelperThreadLaunchSeams::OwnAndResumeSuspendedThread(pOwnedThread, pThread, dwLastError));
	REQUIRE(pOwnedThread == pThread);
	CHECK(pOwnedThread->m_bAutoDelete == FALSE);
	CHECK_FALSE(bDeleted);
	delete pOwnedThread;

	bDeleted = false;
	pThread = new DeletableSuspendedThread;
	pThread->pbDeleted = &bDeleted;
	pThread->dwResumeResult = static_cast<DWORD>(-1);
	pOwnedThread = nullptr;
	CHECK_FALSE(HelperThreadLaunchSeams::OwnAndResumeSuspendedThread(pOwnedThread, pThread, dwLastError));
	CHECK(pOwnedThread == nullptr);
	CHECK(bDeleted);
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

	CHECK(HelperThreadLaunchSeams::ShouldProcessIocpWorkerCompletion(TRUE, 1, NULL));
	CHECK(HelperThreadLaunchSeams::ShouldProcessIocpWorkerCompletion(FALSE, 1, reinterpret_cast<void *>(1)));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldProcessIocpWorkerCompletion(TRUE, 0, NULL));
	CHECK_FALSE(HelperThreadLaunchSeams::ShouldProcessIocpWorkerCompletion(FALSE, 0, NULL));

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
	CHECK_EQ(HelperThreadLaunchSeams::kHelperThreadShutdownWaitMs, 30000u);
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

TEST_CASE("Helper thread shutdown wait seam centralizes event-ended worker policy")
{
	int nTimedOut = 0;
	int nFailed = 0;
	DWORD dwFailedError = ERROR_SUCCESS;

	{
		FakeWaitEvent event(static_cast<HANDLE>(NULL));
		CHECK(HelperThreadLaunchSeams::WaitForEventThreadShutdown(
			event,
			false,
			0,
			[&]() { ++nTimedOut; },
			[&](DWORD dwLastError) {
				++nFailed;
				dwFailedError = dwLastError;
			}) == HelperThreadLaunchSeams::ShutdownWaitAction::Finished);
		CHECK(event.nLockCount == 0);
	}

	{
		FakeWaitEvent event(true);
		CHECK(HelperThreadLaunchSeams::WaitForEventThreadShutdown(
			event,
			true,
			0,
			[&]() { ++nTimedOut; },
			[&](DWORD dwLastError) {
				++nFailed;
				dwFailedError = dwLastError;
			}) == HelperThreadLaunchSeams::ShutdownWaitAction::Finished);
		CHECK(event.nLockCount == 0);
	}

	{
		FakeWaitEvent event(false);
		CHECK(HelperThreadLaunchSeams::WaitForEventThreadShutdown(
			event,
			true,
			0,
			[&]() { ++nTimedOut; },
			[&](DWORD dwLastError) {
				++nFailed;
				dwFailedError = dwLastError;
			}) == HelperThreadLaunchSeams::ShutdownWaitAction::TimedOut);
		CHECK(event.nLockCount == 1);
	}

	{
		FakeWaitEvent event(static_cast<HANDLE>(NULL));
		CHECK(HelperThreadLaunchSeams::WaitForEventThreadShutdown(
			event,
			true,
			0,
			[&]() { ++nTimedOut; },
			[&](DWORD dwLastError) {
				++nFailed;
				dwFailedError = dwLastError;
			}) == HelperThreadLaunchSeams::ShutdownWaitAction::Failed);
		CHECK(event.nLockCount == 1);
	}

	CHECK(nTimedOut == 1);
	CHECK(nFailed == 1);
	CHECK(dwFailedError == ERROR_INVALID_HANDLE);
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
