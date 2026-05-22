#include "../third_party/doctest/doctest.h"

#include "Win32CallbackTimerSeams.h"

namespace
{
	void CALLBACK NoOpTimerProc(HWND, UINT, UINT_PTR, DWORD) noexcept
	{
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Win32 callback timer seam starts and clears null-window timers")
{
	UINT_PTR uTimerId = 0;

	REQUIRE(Win32CallbackTimerSeams::TryStartNullWindowCallbackTimer(uTimerId, 1000u, NoOpTimerProc));
	CHECK(uTimerId != 0);
	CHECK(Win32CallbackTimerSeams::StopNullWindowCallbackTimer(uTimerId) == Win32CallbackTimerSeams::ETimerStopResult::Stopped);
	CHECK(uTimerId == 0);
	CHECK(Win32CallbackTimerSeams::StopNullWindowCallbackTimer(uTimerId) == Win32CallbackTimerSeams::ETimerStopResult::NotRunning);
}

TEST_CASE("Win32 callback timer dispatch guards preserve shutdown and visibility checks")
{
	CHECK(Win32CallbackTimerSeams::ShouldDispatchQueueListRefreshTimer(true, true, true, false));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchQueueListRefreshTimer(false, true, true, false));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchQueueListRefreshTimer(true, false, true, false));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchQueueListRefreshTimer(true, true, false, false));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchQueueListRefreshTimer(true, true, true, true));

	CHECK(Win32CallbackTimerSeams::ShouldDispatchUploadQueueTimer(false));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchUploadQueueTimer(true));

	CHECK(Win32CallbackTimerSeams::ShouldDispatchServerRetryTimer(true));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchServerRetryTimer(false));

	CHECK(Win32CallbackTimerSeams::ShouldDispatchUPnPTimeoutTimer(true, false));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchUPnPTimeoutTimer(false, false));
	CHECK_FALSE(Win32CallbackTimerSeams::ShouldDispatchUPnPTimeoutTimer(true, true));
}

TEST_CASE("Queue-list timer delay keeps the legacy ten-second minimum")
{
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(500u) == 10000u);
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(1000u) == 10000u);
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(2000u) == 10000u);
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(5000u) == 10000u);
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(10000u) == 10000u);
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(0u) == 10000u);
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(750u) == 10000u);
	CHECK(Win32CallbackTimerSeams::GetQueueListRefreshTimerDelayMs(60000u) == 10000u);
}

TEST_SUITE_END();
