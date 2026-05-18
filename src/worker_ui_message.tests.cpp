#include "../third_party/doctest/doctest.h"

#include <atomic>

#include "WorkerUiMessageSeams.h"

namespace
{
	class CScopedMessageOnlyWindow
	{
	public:
		CScopedMessageOnlyWindow()
			: m_hWnd(::CreateWindowEx(0, L"STATIC", L"worker-ui-test", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, ::GetModuleHandle(NULL), NULL))
		{
		}

		~CScopedMessageOnlyWindow()
		{
			if (m_hWnd != NULL)
				(void)::DestroyWindow(m_hWnd);
		}

		HWND GetHwnd() const
		{
			return m_hWnd;
		}

	private:
		HWND m_hWnd;
	};

	struct STrackedPayload
	{
		explicit STrackedPayload(int nValue)
			: value(nValue)
		{
		}

		~STrackedPayload()
		{
			++s_nDestroyCount;
		}

		int value;
		static int s_nDestroyCount;
	};

	int STrackedPayload::s_nDestroyCount = 0;
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Worker/UI seam posts only while the target window is still alive and not closing")
{
	CScopedMessageOnlyWindow window;
	const HWND hWnd = window.GetHwnd();
	if (hWnd == NULL)
		FAIL("Expected the message-only test window to be created.");

	std::atomic_bool bClosing(false);
	CHECK(TryPostWorkerUiMessage(hWnd, WM_APP + 41, 7, 9, &bClosing));

	MSG msg = {};
	REQUIRE(::PeekMessage(&msg, hWnd, WM_APP + 41, WM_APP + 41, PM_REMOVE) != FALSE);
	CHECK_EQ(msg.wParam, static_cast<WPARAM>(7));
	CHECK_EQ(msg.lParam, static_cast<LPARAM>(9));

	bClosing.store(true, std::memory_order_release);
	CHECK_FALSE(TryPostWorkerUiMessage(hWnd, WM_APP + 42, 0, 0, &bClosing));
	CHECK_FALSE(TryPostWorkerUiMessage(NULL, WM_APP + 43));
}

TEST_CASE("Worker/UI seam classifies direct UI message delivery")
{
	CHECK(ClassifyWorkerUiMessageDelivery(true, true) == EWorkerUiMessageDelivery::Delivered);
	CHECK(ClassifyWorkerUiMessageDelivery(true, false) == EWorkerUiMessageDelivery::Failed);
	CHECK(ClassifyWorkerUiMessageDelivery(false, true) == EWorkerUiMessageDelivery::InvalidWindow);
	CHECK(ClassifyWorkerUiMessageDelivery(false, false) == EWorkerUiMessageDelivery::InvalidWindow);

	const SWorkerUiMessageDelivery posted = PostWorkerUiMessage(NULL, WM_APP + 46);
	CHECK(posted.eDelivery == EWorkerUiMessageDelivery::InvalidWindow);
	CHECK(posted.dwLastError == ERROR_INVALID_WINDOW_HANDLE);

	const SWorkerUiMessageDelivery sent = SendWorkerUiMessage(NULL, WM_APP + 47);
	CHECK(sent.eDelivery == EWorkerUiMessageDelivery::InvalidWindow);
	CHECK(sent.dwLastError == ERROR_INVALID_WINDOW_HANDLE);
}

TEST_CASE("Worker/UI seam transfers queued payload ownership to the UI thread")
{
	CScopedMessageOnlyWindow window;
	const HWND hWnd = window.GetHwnd();
	if (hWnd == NULL)
		FAIL("Expected the message-only test window to be created.");

	std::atomic_bool bClosing(false);
	STrackedPayload::s_nDestroyCount = 0;
	REQUIRE(TryPostWorkerUiPayloadMessage(hWnd, &bClosing, 0x1234u, WM_APP + 44, std::unique_ptr<STrackedPayload>(new STrackedPayload(17))));

	MSG msg = {};
	REQUIRE(::PeekMessage(&msg, hWnd, WM_APP + 44, WM_APP + 44, PM_REMOVE) != FALSE);

	std::unique_ptr<STrackedPayload> pPayload = TakePostedWorkerUiPayload<STrackedPayload>(msg.wParam);
	if (pPayload.get() == NULL)
		FAIL("Expected the queued payload to be available on the UI thread.");
	CHECK_EQ(pPayload->value, 17);
	pPayload.reset();
	CHECK_EQ(STrackedPayload::s_nDestroyCount, 1);
}

TEST_CASE("Worker/UI seam drops queued payloads once the owning window tears down")
{
	CScopedMessageOnlyWindow window;
	const HWND hWnd = window.GetHwnd();
	if (hWnd == NULL)
		FAIL("Expected the message-only test window to be created.");

	std::atomic_bool bClosing(false);
	const ULONG_PTR nOwnerKey = 0xBEEFu;
	STrackedPayload::s_nDestroyCount = 0;
	REQUIRE(TryPostWorkerUiPayloadMessage(hWnd, &bClosing, nOwnerKey, WM_APP + 45, std::unique_ptr<STrackedPayload>(new STrackedPayload(33))));

	DiscardPostedWorkerUiPayloadsForOwner(nOwnerKey);
	CHECK_EQ(STrackedPayload::s_nDestroyCount, 1);

	MSG msg = {};
	REQUIRE(::PeekMessage(&msg, hWnd, WM_APP + 45, WM_APP + 45, PM_REMOVE) != FALSE);
	std::unique_ptr<STrackedPayload> pDroppedPayload = TakePostedWorkerUiPayload<STrackedPayload>(msg.wParam);
	CHECK_FALSE(static_cast<bool>(pDroppedPayload));
}

TEST_SUITE_END;
