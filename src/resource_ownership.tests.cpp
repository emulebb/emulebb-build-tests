#include "../third_party/doctest/doctest.h"

#include "ResourceOwnershipSeams.h"

#include <vector>
#include <windows.h>

namespace
{
	struct FakeOwnedObject
	{
		int value;
	};

	struct FakeRequestedBlock
	{
		int id;
	};

	struct FakePendingBlock
	{
		FakeRequestedBlock *block;
	};

	struct FakePendingList
	{
		std::vector<FakePendingBlock*> items;

		~FakePendingList()
		{
			for (FakePendingBlock *pItem : items)
				delete pItem;
		}

		void AddTail(FakePendingBlock *pItem)
		{
			items.push_back(pItem);
		}
	};

	UINT_PTR HandleValue(const void *hHandle) noexcept
	{
		return reinterpret_cast<UINT_PTR>(hHandle);
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("ScopedHandle closes the wrapped Win32 handle on scope exit")
{
	HANDLE hEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	REQUIRE(hEvent != NULL);

	{
		ScopedHandle hOwnedEvent(hEvent);
		REQUIRE(hOwnedEvent.IsValid());
		CHECK(HandleValue(hOwnedEvent.Get()) == HandleValue(hEvent));
	}

	::SetLastError(ERROR_SUCCESS);
	CHECK(::WaitForSingleObject(hEvent, 0) == WAIT_FAILED);
	CHECK(::GetLastError() == ERROR_INVALID_HANDLE);
}

TEST_CASE("ScopedHandle reset closes the previously owned handle before replacing it")
{
	HANDLE hFirstEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	HANDLE hSecondEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	REQUIRE(hFirstEvent != NULL);
	REQUIRE(hSecondEvent != NULL);

	ScopedHandle hOwnedEvent(hFirstEvent);
	hOwnedEvent.Reset(hSecondEvent);

	CHECK(hOwnedEvent.IsValid());
	CHECK(HandleValue(hOwnedEvent.Get()) == HandleValue(hSecondEvent));

	::SetLastError(ERROR_SUCCESS);
	CHECK(::WaitForSingleObject(hFirstEvent, 0) == WAIT_FAILED);
	CHECK(::GetLastError() == ERROR_INVALID_HANDLE);

	HANDLE hReleasedEvent = hOwnedEvent.Release();
	CHECK(HandleValue(hReleasedEvent) == HandleValue(hSecondEvent));
	CHECK_FALSE(hOwnedEvent.IsValid());
	CHECK(::CloseHandle(hReleasedEvent) != 0);
}

TEST_CASE("ScopedHandle release keeps the raw handle alive for the next owner")
{
	HANDLE hEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	REQUIRE(hEvent != NULL);

	ScopedHandle hOwnedEvent(hEvent);
	HANDLE hReleasedEvent = hOwnedEvent.Release();

	CHECK(HandleValue(hReleasedEvent) == HandleValue(hEvent));
	CHECK_FALSE(hOwnedEvent.IsValid());
	CHECK(::WaitForSingleObject(hReleasedEvent, 0) == WAIT_TIMEOUT);
	CHECK(::CloseHandle(hReleasedEvent) != 0);
}

TEST_CASE("ScopedGdiObject deletes owned bitmaps on scope exit")
{
	HBITMAP hBitmap = ::CreateBitmap(2, 2, 1, 1, NULL);
	REQUIRE(hBitmap != NULL);

	{
		ScopedGdiObject hOwnedBitmap(hBitmap);
		CHECK(HandleValue(hOwnedBitmap.Get()) == HandleValue(hBitmap));
	}

	BITMAP bitmap = {};
	CHECK(::GetObject(hBitmap, sizeof(bitmap), &bitmap) == 0);
}

TEST_CASE("ScopedGdiObject release leaves ownership with the caller")
{
	HBRUSH hBrush = ::CreateSolidBrush(RGB(1, 2, 3));
	REQUIRE(hBrush != NULL);

	{
		ScopedGdiObject hOwnedBrush(hBrush);
		CHECK(HandleValue(hOwnedBrush.Release()) == HandleValue(hBrush));
		CHECK(HandleValue(hOwnedBrush.Get()) == 0u);
	}

	LOGBRUSH brush = {};
	CHECK(::GetObject(hBrush, sizeof(brush), &brush) == sizeof(brush));
	CHECK(::DeleteObject(hBrush) != 0);
}

TEST_CASE("ScopedDc deletes scratch DCs on scope exit")
{
	HDC hScratchDc = ::CreateCompatibleDC(NULL);
	REQUIRE(hScratchDc != NULL);

	{
		ScopedDc hOwnedDc(hScratchDc);
		CHECK(HandleValue(hOwnedDc.Get()) == HandleValue(hScratchDc));
	}

	CHECK(::DeleteDC(hScratchDc) == 0);
}

TEST_CASE("ScopedSelectObject restores the previous bitmap before callers consume the selected object")
{
	HDC hScratchDc = ::CreateCompatibleDC(NULL);
	REQUIRE(hScratchDc != NULL);
	ScopedDc hOwnedDc(hScratchDc);

	HBITMAP hFirstBitmap = ::CreateBitmap(2, 2, 1, 1, NULL);
	HBITMAP hSecondBitmap = ::CreateBitmap(2, 2, 1, 1, NULL);
	REQUIRE(hFirstBitmap != NULL);
	REQUIRE(hSecondBitmap != NULL);

	HGDIOBJ hOriginalBitmap = ::SelectObject(hScratchDc, hFirstBitmap);
	REQUIRE(hOriginalBitmap != NULL);
	REQUIRE(hOriginalBitmap != HGDI_ERROR);

	{
		ScopedSelectObject hSelectSecondBitmap(hScratchDc, hSecondBitmap);
		REQUIRE(hSelectSecondBitmap.IsValid());
		CHECK(HandleValue(::GetCurrentObject(hScratchDc, OBJ_BITMAP)) == HandleValue(hSecondBitmap));
	}

	CHECK(HandleValue(::GetCurrentObject(hScratchDc, OBJ_BITMAP)) == HandleValue(hFirstBitmap));

	::SelectObject(hScratchDc, hOriginalBitmap);
	CHECK(::DeleteObject(hFirstBitmap) != 0);
	CHECK(::DeleteObject(hSecondBitmap) != 0);
}

TEST_CASE("ReleaseOwnedObjectIfMatched only releases ownership for the accepted object")
{
	{
		std::unique_ptr<FakeOwnedObject> pOwnedObject(new FakeOwnedObject{1});
		FakeOwnedObject *pAcceptedObject = pOwnedObject.get();

		ReleaseOwnedObjectIfMatched(pOwnedObject, pAcceptedObject);

		CHECK(pOwnedObject.get() == nullptr);
		delete pAcceptedObject;
	}

	{
		std::unique_ptr<FakeOwnedObject> pOwnedObject(new FakeOwnedObject{2});
		FakeOwnedObject otherObject = {3};

		ReleaseOwnedObjectIfMatched(pOwnedObject, &otherObject);

		CHECK(pOwnedObject.get() != nullptr);
		CHECK(pOwnedObject->value == 2);
	}
}

TEST_CASE("ReleaseOwnedObjectIfSuperseded drops the consumed temporary object without touching the replacement")
{
	std::unique_ptr<FakeOwnedObject> pOwnedObject(new FakeOwnedObject{4});
	FakeOwnedObject *pTemporaryObject = pOwnedObject.get();
	FakeOwnedObject replacementObject = {5};

	ReleaseOwnedObjectIfSuperseded(pOwnedObject, pTemporaryObject, &replacementObject);

	CHECK(pOwnedObject.get() == nullptr);
}

TEST_CASE("Hello attach ownership releases the temporary client when the list returns a known replacement")
{
	std::unique_ptr<FakeOwnedObject> pOwnedHelloClient(new FakeOwnedObject{7});
	FakeOwnedObject *pTemporaryHelloClient = pOwnedHelloClient.get();
	FakeOwnedObject knownClient = {8};

	ReleaseOwnedObjectIfSuperseded(pOwnedHelloClient, pTemporaryHelloClient, &knownClient);

	CHECK(pOwnedHelloClient.get() == nullptr);
	CHECK(knownClient.value == 8);
}

TEST_CASE("ReleaseOwnedObjectIfSuperseded keeps ownership when the raw pointer was not replaced")
{
	std::unique_ptr<FakeOwnedObject> pOwnedObject(new FakeOwnedObject{6});
	FakeOwnedObject *pTemporaryObject = pOwnedObject.get();

	ReleaseOwnedObjectIfSuperseded(pOwnedObject, pTemporaryObject, pTemporaryObject);

	REQUIRE(pOwnedObject.get() != nullptr);
	CHECK(pOwnedObject->value == 6);
}

TEST_CASE("AppendPendingBlocksFromStage preserves staged pointer order")
{
	FakeRequestedBlock firstBlock = {1};
	FakeRequestedBlock secondBlock = {2};
	FakeRequestedBlock *stagedBlocks[] = {&firstBlock, &secondBlock};
	FakePendingList pendingList;

	AppendPendingBlocksFromStage<FakePendingList, FakePendingBlock>(pendingList, stagedBlocks, 2);

	REQUIRE(pendingList.items.size() == 2);
	CHECK(pendingList.items[0]->block == &firstBlock);
	CHECK(pendingList.items[1]->block == &secondBlock);
}

TEST_SUITE_END;
