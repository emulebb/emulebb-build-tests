#include "../third_party/doctest/doctest.h"

#include <list>
#include <vector>

#include "UploadBandwidthThrottlerSeams.h"

namespace
{
	struct FakeSocket
	{
		int id;
	};

	template <typename TSocket>
	std::vector<int> GetSocketIds(const std::list<TSocket*> &queue)
	{
		std::vector<int> ids;
		for (TSocket *socket : queue)
			ids.push_back(socket != NULL ? socket->id : -1);
		return ids;
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Upload throttler seam expands equal-share rotation to the last queued active slot")
{
	CHECK_EQ(UploadBandwidthThrottlerSeams::CalculateEqualShareSlotLimit(8u, 3u, 0u), 3u);
	CHECK_EQ(UploadBandwidthThrottlerSeams::CalculateEqualShareSlotLimit(8u, 3u, 6u), 6u);
	CHECK_EQ(UploadBandwidthThrottlerSeams::CalculateEqualShareSlotLimit(8u, 12u, 6u), 8u);
	CHECK_EQ(UploadBandwidthThrottlerSeams::CalculateEqualShareSlotLimit(0u, 3u, 6u), 0u);
}

TEST_CASE("Upload throttler seam rotates surplus slot selection across loops")
{
	std::size_t nextSlot = 0;

	CHECK_EQ(UploadBandwidthThrottlerSeams::PopRotatingSlotIndex(nextSlot, 3u), 0u);
	CHECK_EQ(nextSlot, 1u);
	CHECK_EQ(UploadBandwidthThrottlerSeams::PopRotatingSlotIndex(nextSlot, 3u), 1u);
	CHECK_EQ(UploadBandwidthThrottlerSeams::PopRotatingSlotIndex(nextSlot, 3u), 2u);
	CHECK_EQ(nextSlot, 0u);
	CHECK_EQ(UploadBandwidthThrottlerSeams::PopRotatingSlotIndex(nextSlot, 3u), 0u);

	nextSlot = 7u;
	CHECK_EQ(UploadBandwidthThrottlerSeams::PopRotatingSlotIndex(nextSlot, 3u), 0u);
	CHECK_EQ(nextSlot, 1u);
	CHECK_EQ(UploadBandwidthThrottlerSeams::PopRotatingSlotIndex(nextSlot, 0u), 0u);
	CHECK_EQ(nextSlot, 0u);
}

TEST_CASE("Upload throttler seam merges pending control queues without disturbing existing priority order")
{
	FakeSocket liveFirstA{1};
	FakeSocket liveA{2};
	FakeSocket pendingFirstA{3};
	FakeSocket pendingFirstB{4};
	FakeSocket pendingA{5};
	FakeSocket pendingB{6};

	std::list<FakeSocket*> controlQueueFirst{&liveFirstA};
	std::list<FakeSocket*> controlQueue{&liveA};
	std::list<FakeSocket*> tempControlQueueFirst{&pendingFirstA, &pendingFirstB};
	std::list<FakeSocket*> tempControlQueue{&pendingA, &pendingB};

	UploadBandwidthThrottlerSeams::MergePendingControlQueues(controlQueueFirst, controlQueue, tempControlQueueFirst, tempControlQueue);

	CHECK(GetSocketIds(controlQueueFirst) == std::vector<int>{1, 3, 4});
	CHECK(GetSocketIds(controlQueue) == std::vector<int>{2, 5, 6});
	CHECK(tempControlQueueFirst.empty());
	CHECK(tempControlQueue.empty());
}

TEST_CASE("Upload throttler seam pops queued control sockets in priority order")
{
	FakeSocket firstA{1};
	FakeSocket firstB{2};
	FakeSocket normalA{3};

	std::list<FakeSocket*> controlQueueFirst{&firstA, &firstB};
	std::list<FakeSocket*> controlQueue{&normalA};

	CHECK(UploadBandwidthThrottlerSeams::PopNextControlSocket(controlQueueFirst, controlQueue) == &firstA);
	CHECK(UploadBandwidthThrottlerSeams::PopNextControlSocket(controlQueueFirst, controlQueue) == &firstB);
	CHECK(UploadBandwidthThrottlerSeams::PopNextControlSocket(controlQueueFirst, controlQueue) == &normalA);
	CHECK(UploadBandwidthThrottlerSeams::PopNextControlSocket(controlQueueFirst, controlQueue) == nullptr);
}

TEST_CASE("Upload throttler seam removes a socket from every control queue domain")
{
	FakeSocket keepA{1};
	FakeSocket removeMe{2};
	FakeSocket keepB{3};

	std::list<FakeSocket*> controlQueueFirst{&keepA, &removeMe};
	std::list<FakeSocket*> controlQueue{&removeMe, &keepB};
	std::list<FakeSocket*> tempControlQueueFirst{&removeMe};
	std::list<FakeSocket*> tempControlQueue{&keepA, &removeMe, &keepB};

	CHECK(UploadBandwidthThrottlerSeams::RemoveSocketFromAllControlQueues(
		controlQueueFirst,
		controlQueue,
		tempControlQueueFirst,
		tempControlQueue,
		&removeMe));

	CHECK(GetSocketIds(controlQueueFirst) == std::vector<int>{1});
	CHECK(GetSocketIds(controlQueue) == std::vector<int>{3});
	CHECK(tempControlQueueFirst.empty());
	CHECK(GetSocketIds(tempControlQueue) == std::vector<int>{1, 3});
	CHECK_FALSE(UploadBandwidthThrottlerSeams::RemoveSocketFromAllControlQueues(
		controlQueueFirst,
		controlQueue,
		tempControlQueueFirst,
		tempControlQueue,
		&removeMe));
}

TEST_CASE("Upload throttler seam clears all queue domains during shutdown cleanup")
{
	FakeSocket socketA{1};
	FakeSocket socketB{2};

	std::list<FakeSocket*> controlQueueFirst{&socketA};
	std::list<FakeSocket*> controlQueue{&socketB};
	std::list<FakeSocket*> tempControlQueueFirst{&socketB};
	std::list<FakeSocket*> tempControlQueue{&socketA};

	UploadBandwidthThrottlerSeams::ClearAllControlQueues(controlQueueFirst, controlQueue, tempControlQueueFirst, tempControlQueue);

	CHECK(controlQueueFirst.empty());
	CHECK(controlQueue.empty());
	CHECK(tempControlQueueFirst.empty());
	CHECK(tempControlQueue.empty());
}

TEST_SUITE_END;
