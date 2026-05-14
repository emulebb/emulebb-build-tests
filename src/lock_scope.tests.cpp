#include "../third_party/doctest/doctest.h"

#include "TestSupport.h"
#include "LockScopeSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("UDP control send continues only while queued data can be drained")
{
	CHECK(ShouldContinueUdpControlSend(false, false, 0u, 1024u));
	CHECK_FALSE(ShouldContinueUdpControlSend(true, false, 0u, 1024u));
	CHECK_FALSE(ShouldContinueUdpControlSend(false, true, 0u, 1024u));
	CHECK_FALSE(ShouldContinueUdpControlSend(false, false, 1024u, 1024u));
}

TEST_CASE("UDP control packet expiry uses wrap-safe tick arithmetic")
{
	CHECK(HasUdpControlPacketExpired(5000u, 1000u, 4000u));
	CHECK_FALSE(HasUdpControlPacketExpired(4999u, 1000u, 4000u));
	CHECK(HasUdpControlPacketExpired(10u, 0xFFFFFFF0u, 16u));
}

TEST_CASE("UDP control send requeue only retries would-block results")
{
	CHECK(ShouldRequeueUdpControlPacket(-1));
	CHECK_FALSE(ShouldRequeueUdpControlPacket(0));
	CHECK_FALSE(ShouldRequeueUdpControlPacket(42));
}

TEST_CASE("UDP control send stops the current drain after requeueing a would-block packet")
{
	CHECK(ShouldYieldAfterUdpControlRequeue(-1));
	CHECK_FALSE(ShouldYieldAfterUdpControlRequeue(0));
	CHECK_FALSE(ShouldYieldAfterUdpControlRequeue(42));
}

TEST_CASE("UDP control queue wakeups only happen when a queued packet can be sent")
{
	CHECK(ShouldSignalUdpControlQueue(false, false));
	CHECK_FALSE(ShouldSignalUdpControlQueue(true, false));
	CHECK_FALSE(ShouldSignalUdpControlQueue(false, true));
}

TEST_CASE("UDP control queue wakeups are deferred until after the socket lock is released")
{
	CHECK(ClassifyUdpControlQueueSignal(false, false) == udpControlQueueSignalAfterUnlock);
	CHECK(ClassifyUdpControlQueueSignal(true, false) == udpControlQueueNoSignal);
	CHECK(ClassifyUdpControlQueueSignal(false, true) == udpControlQueueNoSignal);
}

TEST_CASE("Upload disk completion classification separates send, IO error, and discard")
{
	CHECK(ClassifyUploadDiskReadCompletion(uploadQueueEntryLive, false) == uploadDiskReadCompletionSendPackets);
	CHECK(ClassifyUploadDiskReadCompletion(uploadQueueEntryLive, true) == uploadDiskReadCompletionMarkIoError);
	CHECK(ClassifyUploadDiskReadCompletion(uploadQueueEntryRetired, false) == uploadDiskReadCompletionDiscard);
	CHECK(ClassifyUploadDiskReadCompletion(uploadQueueEntryMissing, false) == uploadDiskReadCompletionDiscard);
}

TEST_SUITE_END;
