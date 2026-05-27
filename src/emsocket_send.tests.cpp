#include "../third_party/doctest/doctest.h"

#include "TestSupport.h"
#include "EMSocketSendSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("EMSocket queue-state helper classifies empty, control, standard, and mixed queues")
{
	CHECK_EQ(ClassifyEMSocketQueueState(false, false, false), static_cast<unsigned>(emSocketQueueNone));
	CHECK_EQ(ClassifyEMSocketQueueState(false, true, false), static_cast<unsigned>(emSocketQueueHasControlPackets));
	CHECK_EQ(ClassifyEMSocketQueueState(false, false, true), static_cast<unsigned>(emSocketQueueHasStandardPackets));
	CHECK_EQ(ClassifyEMSocketQueueState(true, true, true), static_cast<unsigned>(emSocketQueueHasSendBuffer | emSocketQueueHasControlPackets | emSocketQueueHasStandardPackets));
}

TEST_CASE("EMSocket queue-state helper honors the standard-only filter")
{
	const unsigned nControlOnly = ClassifyEMSocketQueueState(false, true, false);
	const unsigned nStandardOnly = ClassifyEMSocketQueueState(false, false, true);
	const unsigned nBufferedStandard = ClassifyEMSocketQueueState(true, false, false);

	CHECK(HasEMSocketQueuedPackets(nControlOnly, false));
	CHECK_FALSE(HasEMSocketQueuedPackets(nControlOnly, true));
	CHECK(HasEMSocketQueuedPackets(nStandardOnly, true));
	CHECK(HasEMSocketQueuedPackets(nBufferedStandard, true));
}

TEST_CASE("EMSocket payload helper reports when queued payload still falls below the target")
{
	std::uint32_t nRemainingPayload = 1024u;
	CHECK(ConsumeQueuedFilePayload(256u, &nRemainingPayload));
	CHECK_EQ(nRemainingPayload, static_cast<std::uint32_t>(768));
	CHECK(ConsumeQueuedFilePayload(768u, &nRemainingPayload));
	CHECK_EQ(nRemainingPayload, static_cast<std::uint32_t>(0));

	nRemainingPayload = 512u;
	CHECK_FALSE(ConsumeQueuedFilePayload(1024u, &nRemainingPayload));
	CHECK_EQ(nRemainingPayload, static_cast<std::uint32_t>(512));
}

TEST_CASE("EMSocket overlapped cleanup retry helper retries only for incomplete results with budget left")
{
	CHECK(ShouldRetryOverlappedCleanupProbe(ERROR_IO_INCOMPLETE, 1));
	CHECK_FALSE(ShouldRetryOverlappedCleanupProbe(ERROR_IO_INCOMPLETE, 0));
	CHECK_FALSE(ShouldRetryOverlappedCleanupProbe(ERROR_OPERATION_ABORTED, 1));
}

TEST_CASE("EMSocket send queue budget helpers bound packet counts and bytes")
{
	CHECK(CanQueueEMSocketControlPacket(0u, 0u, 128u));
	CHECK(CanQueueEMSocketControlPacket(kMaxEMSocketQueuedControlPackets - 1u, kMaxEMSocketQueuedControlBytes - 128u, 128u));
	CHECK_FALSE(CanQueueEMSocketControlPacket(kMaxEMSocketQueuedControlPackets, 0u, 128u));
	CHECK_FALSE(CanQueueEMSocketControlPacket(0u, kMaxEMSocketQueuedControlBytes, 1u));
	CHECK_FALSE(CanQueueEMSocketControlPacket(0u, 0u, static_cast<uint32>(kMaxEMSocketQueuedControlBytes + 1u)));

	CHECK(CanQueueEMSocketStandardPacket(0u, 0u, 1024u));
	CHECK(CanQueueEMSocketStandardPacket(kMaxEMSocketQueuedStandardPackets - 1u, kMaxEMSocketQueuedStandardBytes - 1024u, 1024u));
	CHECK_FALSE(CanQueueEMSocketStandardPacket(kMaxEMSocketQueuedStandardPackets, 0u, 1024u));
	CHECK_FALSE(CanQueueEMSocketStandardPacket(0u, kMaxEMSocketQueuedStandardBytes, 1u));
	CHECK_FALSE(CanQueueEMSocketStandardPacket(0u, 0u, static_cast<uint32>(kMaxEMSocketQueuedStandardBytes + 1u)));
}

TEST_CASE("EMSocket overlapped send helper recognizes borrowed sendbuffer slices")
{
	char buffer[16] = {};

	CHECK(CanBorrowOverlappedSendBufferSlice(0u, 16u, 16u));
	CHECK(CanBorrowOverlappedSendBufferSlice(8u, 8u, 16u));
	CHECK_FALSE(CanBorrowOverlappedSendBufferSlice(8u, 9u, 16u));
	CHECK_FALSE(CanBorrowOverlappedSendBufferSlice(17u, 1u, 16u));
	CHECK_FALSE(CanBorrowOverlappedSendBufferSlice(0u, 0u, 16u));

	CHECK(IsBorrowedOverlappedSendBufferSlice(buffer, buffer, sizeof buffer));
	CHECK(IsBorrowedOverlappedSendBufferSlice(buffer + 15, buffer, sizeof buffer));
	CHECK_FALSE(IsBorrowedOverlappedSendBufferSlice(buffer + 16, buffer, sizeof buffer));
	CHECK_FALSE(IsBorrowedOverlappedSendBufferSlice(NULL, buffer, sizeof buffer));
	CHECK_FALSE(IsBorrowedOverlappedSendBufferSlice(buffer, NULL, sizeof buffer));
}

TEST_SUITE_END;
