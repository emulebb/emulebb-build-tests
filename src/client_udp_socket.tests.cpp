#include "doctest.h"

#include "ClientUDPSocketSeams.h"

#include <climits>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Client UDP seam keeps normal packet failures verbose-only")
{
	const auto policy = ClientUDPSocketSeams::GetPacketFailureLogPolicy(false);

	CHECK(policy == ClientUDPSocketSeams::EUdpPacketFailureLogPolicy::VerboseOnly);
	CHECK_FALSE(ClientUDPSocketSeams::ShouldLogPacketFailure(false, policy));
	CHECK(ClientUDPSocketSeams::ShouldLogPacketFailure(true, policy));
}

TEST_CASE("Client UDP seam always logs unexpected packet exceptions")
{
	const auto policy = ClientUDPSocketSeams::GetPacketFailureLogPolicy(true);

	CHECK(policy == ClientUDPSocketSeams::EUdpPacketFailureLogPolicy::Always);
	CHECK(ClientUDPSocketSeams::ShouldLogPacketFailure(false, policy));
	CHECK(ClientUDPSocketSeams::ShouldLogPacketFailure(true, policy));
}

TEST_CASE("Client UDP seam only reads diagnostic opcode when packet contains it")
{
	const unsigned char packet[] = {0xC5, 0x91};
	unsigned char opcode = 0xFF;

	CHECK_FALSE(ClientUDPSocketSeams::TryGetPacketOpcodeForLog(nullptr, 2, opcode));
	CHECK(opcode == 0xFF);
	CHECK_FALSE(ClientUDPSocketSeams::TryGetPacketOpcodeForLog(packet, 0, opcode));
	CHECK(opcode == 0xFF);
	CHECK_FALSE(ClientUDPSocketSeams::TryGetPacketOpcodeForLog(packet, 1, opcode));
	CHECK(opcode == 0xFF);
	CHECK(ClientUDPSocketSeams::TryGetPacketOpcodeForLog(packet, 2, opcode));
	CHECK(opcode == 0x91);
}

TEST_CASE("Client UDP seam gates outgoing encryption on the global crypt preference")
{
	CHECK(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, true, true, false, 0u));
	CHECK(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, true, true, false));

	CHECK(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, true, false, true, 0x12345678u));
	CHECK(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, true, false, true));

	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(false, true, true, false, 0u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(false, true, false, true, 0x12345678u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, false, true, false));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, false, false, true));

	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, false, true, false, 0u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, true, false, true, 0u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, true, false, false));
}

TEST_CASE("Client UDP seam bounds queued outgoing control packets")
{
#ifdef EMULEBB_TEST_HAVE_CLIENT_UDP_SOCKET_FAILURE_SEAMS
	CHECK(ClientUDPSocketSeams::CanQueueOutgoingClientUdpControlPacket(0u));
	CHECK(ClientUDPSocketSeams::CanQueueOutgoingClientUdpControlPacket(ClientUDPSocketSeams::kMaxOutgoingClientUdpControlQueuePackets - 1u));
	CHECK_FALSE(ClientUDPSocketSeams::CanQueueOutgoingClientUdpControlPacket(ClientUDPSocketSeams::kMaxOutgoingClientUdpControlQueuePackets));
	CHECK_FALSE(ClientUDPSocketSeams::CanQueueOutgoingClientUdpControlPacket(ClientUDPSocketSeams::kMaxOutgoingClientUdpControlQueuePackets + 1u));
#else
	MESSAGE("Client UDP outgoing control queue limit helper is not available in this workspace.");
#endif
}

TEST_CASE("Client UDP seam checks datagram allocation and socket lengths together")
{
#ifdef EMULEBB_TEST_HAVE_CLIENT_UDP_SOCKET_FAILURE_SEAMS
	uint32_t plainPacketSize = 0;
	size_t allocationSize = 0;
	int socketSendSize = 0;

	CHECK(ClientUDPSocketSeams::TryGetOutgoingClientUdpPacketSize(
		42u,
		16u,
		&plainPacketSize,
		&allocationSize,
		&socketSendSize));
	CHECK_EQ(plainPacketSize, static_cast<uint32_t>(44u));
	CHECK_EQ(allocationSize, static_cast<size_t>(60u));
	CHECK_EQ(socketSendSize, 44);

	CHECK_FALSE(ClientUDPSocketSeams::TryGetOutgoingClientUdpPacketSize(UINT32_MAX - 1u, 0u, &plainPacketSize, &allocationSize, &socketSendSize));
	CHECK_FALSE(ClientUDPSocketSeams::TryGetOutgoingClientUdpPacketSize(static_cast<uint32_t>(INT_MAX), 0u, &plainPacketSize, &allocationSize, &socketSendSize));
	CHECK_FALSE(ClientUDPSocketSeams::TryGetOutgoingClientUdpPacketSize(1u, static_cast<size_t>(INT_MAX), &plainPacketSize, &allocationSize, &socketSendSize));
	CHECK_FALSE(ClientUDPSocketSeams::TryGetOutgoingClientUdpPacketSize(1u, 0u, NULL, &allocationSize, &socketSendSize));
#else
	MESSAGE("Client UDP outgoing datagram sizing helper is not available in this workspace.");
#endif
}

TEST_SUITE_END();
