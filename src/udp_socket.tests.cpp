#include "doctest.h"

#include "UDPSocketSeams.h"

#include <climits>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Server UDP seam keeps normal packet failures verbose-only")
{
	const auto policy = UDPSocketSeams::GetPacketFailureLogPolicy(false);

	CHECK(policy == UDPSocketSeams::EServerUdpPacketFailureLogPolicy::VerboseOnly);
	CHECK_FALSE(UDPSocketSeams::ShouldLogPacketFailure(false, policy));
	CHECK(UDPSocketSeams::ShouldLogPacketFailure(true, policy));
}

TEST_CASE("Server UDP seam always logs unexpected packet exceptions")
{
	const auto policy = UDPSocketSeams::GetPacketFailureLogPolicy(true);

	CHECK(policy == UDPSocketSeams::EServerUdpPacketFailureLogPolicy::Always);
	CHECK(UDPSocketSeams::ShouldLogPacketFailure(false, policy));
	CHECK(UDPSocketSeams::ShouldLogPacketFailure(true, policy));
}

TEST_CASE("Server UDP DNS completion dispatches only known successful IPv4 results")
{
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(false, true, true, 0x01020304u) == UDPSocketSeams::EServerUdpDnsCompletion::UnknownRequest);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, false, false, 0u) == UDPSocketSeams::EServerUdpDnsCompletion::Failed);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, true, false, 0u) == UDPSocketSeams::EServerUdpDnsCompletion::NoAddress);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, true, true, 0xffffffffu) == UDPSocketSeams::EServerUdpDnsCompletion::NoAddress);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, true, true, 0x01020304u) == UDPSocketSeams::EServerUdpDnsCompletion::Resolved);
}

TEST_CASE("Server UDP seam bounds queued outgoing control packets")
{
	CHECK(UDPSocketSeams::CanQueueOutgoingServerUdpControlPacket(0u));
	CHECK(UDPSocketSeams::CanQueueOutgoingServerUdpControlPacket(UDPSocketSeams::kMaxOutgoingServerUdpControlQueuePackets - 1u));
	CHECK_FALSE(UDPSocketSeams::CanQueueOutgoingServerUdpControlPacket(UDPSocketSeams::kMaxOutgoingServerUdpControlQueuePackets));
	CHECK_FALSE(UDPSocketSeams::CanQueueOutgoingServerUdpControlPacket(UDPSocketSeams::kMaxOutgoingServerUdpControlQueuePackets + 1u));
}

TEST_CASE("Server UDP seam checks datagram allocation and socket lengths together")
{
	uint32_t plainPacketSize = 0;
	size_t allocationSize = 0;
	int socketSendSize = 0;

	CHECK(UDPSocketSeams::TryGetOutgoingServerUdpPacketSize(
		42u,
		16u,
		&plainPacketSize,
		&allocationSize,
		&socketSendSize));
	CHECK_EQ(plainPacketSize, static_cast<uint32_t>(44u));
	CHECK_EQ(allocationSize, static_cast<size_t>(60u));
	CHECK_EQ(socketSendSize, 44);

	CHECK_FALSE(UDPSocketSeams::TryGetOutgoingServerUdpPacketSize(UINT32_MAX - 1u, 0u, &plainPacketSize, &allocationSize, &socketSendSize));
	CHECK_FALSE(UDPSocketSeams::TryGetOutgoingServerUdpPacketSize(static_cast<uint32_t>(INT_MAX), 0u, &plainPacketSize, &allocationSize, &socketSendSize));
	CHECK_FALSE(UDPSocketSeams::TryGetOutgoingServerUdpPacketSize(1u, static_cast<size_t>(INT_MAX), &plainPacketSize, &allocationSize, &socketSendSize));
	CHECK_FALSE(UDPSocketSeams::TryGetOutgoingServerUdpPacketSize(1u, 0u, NULL, &allocationSize, &socketSendSize));

	CHECK(UDPSocketSeams::CanQueueRawServerUdpPacketSize(static_cast<uint32_t>(INT_MAX)));
	CHECK_FALSE(UDPSocketSeams::CanQueueRawServerUdpPacketSize(static_cast<uint32_t>(INT_MAX) + 1u));
}

TEST_CASE("Server UDP DNS seam bounds packets held outside the main queue")
{
	CHECK(UDPSocketSeams::CanQueueServerUdpDnsPacket(0u, 0u, 128u));
	CHECK(UDPSocketSeams::CanQueueServerUdpDnsPacket(
		UDPSocketSeams::kMaxServerUdpDnsPacketsPerRequest - 1u,
		UDPSocketSeams::kMaxServerUdpDnsBytesPerRequest - 128u,
		128u));
	CHECK_FALSE(UDPSocketSeams::CanQueueServerUdpDnsPacket(UDPSocketSeams::kMaxServerUdpDnsPacketsPerRequest, 0u, 1u));
	CHECK_FALSE(UDPSocketSeams::CanQueueServerUdpDnsPacket(0u, UDPSocketSeams::kMaxServerUdpDnsBytesPerRequest, 1u));
	CHECK_FALSE(UDPSocketSeams::CanQueueServerUdpDnsPacket(0u, 0u, static_cast<uint32_t>(UDPSocketSeams::kMaxServerUdpDnsBytesPerRequest + 1u)));
}

TEST_SUITE_END();
