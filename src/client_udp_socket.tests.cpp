#include "doctest.h"

#include "ClientUDPSocketSeams.h"

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

TEST_SUITE_END();
