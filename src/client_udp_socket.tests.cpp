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

TEST_SUITE_END();
