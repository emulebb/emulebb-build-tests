#include "doctest.h"

#include "UDPSocketSeams.h"

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

TEST_SUITE_END();
