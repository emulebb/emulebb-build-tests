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

TEST_CASE("Server UDP DNS completion dispatches only known successful IPv4 results")
{
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(false, true, true, 0x01020304u) == UDPSocketSeams::EServerUdpDnsCompletion::UnknownRequest);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, false, false, 0u) == UDPSocketSeams::EServerUdpDnsCompletion::Failed);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, true, false, 0u) == UDPSocketSeams::EServerUdpDnsCompletion::NoAddress);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, true, true, 0xffffffffu) == UDPSocketSeams::EServerUdpDnsCompletion::NoAddress);
	CHECK(UDPSocketSeams::ClassifyDnsCompletion(true, true, true, 0x01020304u) == UDPSocketSeams::EServerUdpDnsCompletion::Resolved);
}

TEST_SUITE_END();
