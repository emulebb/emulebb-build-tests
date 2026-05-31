#include "../third_party/doctest/doctest.h"

#include "VpnGuardPolicySeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("VPN Guard startup probe runs only for unblocked unapproved Block mode")
{
	CHECK(VpnGuardPolicySeams::ShouldRunStartupProbe(VpnGuardSeams::EMode::Block, false, false));
	CHECK_FALSE(VpnGuardPolicySeams::ShouldRunStartupProbe(VpnGuardSeams::EMode::Off, false, false));
	CHECK_FALSE(VpnGuardPolicySeams::ShouldRunStartupProbe(VpnGuardSeams::EMode::Block, true, false));
	CHECK_FALSE(VpnGuardPolicySeams::ShouldRunStartupProbe(VpnGuardSeams::EMode::Block, false, true));
}

TEST_CASE("VPN Guard public IP probe allows only successful CIDR matches")
{
	CHECK(VpnGuardPolicySeams::IsProbeResultAllowed(true, true));
	CHECK_FALSE(VpnGuardPolicySeams::IsProbeResultAllowed(true, false));
	CHECK_FALSE(VpnGuardPolicySeams::IsProbeResultAllowed(false, true));
	CHECK_FALSE(VpnGuardPolicySeams::IsProbeResultAllowed(false, false));
}

TEST_CASE("VPN Guard failure action blocks startup but exits at runtime")
{
	CHECK(VpnGuardPolicySeams::GetFailureAction(false) == VpnGuardPolicySeams::EFailureAction::BlockStartup);
	CHECK(VpnGuardPolicySeams::GetFailureAction(true) == VpnGuardPolicySeams::EFailureAction::ExitApplication);
}

TEST_SUITE_END();
