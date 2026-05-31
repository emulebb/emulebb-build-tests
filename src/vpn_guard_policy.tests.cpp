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

TEST_CASE("VPN Guard startup connection commands wait for runtime monitor arming")
{
	CHECK_FALSE(VpnGuardPolicySeams::IsRuntimeMonitorRequired(VpnGuardSeams::EMode::Off, false));
	CHECK_FALSE(VpnGuardPolicySeams::IsRuntimeMonitorRequired(VpnGuardSeams::EMode::Block, true));
	CHECK(VpnGuardPolicySeams::IsRuntimeMonitorRequired(VpnGuardSeams::EMode::Block, false));

	CHECK(VpnGuardPolicySeams::CanUseP2PConnectionCommands(VpnGuardSeams::EMode::Off, false, false));
	CHECK_FALSE(VpnGuardPolicySeams::CanUseP2PConnectionCommands(VpnGuardSeams::EMode::Block, false, false));
	CHECK(VpnGuardPolicySeams::CanUseP2PConnectionCommands(VpnGuardSeams::EMode::Block, false, true));
	CHECK_FALSE(VpnGuardPolicySeams::CanUseP2PConnectionCommands(VpnGuardSeams::EMode::Block, true, true));

	CHECK(VpnGuardPolicySeams::CanUseStartupConnectionCommands(VpnGuardSeams::EMode::Off, false, false));
	CHECK_FALSE(VpnGuardPolicySeams::CanUseStartupConnectionCommands(VpnGuardSeams::EMode::Block, false, false));
	CHECK(VpnGuardPolicySeams::CanUseStartupConnectionCommands(VpnGuardSeams::EMode::Block, false, true));
	CHECK_FALSE(VpnGuardPolicySeams::CanUseStartupConnectionCommands(VpnGuardSeams::EMode::Block, true, true));
}

TEST_CASE("VPN Guard startup auto-connect posts only after runtime monitor arming")
{
	CHECK_FALSE(VpnGuardPolicySeams::CanPostStartupAutoConnect(false, VpnGuardSeams::EMode::Off, false, false));
	CHECK(VpnGuardPolicySeams::CanPostStartupAutoConnect(true, VpnGuardSeams::EMode::Off, false, false));
	CHECK_FALSE(VpnGuardPolicySeams::CanPostStartupAutoConnect(true, VpnGuardSeams::EMode::Block, false, false));
	CHECK(VpnGuardPolicySeams::CanPostStartupAutoConnect(true, VpnGuardSeams::EMode::Block, false, true));
	CHECK_FALSE(VpnGuardPolicySeams::CanPostStartupAutoConnect(true, VpnGuardSeams::EMode::Block, true, true));
}

TEST_CASE("VPN Guard failure action blocks startup but exits at runtime")
{
	CHECK(VpnGuardPolicySeams::GetFailureAction(false) == VpnGuardPolicySeams::EFailureAction::BlockStartup);
	CHECK(VpnGuardPolicySeams::GetFailureAction(true) == VpnGuardPolicySeams::EFailureAction::ExitApplication);
}

TEST_SUITE_END();
