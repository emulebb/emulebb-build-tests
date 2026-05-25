#include "doctest.h"

#include "WindowsFirewallRepairSeams.h"

TEST_SUITE_BEGIN("windows_firewall_repair");

TEST_CASE("firewall repair seam builds broad inbound and outbound TCP UDP rules")
{
	const std::vector<WindowsFirewallRepairSeams::CFirewallRuleSpec> rules =
		WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, true, 4711, _T(""));

	REQUIRE(rules.size() == 4);
	CHECK(rules[0].strName == _T("eMuleBB Inbound TCP"));
	CHECK(rules[0].strDirection == _T("Inbound"));
	CHECK(rules[0].strProtocol == _T("TCP"));
	CHECK(rules[1].strName == _T("eMuleBB Inbound UDP"));
	CHECK(rules[1].strDirection == _T("Inbound"));
	CHECK(rules[1].strProtocol == _T("UDP"));
	CHECK(rules[2].strName == _T("eMuleBB Outbound TCP"));
	CHECK(rules[2].strDirection == _T("Outbound"));
	CHECK(rules[2].strProtocol == _T("TCP"));
	CHECK(rules[3].strName == _T("eMuleBB Outbound UDP"));
	CHECK(rules[3].strDirection == _T("Outbound"));
	CHECK(rules[3].strProtocol == _T("UDP"));
}

TEST_CASE("firewall repair seam ignores current listen and REST ports")
{
	CHECK(WindowsFirewallRepairSeams::BuildDesiredRules(0, 70000, true, 4711, _T("127.0.0.1")).size() == 4);
	CHECK(WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, true, 4711, _T("localhost")).size() == 4);
	CHECK(WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, false, 4711, _T("0.0.0.0")).size() == 4);
}

TEST_SUITE_END();
