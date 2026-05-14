#include "doctest.h"

#include "WindowsFirewallRepairSeams.h"

TEST_SUITE_BEGIN("windows_firewall_repair");

TEST_CASE("firewall repair seam builds P2P and externally reachable REST rules")
{
	const std::vector<WindowsFirewallRepairSeams::CFirewallRuleSpec> rules =
		WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, true, 4711, _T(""));

	REQUIRE(rules.size() == 3);
	CHECK(rules[0].strName == _T("eMule BB TCP"));
	CHECK(rules[0].strProtocol == _T("TCP"));
	CHECK(rules[0].uPort == 4662);
	CHECK(rules[1].strName == _T("eMule BB UDP"));
	CHECK(rules[1].strProtocol == _T("UDP"));
	CHECK(rules[1].uPort == 4672);
	CHECK(rules[2].strName == _T("eMule BB REST"));
	CHECK(rules[2].strProtocol == _T("TCP"));
	CHECK(rules[2].uPort == 4711);
}

TEST_CASE("firewall repair seam skips invalid ports and localhost-only REST")
{
	CHECK(WindowsFirewallRepairSeams::BuildDesiredRules(0, 70000, true, 4711, _T("127.0.0.1")).empty());
	CHECK(WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, true, 4711, _T("localhost")).size() == 2);
	CHECK(WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, false, 4711, _T("0.0.0.0")).size() == 2);
}

TEST_CASE("firewall repair seam safely quotes PowerShell literals")
{
	CHECK(WindowsFirewallRepairSeams::QuotePowerShellSingleQuotedLiteral(_T("C:\\Users\\O'Brien\\emule.exe"))
		== _T("'C:\\Users\\O''Brien\\emule.exe'"));
}

TEST_CASE("firewall repair script owns stable rule names and all firewall profiles")
{
	const std::vector<WindowsFirewallRepairSeams::CFirewallRuleSpec> rules =
		WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, true, 4711, _T("0.0.0.0"));
	const CString script = WindowsFirewallRepairSeams::BuildRepairScript(
		_T("C:\\Apps\\eMule BB\\emule.exe"),
		rules,
		_T("C:\\Temp\\repair-result.json"));

	CHECK(script.Find(_T("eMule BB TCP")) >= 0);
	CHECK(script.Find(_T("eMule BB UDP")) >= 0);
	CHECK(script.Find(_T("eMule BB REST")) >= 0);
	CHECK(script.Find(_T("-Profile Domain,Private,Public")) >= 0);
	CHECK(script.Find(_T("Remove-NetFirewallRule")) >= 0);
	CHECK(script.Find(_T("New-NetFirewallRule")) >= 0);
	CHECK(script.Find(_T("ConvertTo-Json")) >= 0);
}

TEST_SUITE_END();
