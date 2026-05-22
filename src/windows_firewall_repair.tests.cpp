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

TEST_CASE("firewall repair seam safely quotes PowerShell literals")
{
	CHECK(WindowsFirewallRepairSeams::QuotePowerShellSingleQuotedLiteral(_T("C:\\Users\\O'Brien\\emulebb.exe"))
		== _T("'C:\\Users\\O''Brien\\emulebb.exe'"));
}

TEST_CASE("firewall repair script owns broad rule names and all firewall profiles")
{
	const std::vector<WindowsFirewallRepairSeams::CFirewallRuleSpec> rules =
		WindowsFirewallRepairSeams::BuildDesiredRules(4662, 4672, true, 4711, _T("0.0.0.0"));
	const CString script = WindowsFirewallRepairSeams::BuildRepairScript(
		_T("C:\\Apps\\eMuleBB\\emulebb.exe"),
		rules,
		_T("C:\\Temp\\repair-result.json"));

	CHECK(script.Find(_T("eMuleBB Inbound TCP")) >= 0);
	CHECK(script.Find(_T("eMuleBB Inbound UDP")) >= 0);
	CHECK(script.Find(_T("eMuleBB Outbound TCP")) >= 0);
	CHECK(script.Find(_T("eMuleBB Outbound UDP")) >= 0);
	CHECK(script.Find(_T("eMuleBB REST")) < 0);
	CHECK(script.Find(_T("-Profile Domain,Private,Public")) >= 0);
	CHECK(script.Find(_T("-Direction $Direction")) >= 0);
	CHECK(script.Find(_T("-Protocol $Protocol")) >= 0);
	CHECK(script.Find(_T("-LocalPort")) < 0);
	CHECK(script.Find(_T("-RemotePort")) < 0);
	CHECK(script.Find(_T("Write-Host 'eMuleBB Windows Firewall Repair'")) >= 0);
	CHECK(script.Find(_T("all ports, all hosts, all interfaces")) >= 0);
	CHECK(script.Find(_T("Windows Firewall repair completed successfully.")) >= 0);
	CHECK(script.Find(_T("Press Enter to close this window")) >= 0);
	CHECK(script.Find(_T("Remove-NetFirewallRule")) >= 0);
	CHECK(script.Find(_T("New-NetFirewallRule")) >= 0);
	CHECK(script.Find(_T("ConvertTo-Json")) >= 0);
	CHECK(script.Find(_T("localPort = 'Any'")) >= 0);
	CHECK(script.Find(_T("remotePort = 'Any'")) >= 0);
	CHECK(script.Find(_T("localAddress = 'Any'")) >= 0);
	CHECK(script.Find(_T("remoteAddress = 'Any'")) >= 0);
}

TEST_SUITE_END();
