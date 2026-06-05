#include "../third_party/doctest/doctest.h"

#ifndef ASSERT
#define ASSERT(expr) ((void)0)
#endif

#include "StatusBarInfo.h"

TEST_SUITE_BEGIN("status_bar");

namespace
{
	CString FormatNetworkAddressPaneTextForTest(const CString &strBindAddress, uint32 dwPublicIp, uint16 uInboundTcpPort = 0, bool bNetworkAddressBlocked = false)
	{
#ifdef EMULEBB_STATUS_BAR_INFO_USES_EXTERNAL_TEXT
		return StatusBarInfo::FormatNetworkAddressPaneText(strBindAddress
			, dwPublicIp
			, CString(_T("B"))
			, CString(_T("P"))
			, CString(_T("Any"))
			, CString(_T("?"))
			, CString(_T("%s:%s|%s:%s"))
			, uInboundTcpPort
			, bNetworkAddressBlocked);
#else
		return StatusBarInfo::FormatNetworkAddressPaneText(strBindAddress, dwPublicIp, uInboundTcpPort, bNetworkAddressBlocked);
#endif
	}

	CString FormatNetworkAddressPaneToolTipForTest(const CString &strBindAddress, uint32 dwPublicIp, uint16 uInboundTcpPort = 0, bool bNetworkAddressBlocked = false)
	{
#ifdef EMULEBB_STATUS_BAR_INFO_USES_EXTERNAL_TEXT
		return StatusBarInfo::FormatNetworkAddressPaneToolTip(strBindAddress
			, dwPublicIp
			, CString(_T("Bind IP"))
			, CString(_T("Public IP"))
			, CString(_T("Any interface"))
			, CString(_T("Unknown"))
			, CString(_T("%s: %s | %s: %s"))
			, uInboundTcpPort
			, bNetworkAddressBlocked);
#else
		return StatusBarInfo::FormatNetworkAddressPaneToolTip(strBindAddress, dwPublicIp, uInboundTcpPort, bNetworkAddressBlocked);
#endif
	}
}

TEST_CASE("Status bar IP pane uses compact placeholders for default bind and unknown public IP")
{
	CHECK(FormatNetworkAddressPaneTextForTest(CString(), 0) == CString(_T("B:Any|P:?")));
	CHECK(FormatNetworkAddressPaneToolTipForTest(CString(), 0) == CString(_T("Bind IP: Any interface | Public IP: Unknown")));
}

TEST_CASE("Status bar IP pane formats both bind and public IPv4 addresses")
{
	const CString strBindAddress(_T("10.54.218.144"));
	const uint32 dwPublicIp = 203u | (0u << 8) | (113u << 16) | (7u << 24);

	CHECK(StatusBarInfo::Detail::FormatStoredIPv4Address(dwPublicIp) == CString(_T("203.0.113.7")));
	CHECK(FormatNetworkAddressPaneTextForTest(strBindAddress, dwPublicIp) == CString(_T("B:10.54.218.144|P:203.0.113.7")));
	CHECK(FormatNetworkAddressPaneToolTipForTest(strBindAddress, dwPublicIp) == CString(_T("Bind IP: 10.54.218.144 | Public IP: 203.0.113.7")));
}

TEST_CASE("Status bar IP pane includes the inbound TCP port when public IP is known")
{
	const CString strBindAddress(_T("10.54.218.144"));
	const uint32 dwPublicIp = 203u | (0u << 8) | (113u << 16) | (7u << 24);

	CHECK(FormatNetworkAddressPaneTextForTest(strBindAddress, dwPublicIp, 2123) == CString(_T("B:10.54.218.144|P:203.0.113.7:2123")));
	CHECK(FormatNetworkAddressPaneToolTipForTest(strBindAddress, dwPublicIp, 2123) == CString(_T("Bind IP: 10.54.218.144 | Public IP: 203.0.113.7:2123")));
}

TEST_CASE("Status bar IP pane keeps a known bind address when public IP is still pending")
{
	const CString strBindAddress(_T("192.168.50.12"));

	CHECK(FormatNetworkAddressPaneTextForTest(strBindAddress, 0) == CString(_T("B:192.168.50.12|P:?")));
	CHECK(FormatNetworkAddressPaneToolTipForTest(strBindAddress, 0) == CString(_T("Bind IP: 192.168.50.12 | Public IP: Unknown")));
}

TEST_CASE("Status bar IP pane shows binding and public address as KO when VPN Guard blocks")
{
	const CString strBindAddress(_T("10.54.218.144"));
	const uint32 dwPublicIp = 203u | (0u << 8) | (113u << 16) | (7u << 24);

	CHECK(FormatNetworkAddressPaneTextForTest(strBindAddress, dwPublicIp, 2123, true) == CString(_T("B:-|P:-")));
	CHECK(FormatNetworkAddressPaneToolTipForTest(strBindAddress, dwPublicIp, 2123, true) == CString(_T("Bind IP: - | Public IP: -")));
}
