#include "../third_party/doctest/doctest.h"

#ifndef ASSERT
#define ASSERT(expr) ((void)0)
#endif

#include "VpnGuardSeams.h"

TEST_SUITE_BEGIN("parity");

namespace
{
	uint32_t ParseIpv4ForTest(LPCTSTR pszAddress)
	{
		uint32_t uAddress = 0;
		REQUIRE(IPv4AddressSeams::TryParseIPv4Address(CString(pszAddress), uAddress));
		return uAddress;
	}
}

TEST_CASE("VPN Guard mode preference accepts only Off and Block")
{
	CHECK(VpnGuardSeams::ParseModePreferenceText(_T("Block")) == VpnGuardSeams::EMode::Block);
	CHECK(VpnGuardSeams::ParseModePreferenceText(_T("Warn")) == VpnGuardSeams::EMode::Off);
	CHECK(CString(VpnGuardSeams::GetModePreferenceText(VpnGuardSeams::EMode::Block)) == _T("Block"));
	CHECK(CString(VpnGuardSeams::GetModePreferenceText(VpnGuardSeams::EMode::Off)) == _T("Off"));
}

TEST_CASE("VPN Guard parses public CIDRs and single public IPv4 addresses")
{
	std::vector<VpnGuardSeams::SAllowedPublicIpv4Range> ranges;
	CString strError;

	CHECK(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("8.8.8.0/24, 1.1.1.1; 9.9.9.0/24"), ranges, strError));
	REQUIRE(ranges.size() == 3);
	CHECK(ranges[0].uPrefixLength == 24);
	CHECK(ranges[1].uPrefixLength == 32);
	CHECK(VpnGuardSeams::IsPublicIpv4Allowed(ParseIpv4ForTest(_T("8.8.8.8")), ranges));
	CHECK(VpnGuardSeams::IsPublicIpv4Allowed(ParseIpv4ForTest(_T("1.1.1.1")), ranges));
	CHECK_FALSE(VpnGuardSeams::IsPublicIpv4Allowed(ParseIpv4ForTest(_T("8.8.4.4")), ranges));
}

TEST_CASE("VPN Guard rejects empty malformed and non-public ranges")
{
	std::vector<VpnGuardSeams::SAllowedPublicIpv4Range> ranges;
	CString strError;

	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T(""), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("not-an-ip"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("8.8.8.0/33"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("10.0.0.0/8"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("127.0.0.1"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("169.254.1.1"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("192.168.1.0/24"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("224.0.0.0/4"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("203.0.113.0/24"), ranges, strError));
}

TEST_CASE("VPN Guard rejects public-looking ranges that overlap reserved space")
{
	std::vector<VpnGuardSeams::SAllowedPublicIpv4Range> ranges;
	CString strError;

	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("8.0.0.0/4"), ranges, strError));
	CHECK_FALSE(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("192.0.0.0/8"), ranges, strError));
	CHECK(VpnGuardSeams::TryParseAllowedPublicIpv4Ranges(_T("8.8.8.0/24"), ranges, strError));
}

TEST_SUITE_END();
