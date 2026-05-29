#include "../third_party/doctest/doctest.h"

#ifndef ASSERT
#define ASSERT(expr) ((void)0)
#endif

#include "BindStartupPolicy.h"

TEST_SUITE_BEGIN("parity");

namespace
{
#ifdef EMULEBB_BIND_STARTUP_POLICY_USES_EXTERNAL_TEXT
	BindStartupPolicy::CBindStartupPolicyText GetBindStartupPolicyTextForTest()
	{
		BindStartupPolicy::CBindStartupPolicyText text;
		text.strAnyInterface = _T("Any interface");
		text.strInterfaceNotFoundFormat = _T("Networking disabled for this session because the selected bind interface is no longer available: %s");
		text.strInterfaceNameAmbiguousFormat = _T("Networking disabled for this session because the selected bind interface name matches multiple live adapters: %s");
		text.strInterfaceHasNoAddressFormat = _T("Networking disabled for this session because the selected bind interface has no usable IPv4 address: %s");
		text.strAddressNotFoundOnInterfaceFormat = _T("Networking disabled for this session because the selected bind IP is no longer present on the selected interface: %s");
		text.strAddressNotFoundFormat = _T("Networking disabled for this session because the selected bind IP is no longer present on any live interface: %s");
		return text;
	}
#endif

	CString FormatStartupBlockReasonForTest(const CString &strInterfaceName
		, const CString &strInterfaceId
		, const CString &strConfiguredAddress
		, EBindAddressResolveResult eResult)
	{
#ifdef EMULEBB_BIND_STARTUP_POLICY_USES_EXTERNAL_TEXT
		return BindStartupPolicy::FormatStartupBlockReason(strInterfaceName, strInterfaceId, strConfiguredAddress, eResult, GetBindStartupPolicyTextForTest());
#else
		return BindStartupPolicy::FormatStartupBlockReason(strInterfaceName, strInterfaceId, strConfiguredAddress, eResult);
#endif
	}
}

TEST_CASE("Startup bind policy allows the default interface selection")
{
	CHECK_FALSE(BindStartupPolicy::HasExplicitBindSelection(CString(), CString()));
	CHECK_FALSE(BindStartupPolicy::ShouldBlockSessionNetworking(false, CString(), CString(), BARR_Default));
	CHECK(FormatStartupBlockReasonForTest(CString(), CString(), CString(), BARR_Default).IsEmpty());
}

TEST_CASE("Startup bind policy blocks an explicit interface when it disappears")
{
	const CString strInterfaceId(_T("vpn-if-guid"));
	const CString strInterfaceName(_T("My VPN"));

	CHECK(BindStartupPolicy::HasExplicitBindSelection(strInterfaceId, CString()));
	CHECK(BindStartupPolicy::ShouldBlockSessionNetworking(true, strInterfaceId, CString(), BARR_InterfaceNotFound));
	CHECK_FALSE(BindStartupPolicy::ShouldBlockSessionNetworking(false, strInterfaceId, CString(), BARR_InterfaceNotFound));
	CHECK(FormatStartupBlockReasonForTest(strInterfaceName, strInterfaceId, CString(), BARR_InterfaceNotFound)
		== CString(_T("Networking disabled for this session because the selected bind interface is no longer available: My VPN")));
}

TEST_CASE("Startup bind policy blocks a selected IP that vanished from the chosen interface")
{
	const CString strInterfaceId(_T("vpn-if-guid"));
	const CString strInterfaceName(_T("My VPN"));
	const CString strAddress(_T("10.54.218.144"));

	CHECK(BindStartupPolicy::ShouldBlockSessionNetworking(true, strInterfaceId, strAddress, BARR_AddressNotFoundOnInterface));
	CHECK(FormatStartupBlockReasonForTest(strInterfaceName, strInterfaceId, strAddress, BARR_AddressNotFoundOnInterface)
		== CString(_T("Networking disabled for this session because the selected bind IP is no longer present on the selected interface: My VPN / 10.54.218.144")));
}

TEST_CASE("Startup bind policy blocks an address-only selection that is missing everywhere")
{
	const CString strAddress(_T("10.54.218.144"));

	CHECK(BindStartupPolicy::ShouldBlockSessionNetworking(true, CString(), strAddress, BARR_AddressNotFound));
	CHECK(FormatStartupBlockReasonForTest(CString(), CString(), strAddress, BARR_AddressNotFound)
		== CString(_T("Networking disabled for this session because the selected bind IP is no longer present on any live interface: Any interface / 10.54.218.144")));
}
