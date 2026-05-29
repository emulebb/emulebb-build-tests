#include "../third_party/doctest/doctest.h"

#ifndef ASSERT
#define ASSERT(expr) ((void)0)
#endif

#include "BindRuntimeLossPolicy.h"

TEST_SUITE_BEGIN("parity");

namespace
{
#ifdef EMULEBB_BIND_RUNTIME_LOSS_POLICY_USES_EXTERNAL_TEXT
	BindRuntimeLossPolicy::CBindRuntimeLossPolicyText GetBindRuntimeLossPolicyTextForTest()
	{
		BindRuntimeLossPolicy::CBindRuntimeLossPolicyText text;
		text.startupText.strAnyInterface = _T("Any interface");
		text.startupText.strInterfaceNotFoundFormat = _T("Networking disabled for this session because the selected bind interface is no longer available: %s");
		text.startupText.strInterfaceNameAmbiguousFormat = _T("Networking disabled for this session because the selected bind interface name matches multiple live adapters: %s");
		text.startupText.strInterfaceHasNoAddressFormat = _T("Networking disabled for this session because the selected bind interface has no usable IPv4 address: %s");
		text.startupText.strAddressNotFoundOnInterfaceFormat = _T("Networking disabled for this session because the selected bind IP is no longer present on the selected interface: %s");
		text.startupText.strAddressNotFoundFormat = _T("Networking disabled for this session because the selected bind IP is no longer present on any live interface: %s");
		text.strInterfaceChangedFormat = _T("Exiting eMule because the selected bind interface changed address from %s to %s: %s");
		text.strInterfaceUnavailable = _T("Exiting eMule because the selected bind interface is no longer available.");
		text.strStartupDisabledPrefix = _T("Networking disabled for this session");
		text.strRuntimeExitPrefix = _T("Exiting eMule");
		return text;
	}
#endif

	CString FormatRuntimeBindLossReasonForTest(const CString &strResolvedInterfaceName
		, const CString &strActiveInterfaceName
		, const CString &strActiveInterfaceId
		, const CString &strActiveConfiguredAddress
		, EBindAddressResolveResult eResult
		, const CString &strResolvedAddress
		, const CString &strActiveBindAddress)
	{
#ifdef EMULEBB_BIND_RUNTIME_LOSS_POLICY_USES_EXTERNAL_TEXT
		return BindRuntimeLossPolicy::FormatRuntimeBindLossReason(strResolvedInterfaceName
			, strActiveInterfaceName
			, strActiveInterfaceId
			, strActiveConfiguredAddress
			, eResult
			, strResolvedAddress
			, strActiveBindAddress
			, GetBindRuntimeLossPolicyTextForTest());
#else
		return BindRuntimeLossPolicy::FormatRuntimeBindLossReason(strResolvedInterfaceName
			, strActiveInterfaceName
			, strActiveInterfaceId
			, strActiveConfiguredAddress
			, eResult
			, strResolvedAddress
			, strActiveBindAddress);
#endif
	}
}

TEST_CASE("Runtime bind-loss policy stays quiet when the resolved address is unchanged")
{
	const CString strAddress(_T("10.54.218.144"));

	CHECK(BindRuntimeLossPolicy::IsActiveBindAddressStillCurrent(BARR_Resolved, strAddress, strAddress));
	CHECK_FALSE(BindRuntimeLossPolicy::ShouldExitForRuntimeBindLoss(true, BARR_Resolved, strAddress, strAddress));
}

TEST_CASE("Runtime bind-loss policy is inert while the monitor is disabled")
{
	CHECK_FALSE(BindRuntimeLossPolicy::ShouldExitForRuntimeBindLoss(false
		, BARR_InterfaceNotFound
		, CString()
		, CString(_T("10.54.218.144"))));
}

TEST_CASE("Runtime bind-loss policy exits when the selected interface disappears")
{
	const CString strInterface(_T("My VPN"));
	const CString strAddress(_T("10.54.218.144"));

	CHECK(BindRuntimeLossPolicy::ShouldExitForRuntimeBindLoss(true, BARR_InterfaceNotFound, CString(), strAddress));
	CHECK(FormatRuntimeBindLossReasonForTest(CString(), strInterface, strInterface, CString(), BARR_InterfaceNotFound, CString(), strAddress)
		== CString(_T("Exiting eMule because the selected bind interface is no longer available: My VPN")));
}

TEST_CASE("Runtime bind-loss policy exits when the selected interface changes address")
{
	const CString strInterface(_T("My VPN"));
	const CString strOldAddress(_T("10.54.218.144"));
	const CString strNewAddress(_T("10.54.218.145"));

	CHECK_FALSE(BindRuntimeLossPolicy::IsActiveBindAddressStillCurrent(BARR_Resolved, strNewAddress, strOldAddress));
	CHECK(BindRuntimeLossPolicy::ShouldExitForRuntimeBindLoss(true, BARR_Resolved, strNewAddress, strOldAddress));
	CHECK(FormatRuntimeBindLossReasonForTest(strInterface, strInterface, strInterface, CString(), BARR_Resolved, strNewAddress, strOldAddress)
		== CString(_T("Exiting eMule because the selected bind interface changed address from 10.54.218.144 to 10.54.218.145: My VPN")));
}

TEST_CASE("Runtime bind-loss policy exits when the configured IP leaves the selected interface")
{
	const CString strInterface(_T("My VPN"));
	const CString strAddress(_T("10.54.218.144"));

	CHECK(BindRuntimeLossPolicy::ShouldExitForRuntimeBindLoss(true, BARR_AddressNotFoundOnInterface, CString(), strAddress));
	CHECK(FormatRuntimeBindLossReasonForTest(strInterface, strInterface, strInterface, strAddress, BARR_AddressNotFoundOnInterface, CString(), strAddress)
		== CString(_T("Exiting eMule because the selected bind IP is no longer present on the selected interface: My VPN / 10.54.218.144")));
}
