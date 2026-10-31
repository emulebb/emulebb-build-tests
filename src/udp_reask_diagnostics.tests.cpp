#include "doctest.h"

#include "UdpReaskDiagnosticsSeams.h"

namespace
{
UdpReaskDiagnosticsSeams::SUdpReaskEligibility DirectEligibility()
{
	UdpReaskDiagnosticsSeams::SUdpReaskEligibility eligibility = {};
	eligibility.bHasRequestFile = true;
	eligibility.uRemoteUdpPort = 4672u;
	eligibility.uRemoteUdpVersion = 4u;
	eligibility.uLocalUdpPort = 4672u;
	return eligibility;
}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("UDP reask diagnostics classify direct eligibility and ordered transport blockers")
{
	using UdpReaskDiagnosticsSeams::EUdpReaskDecision;

	auto eligibility = DirectEligibility();
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::DirectEligible);

	eligibility = DirectEligibility();
	eligibility.bHasRequestFile = false;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::MissingRequestFile);

	eligibility = DirectEligibility();
	eligibility.bRequestPending = true;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::RequestPending);

	eligibility = DirectEligibility();
	eligibility.uRemoteUdpPort = 0u;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::RemoteUdpPortMissing);

	eligibility = DirectEligibility();
	eligibility.uRemoteUdpVersion = 0u;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::RemoteUdpVersionMissing);

	eligibility = DirectEligibility();
	eligibility.uLocalUdpPort = 0u;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::LocalUdpDisabled);

	eligibility = DirectEligibility();
	eligibility.bLocalFirewalled = true;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::LocalFirewalled);

	eligibility = DirectEligibility();
	eligibility.bTcpConnected = true;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::TcpConnected);

	eligibility = DirectEligibility();
	eligibility.bProxyEnabled = true;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::ProxyEnabled);
}

TEST_CASE("UDP reask diagnostics preserve the existing failure-ratio threshold")
{
	using UdpReaskDiagnosticsSeams::EUdpReaskDecision;
	auto eligibility = DirectEligibility();

	eligibility.uTotalPackets = 3u;
	eligibility.uFailedPackets = 3u;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::DirectEligible);

	eligibility.uTotalPackets = 10u;
	eligibility.uFailedPackets = 3u;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::DirectEligible);

	eligibility.uFailedPackets = 4u;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::FailureRatioExceeded);
}

TEST_CASE("UDP reask diagnostics classify callback buddy requirements")
{
	using UdpReaskDiagnosticsSeams::EUdpReaskDecision;
	auto eligibility = DirectEligibility();
	eligibility.bLowId = true;

	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::BuddyIpMissing);

	eligibility.bBuddyIpKnown = true;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::BuddyPortMissing);

	eligibility.bBuddyPortKnown = true;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::BuddyIdInvalid);

	eligibility.bBuddyIdValid = true;
	CHECK(UdpReaskDiagnosticsSeams::EvaluateEligibility(eligibility) == EUdpReaskDecision::CallbackEligible);
}

TEST_CASE("UDP reask diagnostics distinguish transport eligibility from sends")
{
	using UdpReaskDiagnosticsSeams::EUdpReaskDecision;

	CHECK_FALSE(UdpReaskDiagnosticsSeams::IsTransportEligibleDecision(EUdpReaskDecision::TcpConnected));
	CHECK(UdpReaskDiagnosticsSeams::IsTransportEligibleDecision(EUdpReaskDecision::SourceExchangeDue));
	CHECK(UdpReaskDiagnosticsSeams::IsTransportEligibleDecision(EUdpReaskDecision::SwappedToAnotherFile));
	CHECK(UdpReaskDiagnosticsSeams::IsTransportEligibleDecision(EUdpReaskDecision::DirectReaskSent));
	CHECK_FALSE(UdpReaskDiagnosticsSeams::IsSentDecision(EUdpReaskDecision::SourceExchangeDue));
	CHECK(UdpReaskDiagnosticsSeams::IsSentDecision(EUdpReaskDecision::CallbackReaskSent));
}

TEST_CASE("UDP reask diagnostics suppress repeated decisions without hiding transitions")
{
	using UdpReaskDiagnosticsSeams::EUdpReaskDecision;
	const uint64_t firstTick = 1000u;

	CHECK(UdpReaskDiagnosticsSeams::ShouldLogDecision(
		EUdpReaskDecision::None, 0u, EUdpReaskDecision::TcpConnected, firstTick, true));
	CHECK_FALSE(UdpReaskDiagnosticsSeams::ShouldLogDecision(
		EUdpReaskDecision::TcpConnected, firstTick, EUdpReaskDecision::TcpConnected, firstTick + 1u, true));
	CHECK(UdpReaskDiagnosticsSeams::ShouldLogDecision(
		EUdpReaskDecision::TcpConnected, firstTick, EUdpReaskDecision::TcpConnected, firstTick + 1u, false));
	CHECK(UdpReaskDiagnosticsSeams::ShouldLogDecision(
		EUdpReaskDecision::TcpConnected,
		firstTick,
		EUdpReaskDecision::TcpConnected,
		firstTick + UdpReaskDiagnosticsSeams::kRepeatDecisionLogIntervalMs,
		true));
	CHECK(UdpReaskDiagnosticsSeams::ShouldLogDecision(
		EUdpReaskDecision::TcpConnected, firstTick, EUdpReaskDecision::SourceExchangeDue, firstTick + 1u, true));
	CHECK(UdpReaskDiagnosticsSeams::ShouldLogDecision(
		EUdpReaskDecision::TcpConnected, firstTick, EUdpReaskDecision::TcpConnected, firstTick - 1u, true));
}

TEST_SUITE_END;
