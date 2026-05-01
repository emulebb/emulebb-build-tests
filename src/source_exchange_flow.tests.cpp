#include "../third_party/doctest/doctest.h"

#include <cstdint>

#include "TestSupport.h"
#include "BaseClientFriendBuddySeams.h"
#include "DownloadQueueHostnameResolverSeams.h"
#include "SourceExchangeSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Source flow keeps buddy advertisement and hostname dispatch decisions independent across a sequence")
{
	const BuddyHelloSnapshot buddySnapshot = BuildBuddyHelloSnapshot(true, true, 0x01020304u, 4662u);
	CHECK(buddySnapshot.bShouldAdvertise);
#ifdef MOD_CLIENT_MOD_VERSION_TEXT
	CHECK_EQ(GetHelloTagCount(buddySnapshot), static_cast<uint32>(9u));
#else
	CHECK_EQ(GetHelloTagCount(buddySnapshot), static_cast<uint32>(8u));
#endif

	const EDownloadHostnameResolveDispatch firstDispatch = GetDownloadHostnameResolveDispatch(true, true, true, false);
	const EDownloadHostnameResolveDispatch secondDispatch = GetDownloadHostnameResolveDispatch(true, true, true, true);
	const EDownloadHostnameResolveDispatch thirdDispatch = GetDownloadHostnameResolveDispatch(true, false, true, true);

	CHECK(firstDispatch == EDownloadHostnameResolveDispatch::AddPackedSource);
	CHECK(secondDispatch == EDownloadHostnameResolveDispatch::AddUrlSource);
	CHECK(thirdDispatch == EDownloadHostnameResolveDispatch::Drop);
}

TEST_CASE("Source flow keeps packed and URL hostname completions isolated across repeated transitions")
{
	CHECK(GetDownloadHostnameResolveDispatch(true, true, true, false) == EDownloadHostnameResolveDispatch::AddPackedSource);
	CHECK(GetDownloadHostnameResolveDispatch(true, true, true, true) == EDownloadHostnameResolveDispatch::AddUrlSource);
	CHECK(GetDownloadHostnameResolveDispatch(false, true, true, false) == EDownloadHostnameResolveDispatch::Drop);
	CHECK(GetDownloadHostnameResolveDispatch(true, false, true, false) == EDownloadHostnameResolveDispatch::Drop);
	CHECK(GetDownloadHostnameResolveDispatch(true, true, false, true) == EDownloadHostnameResolveDispatch::Drop);
}

TEST_CASE("Source flow only searches for replacement friends when the link snapshot really drifted")
{
	const FriendLinkSnapshot stableIpOnlyFriend = {true, false, false, false, true};
	const FriendLinkSnapshot hashedMismatchFriend = {true, true, false, false, false};
	const FriendLinkSnapshot missingFriend = {false, false, false, false, false};

	CHECK_FALSE(ShouldSearchReplacementFriend(stableIpOnlyFriend));
	CHECK(ShouldSearchReplacementFriend(hashedMismatchFriend));
	CHECK(ShouldSearchReplacementFriend(missingFriend));
}

TEST_CASE("Source exchange seam only allows requests for extended protocol peers with SX2")
{
	CHECK(SourceExchangeSeams::ShouldAllowSourceExchangeRequest(true, true));
	CHECK_FALSE(SourceExchangeSeams::ShouldAllowSourceExchangeRequest(true, false));
	CHECK_FALSE(SourceExchangeSeams::ShouldAllowSourceExchangeRequest(false, true));
	CHECK_FALSE(SourceExchangeSeams::ShouldAllowSourceExchangeRequest(false, false));
}

TEST_CASE("Source exchange seam resolves SX2-only response packets and rejects legacy request shapes")
{
	const SourceExchangeSeams::ResponsePlan plan = SourceExchangeSeams::ResolveSourceExchangeResponsePlan(true, 9);
	CHECK(plan.bShouldSend);
	CHECK_EQ(plan.byUsedVersion, static_cast<std::uint8_t>(SOURCEEXCHANGE2_VERSION));
	CHECK_EQ(plan.byAnswerOpcode, static_cast<std::uint8_t>(OP_ANSWERSOURCES2));
	CHECK_EQ(plan.nCountSeekOffset, static_cast<std::uint8_t>(17u));

	CHECK(SourceExchangeSeams::IsValidSourceExchange2Request(1));
	CHECK_FALSE(SourceExchangeSeams::IsValidSourceExchange2Request(0));
	CHECK_FALSE(SourceExchangeSeams::ResolveSourceExchangeResponsePlan(true, 0).bShouldSend);
	CHECK_FALSE(SourceExchangeSeams::ResolveSourceExchangeResponsePlan(false, 4).bShouldSend);
}

TEST_SUITE_END;
