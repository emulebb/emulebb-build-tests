#include "../third_party/doctest/doctest.h"

#include "TestSupport.h"
#include "BaseClientFriendBuddySeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Friend transition reports userhash failure only for mismatched hashed friends that are still connecting")
{
	const FriendLinkSnapshot connectingMismatch = {true, true, true, false, false};
	const FriendLinkSnapshot linkedMismatch = {true, true, false, false, false};
	const FriendLinkSnapshot matchingHashedFriend = {true, true, false, true, false};

	CHECK_EQ(ClassifyFriendLinkTransition(connectingMismatch), friendLinkTransitionUserhashFailed);
	CHECK_EQ(ClassifyFriendLinkTransition(linkedMismatch), friendLinkTransitionUnlink);
	CHECK_EQ(ClassifyFriendLinkTransition(matchingHashedFriend), friendLinkTransitionNone);
}

TEST_CASE("Friend replacement policy preserves the IP-only friend exception")
{
	const FriendLinkSnapshot matchingIpOnlyFriend = {true, false, false, true, true};
	const FriendLinkSnapshot mismatchedEndpoint = {true, false, false, true, false};
	const FriendLinkSnapshot hashedFriend = {true, true, false, true, true};
	const FriendLinkSnapshot noFriend = {false, false, false, false, false};

	CHECK_FALSE(ShouldSearchReplacementFriend(matchingIpOnlyFriend));
	CHECK(ShouldSearchReplacementFriend(mismatchedEndpoint));
	CHECK(ShouldSearchReplacementFriend(hashedFriend));
	CHECK(ShouldSearchReplacementFriend(noFriend));
}

TEST_CASE("Buddy hello snapshot advertises tags only when firewalled mode has a buddy snapshot")
{
	const BuddyHelloSnapshot advertisedBuddy = BuildBuddyHelloSnapshot(true, true, 0x01020304u, 4662u);
	const BuddyHelloSnapshot noBuddy = BuildBuddyHelloSnapshot(true, false, 0u, 0u);
	const BuddyHelloSnapshot notFirewalled = BuildBuddyHelloSnapshot(false, true, 0x01020304u, 4662u);

	CHECK(advertisedBuddy.bShouldAdvertise);
	CHECK_EQ(advertisedBuddy.dwBuddyIP, static_cast<uint32>(0x01020304u));
	CHECK_EQ(advertisedBuddy.nBuddyPort, static_cast<uint16>(4662u));
	CHECK_FALSE(noBuddy.bShouldAdvertise);
	CHECK_FALSE(notFirewalled.bShouldAdvertise);
}

TEST_CASE("Hello tag count stays aligned with the buddy advertisement snapshot")
{
	const BuddyHelloSnapshot advertisedBuddy = BuildBuddyHelloSnapshot(true, true, 1u, 2u);
	const BuddyHelloSnapshot noBuddy = BuildBuddyHelloSnapshot(true, false, 0u, 0u);

#ifdef MOD_CLIENT_MOD_VERSION_TEXT
	CHECK_EQ(GetHelloTagCount(advertisedBuddy), static_cast<uint32>(9u));
	CHECK_EQ(GetHelloTagCount(noBuddy), static_cast<uint32>(7u));
#else
	CHECK_EQ(GetHelloTagCount(advertisedBuddy), static_cast<uint32>(8u));
	CHECK_EQ(GetHelloTagCount(noBuddy), static_cast<uint32>(6u));
#endif
}

#ifdef MOD_CLIENT_MOD_VERSION_TEXT
TEST_CASE("Hello mod identity advertises the eMule BB release")
{
	CHECK(GetAdvertisedClientModIdentity() == CString(_T("eMule BB 1.0.0")));
}

TEST_CASE("Client software display appends a non-empty mod identity")
{
	CHECK(BuildFullClientSoftVersionDisplay(CString(_T("eMule v0.72a")), CString()) == CString(_T("eMule v0.72a")));
	CHECK(BuildFullClientSoftVersionDisplay(CString(_T("eMule v0.72a")), CString(_T("MorphXT 12.7"))) == CString(_T("eMule v0.72a [MorphXT 12.7]")));
}
#endif

TEST_CASE("Friend transition never unlinks IP-only friends solely because the endpoint changed")
{
	const FriendLinkSnapshot ipOnlyConnecting = {true, false, true, false, false};
	const FriendLinkSnapshot ipOnlyLinked = {true, false, false, false, false};

	CHECK_EQ(ClassifyFriendLinkTransition(ipOnlyConnecting), friendLinkTransitionNone);
	CHECK_EQ(ClassifyFriendLinkTransition(ipOnlyLinked), friendLinkTransitionNone);
	CHECK(ShouldSearchReplacementFriend(ipOnlyConnecting));
	CHECK(ShouldSearchReplacementFriend(ipOnlyLinked));
}

TEST_CASE("Buddy hello snapshot preserves the captured endpoint even when it does not advertise")
{
	const BuddyHelloSnapshot hiddenBuddy = BuildBuddyHelloSnapshot(false, true, 0x01020304u, 4662u);
	CHECK_FALSE(hiddenBuddy.bShouldAdvertise);
	CHECK_EQ(hiddenBuddy.dwBuddyIP, static_cast<uint32>(0x01020304u));
	CHECK_EQ(hiddenBuddy.nBuddyPort, static_cast<uint16>(4662u));
}

TEST_SUITE_END;
