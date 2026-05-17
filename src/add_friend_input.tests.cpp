#include "../third_party/doctest/doctest.h"

#include "AddFriendInputSeams.h"

namespace
{
	/**
	 * @brief Returns the scalar form used by inet_addr for dotted IPv4 text.
	 */
	uint32_t NetworkOrderIPv4(unsigned u1, unsigned u2, unsigned u3, unsigned u4)
	{
		return u1 | (u2 << 8u) | (u3 << 16u) | (u4 << 24u);
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Add friend input seam accepts IPv4 with an embedded port")
{
	const AddFriendInputSeams::FriendInput input = AddFriendInputSeams::ParseFriendInput(
		CString(_T(" 1.2.3.4:4662 ")),
		CString(_T("9999")),
		CString(_T(" friend ")),
		16);

	CHECK(input.Status == AddFriendInputSeams::FriendInputStatus::Valid);
	CHECK(input.AddressContainedPort);
	CHECK(input.NetworkOrderAddress == NetworkOrderIPv4(1, 2, 3, 4));
	CHECK(input.Port == 4662);
	CHECK(input.UserName == CString(_T("friend")));
}

TEST_CASE("Add friend input seam uses the separate port when the address has none")
{
	const AddFriendInputSeams::FriendInput input = AddFriendInputSeams::ParseFriendInput(
		CString(_T("10.20.30.40")),
		CString(_T(" 12345 ")),
		CString(_T("LongNickname")),
		4);

	CHECK(input.Status == AddFriendInputSeams::FriendInputStatus::Valid);
	CHECK_FALSE(input.AddressContainedPort);
	CHECK(input.NetworkOrderAddress == NetworkOrderIPv4(10, 20, 30, 40));
	CHECK(input.Port == 12345);
	CHECK(input.UserName == CString(_T("Long")));
}

TEST_CASE("Add friend input seam rejects invalid addresses and overflowing ports")
{
	CHECK(AddFriendInputSeams::ParseFriendInput(CString(_T("1.2.3.256")), CString(_T("4662")), CString(), 16).Status == AddFriendInputSeams::FriendInputStatus::InvalidAddress);
	CHECK(AddFriendInputSeams::ParseFriendInput(CString(_T("1.2.3.4:70000")), CString(_T("4662")), CString(), 16).Status == AddFriendInputSeams::FriendInputStatus::InvalidEmbeddedPort);
	CHECK(AddFriendInputSeams::ParseFriendInput(CString(_T("1.2.3.4")), CString(_T("70000")), CString(), 16).Status == AddFriendInputSeams::FriendInputStatus::InvalidPort);
	CHECK(AddFriendInputSeams::ParseFriendInput(CString(_T("1.2.3.4")), CString(), CString(), 16).Status == AddFriendInputSeams::FriendInputStatus::MissingPort);
}

TEST_SUITE_END();
