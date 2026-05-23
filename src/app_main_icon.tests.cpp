#include "../third_party/doctest/doctest.h"

#include "AppMainIconSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Main app icon seam keeps normal icon outside connected LowID")
{
	CHECK(AppMainIconSeams::SelectConnectionIcon(false, false) == AppMainIconSeams::EConnectionIcon::Default);
	CHECK(AppMainIconSeams::SelectConnectionIcon(false, true) == AppMainIconSeams::EConnectionIcon::Default);
	CHECK(AppMainIconSeams::SelectConnectionIcon(true, false) == AppMainIconSeams::EConnectionIcon::Default);
}

TEST_CASE("Main app icon seam selects LowID icon only for connected firewalled state")
{
	CHECK(AppMainIconSeams::SelectConnectionIcon(true, true) == AppMainIconSeams::EConnectionIcon::LowID);
}

TEST_CASE("Main app icon seam skips redundant refreshes")
{
	CHECK(AppMainIconSeams::ShouldApplyConnectionIcon(AppMainIconSeams::EConnectionIcon::Unknown, AppMainIconSeams::EConnectionIcon::Default));
	CHECK(AppMainIconSeams::ShouldApplyConnectionIcon(AppMainIconSeams::EConnectionIcon::Default, AppMainIconSeams::EConnectionIcon::LowID));
	CHECK_FALSE(AppMainIconSeams::ShouldApplyConnectionIcon(AppMainIconSeams::EConnectionIcon::Default, AppMainIconSeams::EConnectionIcon::Default));
	CHECK_FALSE(AppMainIconSeams::ShouldApplyConnectionIcon(AppMainIconSeams::EConnectionIcon::LowID, AppMainIconSeams::EConnectionIcon::LowID));
}

TEST_SUITE_END();
