#include "../third_party/doctest/doctest.h"

#include "SpeedQuickActionsSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Speed quick actions expose fixed upload percentages from ten through ninety")
{
	REQUIRE(SpeedQuickActionsSeams::kUploadPercentActions.size() == 9);

	unsigned int uExpectedPercent = 10;
	unsigned int uExpectedCommand = MP_QS_U10;
	for (const SpeedQuickActionsSeams::CQuickSpeedPercentAction &action : SpeedQuickActionsSeams::kUploadPercentActions) {
		CHECK(action.uPercent == uExpectedPercent);
		CHECK(action.uCommandId == uExpectedCommand);
		CHECK(SpeedQuickActionsSeams::GetPercentForCommand(action.uCommandId) == uExpectedPercent);
		uExpectedPercent += 10;
		++uExpectedCommand;
	}
}

TEST_CASE("Speed quick actions expose fixed download percentages from ten through ninety")
{
	REQUIRE(SpeedQuickActionsSeams::kDownloadPercentActions.size() == 9);

	unsigned int uExpectedPercent = 10;
	unsigned int uExpectedCommand = MP_QS_D10;
	for (const SpeedQuickActionsSeams::CQuickSpeedPercentAction &action : SpeedQuickActionsSeams::kDownloadPercentActions) {
		CHECK(action.uPercent == uExpectedPercent);
		CHECK(action.uCommandId == uExpectedCommand);
		CHECK(SpeedQuickActionsSeams::GetPercentForCommand(action.uCommandId) == uExpectedPercent);
		uExpectedPercent += 10;
		++uExpectedCommand;
	}
}

TEST_CASE("Speed quick actions expose fixed combined percentages from ten through ninety")
{
	REQUIRE(SpeedQuickActionsSeams::kBothPercentActions.size() == 9);

	unsigned int uExpectedPercent = 10;
	unsigned int uExpectedCommand = MP_QS_B10;
	for (const SpeedQuickActionsSeams::CQuickSpeedPercentAction &action : SpeedQuickActionsSeams::kBothPercentActions) {
		CHECK(action.uPercent == uExpectedPercent);
		CHECK(action.uCommandId == uExpectedCommand);
		CHECK(SpeedQuickActionsSeams::GetPercentForCommand(action.uCommandId) == uExpectedPercent);
		uExpectedPercent += 10;
		++uExpectedCommand;
	}
}

TEST_CASE("Speed quick action limits are calculated from configured caps")
{
	CHECK(SpeedQuickActionsSeams::CalculatePercentLimitKiB(1000u, 10u) == 100u);
	CHECK(SpeedQuickActionsSeams::CalculatePercentLimitKiB(1000u, 50u) == 500u);
	CHECK(SpeedQuickActionsSeams::CalculatePercentLimitKiB(10u, 10u) == 1u);
	CHECK(SpeedQuickActionsSeams::CalculatePercentLimitKiB(1u, 10u) == 1u);
	CHECK(SpeedQuickActionsSeams::GetPercentForCommand(MP_QS_PA) == 0u);
	CHECK(SpeedQuickActionsSeams::GetPercentForCommand(MP_QS_UA) == 0u);
}

TEST_SUITE_END();
