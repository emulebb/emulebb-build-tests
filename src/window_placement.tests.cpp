#include "../third_party/doctest/doctest.h"

#include "WindowPlacementSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Default main window placement is maximized with centered eighty percent normal rect")
{
	RECT rcWorkArea = {};
	rcWorkArea.left = 0;
	rcWorkArea.top = 0;
	rcWorkArea.right = 1920;
	rcWorkArea.bottom = 1080;

	const WINDOWPLACEMENT placement = WindowPlacementSeams::BuildDefaultMainWindowPlacement(rcWorkArea);

	CHECK(placement.length == sizeof(WINDOWPLACEMENT));
	CHECK(placement.showCmd == SW_SHOWMAXIMIZED);
	CHECK(placement.rcNormalPosition.left == 192);
	CHECK(placement.rcNormalPosition.top == 108);
	CHECK(placement.rcNormalPosition.right == 1728);
	CHECK(placement.rcNormalPosition.bottom == 972);
}

TEST_CASE("Default main window placement respects offset work areas")
{
	RECT rcWorkArea = {};
	rcWorkArea.left = 100;
	rcWorkArea.top = 50;
	rcWorkArea.right = 1100;
	rcWorkArea.bottom = 850;

	const RECT rcNormal = WindowPlacementSeams::BuildCenteredPercentRect(rcWorkArea, WindowPlacementSeams::kDefaultNormalRectPercent);

	CHECK(rcNormal.left == 200);
	CHECK(rcNormal.top == 130);
	CHECK(rcNormal.right == 1000);
	CHECK(rcNormal.bottom == 770);
}

TEST_SUITE_END();
