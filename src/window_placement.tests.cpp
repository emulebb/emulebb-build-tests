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

TEST_CASE("Tray restore preserves restore-to-maximized placement")
{
	WINDOWPLACEMENT placement = {};
	placement.length = sizeof(WINDOWPLACEMENT);
	placement.showCmd = SW_SHOWMINIMIZED;
	placement.flags = WPF_RESTORETOMAXIMIZED;

	CHECK(WindowPlacementSeams::ResolveRestoreShowCommand(placement) == SW_SHOWMAXIMIZED);
}

TEST_CASE("Tray restore preserves explicit maximized placement")
{
	WINDOWPLACEMENT placement = {};
	placement.length = sizeof(WINDOWPLACEMENT);
	placement.showCmd = SW_SHOWMAXIMIZED;

	CHECK(WindowPlacementSeams::ResolveRestoreShowCommand(placement) == SW_SHOWMAXIMIZED);
}

TEST_CASE("Tray restore uses normal state for non-maximized placements")
{
	WINDOWPLACEMENT placement = {};
	placement.length = sizeof(WINDOWPLACEMENT);
	placement.showCmd = SW_SHOWMINIMIZED;

	CHECK(WindowPlacementSeams::ResolveRestoreShowCommand(placement) == SW_SHOWNORMAL);

	placement.showCmd = SW_SHOWNORMAL;
	placement.flags = 0;
	CHECK(WindowPlacementSeams::ResolveRestoreShowCommand(placement) == SW_SHOWNORMAL);
}

TEST_SUITE_END();
