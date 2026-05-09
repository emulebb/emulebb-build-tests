#include "../third_party/doctest/doctest.h"

#include "TrayNotificationSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Tray notification seam shows icon for explicit always-show and balloon modes")
{
	TrayNotificationSeams::CTrayVisibilityState state;
	CHECK_FALSE(TrayNotificationSeams::ShouldTrayIconBeVisible(state));

	state.bAlwaysShowTrayIcon = true;
	CHECK(TrayNotificationSeams::ShouldTrayIconBeVisible(state));

	state.bAlwaysShowTrayIcon = false;
	state.eNotifierDisplayMode = TrayNotificationSeams::ENotifierDisplayMode::TrayBalloon;
	CHECK(TrayNotificationSeams::ShouldTrayIconBeVisible(state));
}

TEST_CASE("Tray notification seam exposes Windows toast fallback session visibility")
{
	TrayNotificationSeams::CTrayVisibilityState state;
	state.eNotifierDisplayMode = TrayNotificationSeams::ENotifierDisplayMode::WindowsToast;
	CHECK_FALSE(TrayNotificationSeams::ShouldTrayIconBeVisible(state));

	state.bTrayBalloonFallbackForSession = true;
	CHECK(TrayNotificationSeams::ShouldTrayIconBeVisible(state));
}

TEST_CASE("Tray notification seam shows minimized windows only when minimize-to-tray is enabled")
{
	TrayNotificationSeams::CTrayVisibilityState state;
	state.bMainWindowVisible = false;
	CHECK_FALSE(TrayNotificationSeams::ShouldTrayIconBeVisible(state));

	state.bMinimizeToTray = true;
	CHECK(TrayNotificationSeams::ShouldTrayIconBeVisible(state));

	state.bMainWindowVisible = true;
	CHECK_FALSE(TrayNotificationSeams::ShouldTrayIconBeVisible(state));
}

TEST_SUITE_END();
