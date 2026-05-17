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

TEST_CASE("Tray notification seam routes hidden single mouse activation to MiniMule when enabled")
{
	TrayNotificationSeams::CTrayPrimaryActivationState state;
	state.bMiniMuleEnabled = true;
	state.bMainWindowVisible = false;
	state.eActivation = TrayNotificationSeams::ETrayPrimaryActivation::MouseSingleClick;

	CHECK(TrayNotificationSeams::ResolveTrayPrimaryActivation(state)
		== TrayNotificationSeams::ETrayPrimaryActivationAction::ShowMiniMule);
}

TEST_CASE("Tray notification seam restores when MiniMule is disabled or activation is explicit restore")
{
	TrayNotificationSeams::CTrayPrimaryActivationState state;
	state.bMiniMuleEnabled = false;
	state.bMainWindowVisible = false;
	state.eActivation = TrayNotificationSeams::ETrayPrimaryActivation::MouseSingleClick;

	CHECK(TrayNotificationSeams::ResolveTrayPrimaryActivation(state)
		== TrayNotificationSeams::ETrayPrimaryActivationAction::RestoreMainWindow);

	state.bMiniMuleEnabled = true;
	state.eActivation = TrayNotificationSeams::ETrayPrimaryActivation::MouseDoubleClick;
	CHECK(TrayNotificationSeams::ResolveTrayPrimaryActivation(state)
		== TrayNotificationSeams::ETrayPrimaryActivationAction::RestoreMainWindow);

	state.eActivation = TrayNotificationSeams::ETrayPrimaryActivation::KeyboardSelect;
	CHECK(TrayNotificationSeams::ResolveTrayPrimaryActivation(state)
		== TrayNotificationSeams::ETrayPrimaryActivationAction::RestoreMainWindow);
}

TEST_CASE("Tray notification seam ignores visible single mouse activation while MiniMule is enabled")
{
	TrayNotificationSeams::CTrayPrimaryActivationState state;
	state.bMiniMuleEnabled = true;
	state.bMainWindowVisible = true;
	state.eActivation = TrayNotificationSeams::ETrayPrimaryActivation::MouseSingleClick;

	CHECK(TrayNotificationSeams::ResolveTrayPrimaryActivation(state)
		== TrayNotificationSeams::ETrayPrimaryActivationAction::None);
}

TEST_SUITE_END();
