#include "../third_party/doctest/doctest.h"

#include "AppKeyboardShortcutsSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("App keyboard shortcut seam reserves native Alt-key commands")
{
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'x', false) == AppKeyboardShortcutsSeams::ECommand::ExitApp);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'X', false) == AppKeyboardShortcutsSeams::ECommand::ExitApp);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'u', false) == AppKeyboardShortcutsSeams::ECommand::ShowHotMenu);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'U', false) == AppKeyboardShortcutsSeams::ECommand::ShowHotMenu);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'w', false) == AppKeyboardShortcutsSeams::ECommand::ShowToolsMenu);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'W', false) == AppKeyboardShortcutsSeams::ECommand::ShowToolsMenu);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '1', false) == AppKeyboardShortcutsSeams::ECommand::ShowKad);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '2', false) == AppKeyboardShortcutsSeams::ECommand::ShowServer);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '3', false) == AppKeyboardShortcutsSeams::ECommand::ShowTransfers);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '4', false) == AppKeyboardShortcutsSeams::ECommand::ShowSearch);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '5', false) == AppKeyboardShortcutsSeams::ECommand::ShowSharedFiles);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '6', false) == AppKeyboardShortcutsSeams::ECommand::ShowMessages);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '7', false) == AppKeyboardShortcutsSeams::ECommand::ShowIrc);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '8', false) == AppKeyboardShortcutsSeams::ECommand::ShowStatistics);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '9', false) == AppKeyboardShortcutsSeams::ECommand::ShowOptions);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'o', false) == AppKeyboardShortcutsSeams::ECommand::ShowOptions);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'O', false) == AppKeyboardShortcutsSeams::ECommand::ShowOptions);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 't', false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'T', false) == AppKeyboardShortcutsSeams::ECommand::None);
}

TEST_CASE("App keyboard shortcut seam leaves ordinary navigation and modal contexts alone")
{
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, VK_TAB, true, false, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, 'Q', true, false, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, 'M', true, false, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_SYSKEYDOWN, 'X', false, true, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_SYSKEYDOWN, 'U', false, true, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, 'Q', true, false, true) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'x', true) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'u', true) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'w', true) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, '1', true) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'o', true) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'm', false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, 'q', false) == AppKeyboardShortcutsSeams::ECommand::None);
}

TEST_CASE("Search keyboard shortcut seam owns F6 focus toggle locally")
{
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_F6, false, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::ToggleNameResults);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_F6, true, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_F6, false, true, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_F6, false, false, true, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_F6, false, false, false, true) == AppKeyboardShortcutsSeams::ESearchCommand::None);
}

TEST_CASE("Search keyboard shortcut seam owns local non-toolbar mnemonics")
{
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'n', false) == AppKeyboardShortcutsSeams::ESearchCommand::FocusName);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'Y', false) == AppKeyboardShortcutsSeams::ESearchCommand::FocusType);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'd', false) == AppKeyboardShortcutsSeams::ESearchCommand::FocusMethod);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'G', false) == AppKeyboardShortcutsSeams::ESearchCommand::StartSearch);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'e', false) == AppKeyboardShortcutsSeams::ESearchCommand::SearchMore);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'R', false) == AppKeyboardShortcutsSeams::ESearchCommand::ResetSearch);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'l', false) == AppKeyboardShortcutsSeams::ESearchCommand::CancelSearch);
}

TEST_CASE("Search keyboard shortcut seam leaves main-shell reserved mnemonics alone")
{
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'x', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'u', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 't', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'w', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, '1', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 's', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'm', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'o', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'n', true) == AppKeyboardShortcutsSeams::ESearchCommand::None);
}

TEST_SUITE_END();
