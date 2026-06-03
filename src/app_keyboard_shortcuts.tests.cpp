#include "../third_party/doctest/doctest.h"

#include "AppKeyboardShortcutsSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("App keyboard shortcut seam reserves native Alt-key commands")
{
	struct SExpectedShortcut
	{
		char ch;
		AppKeyboardShortcutsSeams::ECommand eCommand;
	};
	const SExpectedShortcut aShortcuts[] = {
		{ 'c', AppKeyboardShortcutsSeams::ECommand::ShowConnect },
		{ 'k', AppKeyboardShortcutsSeams::ECommand::ShowKad },
		{ 'v', AppKeyboardShortcutsSeams::ECommand::ShowServer },
		{ 't', AppKeyboardShortcutsSeams::ECommand::ShowTransfers },
		{ 's', AppKeyboardShortcutsSeams::ECommand::ShowSearch },
		{ 'f', AppKeyboardShortcutsSeams::ECommand::ShowSharedFiles },
		{ 'm', AppKeyboardShortcutsSeams::ECommand::ShowMessages },
		{ 'i', AppKeyboardShortcutsSeams::ECommand::ShowIrc },
		{ 'a', AppKeyboardShortcutsSeams::ECommand::ShowStatistics },
		{ 'o', AppKeyboardShortcutsSeams::ECommand::ShowOptions },
		{ 'h', AppKeyboardShortcutsSeams::ECommand::ShowHelp },
		{ 'x', AppKeyboardShortcutsSeams::ECommand::ExitApp },
		{ 'u', AppKeyboardShortcutsSeams::ECommand::ShowHotMenu },
		{ 'w', AppKeyboardShortcutsSeams::ECommand::ShowToolsMenu },
	};
	for (const SExpectedShortcut &shortcut : aShortcuts) {
		CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, shortcut.ch, false) == shortcut.eCommand);
		CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, shortcut.ch - 'a' + 'A', false) == shortcut.eCommand);
		CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, shortcut.ch, true) == AppKeyboardShortcutsSeams::ECommand::None);
	}
}

TEST_CASE("App keyboard shortcut seam maps numeric toolbar shortcuts")
{
	struct SExpectedShortcut
	{
		char ch;
		AppKeyboardShortcutsSeams::ECommand eCommand;
	};
	const SExpectedShortcut aShortcuts[] = {
		{ '1', AppKeyboardShortcutsSeams::ECommand::ShowConnect },
		{ '2', AppKeyboardShortcutsSeams::ECommand::ShowKad },
		{ '3', AppKeyboardShortcutsSeams::ECommand::ShowServer },
		{ '4', AppKeyboardShortcutsSeams::ECommand::ShowTransfers },
		{ '5', AppKeyboardShortcutsSeams::ECommand::ShowSearch },
		{ '6', AppKeyboardShortcutsSeams::ECommand::ShowSharedFiles },
		{ '7', AppKeyboardShortcutsSeams::ECommand::ShowMessages },
		{ '8', AppKeyboardShortcutsSeams::ECommand::ShowIrc },
		{ '9', AppKeyboardShortcutsSeams::ECommand::ShowStatistics },
		{ '0', AppKeyboardShortcutsSeams::ECommand::ShowOptions },
	};
	for (const SExpectedShortcut &shortcut : aShortcuts) {
		CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, shortcut.ch, false) == shortcut.eCommand);
		CHECK(AppKeyboardShortcutsSeams::ClassifySystemKeyMenu(SC_KEYMENU, shortcut.ch, true) == AppKeyboardShortcutsSeams::ECommand::None);
	}
}

TEST_CASE("App keyboard shortcut seam leaves ordinary navigation and modal contexts alone")
{
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, VK_TAB, true, false, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, 'Q', true, false, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, 'M', true, false, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_SYSKEYDOWN, 'X', false, true, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_SYSKEYDOWN, 'U', false, true, false) == AppKeyboardShortcutsSeams::ECommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifyMainKeyMessage(WM_KEYDOWN, 'Q', true, false, true) == AppKeyboardShortcutsSeams::ECommand::None);
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

TEST_CASE("Search keyboard shortcut seam keeps Ctrl+Tab global and owns result tabs")
{
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_TAB, true, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_TAB, true, false, true, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_PRIOR, true, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::SelectPreviousResultTab);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_NEXT, true, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::SelectNextResultTab);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, 'W', true, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::CloseSelectedResultTab);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_F4, true, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::CloseSelectedResultTab);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_NEXT, true, true, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYDOWN, VK_NEXT, true, false, true, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMessage(WM_KEYUP, VK_NEXT, true, false, false, false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
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
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 's', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'm', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'o', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'w', false) == AppKeyboardShortcutsSeams::ESearchCommand::None);
	CHECK(AppKeyboardShortcutsSeams::ClassifySearchKeyMenu(SC_KEYMENU, 'n', true) == AppKeyboardShortcutsSeams::ESearchCommand::None);
}

TEST_SUITE_END();
