#include "doctest.h"

#include "DownloadListKeyboardShortcutsSeams.h"

TEST_SUITE_BEGIN("download_list_keyboard_shortcuts");

TEST_CASE("download list shortcut seam maps selected transfer actions")
{
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', true, false, false) == MP_PAUSE);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'S', true, false, false) == MP_RESUME);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'T', true, false, false) == MP_STOP);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, false, false, true) == MP_CANCEL_NO_CONFIRM);
}

TEST_CASE("download list shortcut seam leaves unrelated and modified keys alone")
{
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYUP, 'P', true, false, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, false, false, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, true, false, true) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, false, true, true) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', false, false, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', true, true, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', true, false, true) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'R', true, false, false) == 0);
}

TEST_SUITE_END();
