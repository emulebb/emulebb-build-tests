#include "doctest.h"

#include "DownloadListKeyboardShortcutsSeams.h"
#include "DownloadPriorityShortcutsSeams.h"

TEST_SUITE_BEGIN("download_list_keyboard_shortcuts");

TEST_CASE("download list shortcut seam maps selected transfer actions")
{
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', true, false, false) == MP_PAUSE);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'S', true, false, false) == MP_RESUME);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'T', true, false, false) == MP_STOP);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', true, false, true) == MP_PAUSE_CATEGORY);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'S', true, false, true) == MP_RESUME_CATEGORY);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'T', true, false, true) == MP_STOP_CATEGORY);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'R', true, false, false) == MP_CLEARCOMPLETED);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'L', true, false, false) == MP_GETED2KLINK);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, false, false, true) == MP_CANCEL_NO_CONFIRM);
}

TEST_CASE("download list shortcut seam maps qBittorrent-style priority shortcuts")
{
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_OEM_PLUS, true, false, false) == MP_PRIOUP);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_ADD, true, false, false) == MP_PRIOUP);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_OEM_MINUS, true, false, false) == MP_PRIODOWN);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_SUBTRACT, true, false, false) == MP_PRIODOWN);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_OEM_PLUS, true, false, true) == MP_PRIOHIGH);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_OEM_MINUS, true, false, true) == MP_PRIOLOW);
}

TEST_CASE("download list shortcut seam owns category menu shortcut")
{
	CHECK(DownloadListKeyboardShortcutsSeams::IsCategoryMenuShortcut(WM_KEYDOWN, 'M', true, false, false));
	CHECK_FALSE(DownloadListKeyboardShortcutsSeams::IsCategoryMenuShortcut(WM_KEYDOWN, 'M', true, false, true));
	CHECK_FALSE(DownloadListKeyboardShortcutsSeams::IsCategoryMenuShortcut(WM_KEYDOWN, 'M', true, true, false));
	CHECK_FALSE(DownloadListKeyboardShortcutsSeams::IsCategoryMenuShortcut(WM_KEYUP, 'M', true, false, false));
}

TEST_CASE("download list shortcut seam leaves unrelated and modified keys alone")
{
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYUP, 'P', true, false, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, false, false, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, true, false, true) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_DELETE, false, true, true) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', false, false, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'P', true, true, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'R', true, false, true) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, 'R', true, true, false) == 0);
	CHECK(DownloadListKeyboardShortcutsSeams::ClassifyKeyMessage(WM_KEYDOWN, VK_OEM_PLUS, true, true, false) == 0);
}

TEST_CASE("download priority shortcut seam steps manual priorities with bounds")
{
	CHECK(DownloadPriorityShortcutsSeams::StepManualDownloadPriority(DownloadPriorityShortcutsSeams::kDownloadPriorityLow, true) == DownloadPriorityShortcutsSeams::kDownloadPriorityNormal);
	CHECK(DownloadPriorityShortcutsSeams::StepManualDownloadPriority(DownloadPriorityShortcutsSeams::kDownloadPriorityNormal, true) == DownloadPriorityShortcutsSeams::kDownloadPriorityHigh);
	CHECK(DownloadPriorityShortcutsSeams::StepManualDownloadPriority(DownloadPriorityShortcutsSeams::kDownloadPriorityHigh, true) == DownloadPriorityShortcutsSeams::kDownloadPriorityHigh);
	CHECK(DownloadPriorityShortcutsSeams::StepManualDownloadPriority(DownloadPriorityShortcutsSeams::kDownloadPriorityHigh, false) == DownloadPriorityShortcutsSeams::kDownloadPriorityNormal);
	CHECK(DownloadPriorityShortcutsSeams::StepManualDownloadPriority(DownloadPriorityShortcutsSeams::kDownloadPriorityNormal, false) == DownloadPriorityShortcutsSeams::kDownloadPriorityLow);
	CHECK(DownloadPriorityShortcutsSeams::StepManualDownloadPriority(DownloadPriorityShortcutsSeams::kDownloadPriorityLow, false) == DownloadPriorityShortcutsSeams::kDownloadPriorityLow);
}

TEST_SUITE_END();
