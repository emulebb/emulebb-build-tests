#include "../third_party/doctest/doctest.h"

#include "MuleListKeyboardShortcutsSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Mule list shortcut seam maps common detail shortcut")
{
	CHECK(MuleListKeyboardShortcutsSeams::ClassifyCommonKeyMessage(WM_KEYDOWN, 'I', true, false, false) == MP_DETAIL);
	CHECK(MuleListKeyboardShortcutsSeams::ClassifyCommonKeyMessage(WM_KEYDOWN, 'I', false, false, false) == 0);
	CHECK(MuleListKeyboardShortcutsSeams::ClassifyCommonKeyMessage(WM_KEYDOWN, 'I', true, true, false) == 0);
	CHECK(MuleListKeyboardShortcutsSeams::ClassifyCommonKeyMessage(WM_KEYDOWN, 'I', true, false, true) == 0);
	CHECK(MuleListKeyboardShortcutsSeams::ClassifyCommonKeyMessage(WM_KEYUP, 'I', true, false, false) == 0);
	CHECK(MuleListKeyboardShortcutsSeams::ClassifyCommonKeyMessage(WM_KEYDOWN, 'L', true, false, false) == 0);
}

TEST_SUITE_END();
