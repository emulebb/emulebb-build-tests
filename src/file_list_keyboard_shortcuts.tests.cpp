#include "doctest.h"

#include "FileListKeyboardShortcutsSeams.h"
#include "MenuShortcutLabels.h"

TEST_SUITE_BEGIN("file_list_keyboard_shortcuts");

TEST_CASE("common file-list shortcuts map to existing non-destructive commands")
{
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'I', true, false, false) == MP_METINFO);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SearchResults, WM_KEYDOWN, 'I', true, false, false) == MP_DETAIL);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedFiles, WM_KEYDOWN, 'L', true, false, false) == MP_GETED2KLINK);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedDirs, WM_KEYDOWN, 'O', true, false, true) == MP_OPENFOLDER);
}

TEST_CASE("file-list shortcuts keep context-specific actions local")
{
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'P', true, false, false) == MP_PAUSE);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'S', true, false, false) == MP_RESUME);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'T', true, false, false) == MP_STOP);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'F', true, false, false) == MP_FIND);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SearchResults, WM_KEYDOWN, 'F', true, false, false) == MP_FIND);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedFiles, WM_KEYDOWN, 'F', true, false, false) == MP_FIND);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SearchResults, WM_KEYDOWN, 'D', true, false, false) == MP_RESUME);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SearchResults, WM_KEYDOWN, 'D', true, false, true) == MP_RESUMEPAUSED);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SearchResults, WM_KEYDOWN, 'P', true, false, false) == 0);
}

TEST_CASE("file-list summary shortcuts are supported only where summaries exist")
{
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'C', true, false, true) == MP_COPY_FILE_SUMMARY);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SearchResults, WM_KEYDOWN, 'C', true, false, true) == MP_COPY_SEARCH_SUMMARY);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedFiles, WM_KEYDOWN, 'C', true, false, true) == MP_COPY_FILE_SUMMARY);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedDirs, WM_KEYDOWN, 'C', true, false, true) == 0);
}

TEST_CASE("file-list shortcuts leave unrelated and unsafe variants alone")
{
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYUP, 'I', true, false, false) == 0);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'I', false, false, false) == 0);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::Downloads, WM_KEYDOWN, 'I', true, true, false) == 0);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedDirs, WM_KEYDOWN, 'O', true, false, false) == 0);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedDirs, WM_KEYDOWN, 'I', true, false, false) == 0);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedDirs, WM_KEYDOWN, 'L', true, false, false) == 0);
	CHECK(FileListKeyboardShortcutsSeams::ClassifyKeyMessage(FileListKeyboardShortcutsSeams::EContext::SharedDirs, WM_KEYDOWN, 'F', true, false, false) == 0);
}

TEST_CASE("menu shortcut labels use native right-aligned menu hint format")
{
	CHECK(AddMenuShortcutLabel(CString(_T("Find")), _T("Ctrl+F")).Compare(_T("Find\tCtrl+F")) == 0);
	CHECK(AddMenuShortcutLabel(CString(_T("Find")), _T("")).Compare(_T("Find")) == 0);
	CHECK(AddMenuShortcutLabel(CString(_T("Find")), NULL).Compare(_T("Find")) == 0);
}

TEST_SUITE_END();
