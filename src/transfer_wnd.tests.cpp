#include "../third_party/doctest/doctest.h"

#include <windows.h>

#include "TransferWndSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Transfer window seam validates secondary panes")
{
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneDownloading));
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneUploading));
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneOnQueue));
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneClients));

	CHECK_FALSE(TransferWndSeams::IsValidSecondaryPane(-1));
	CHECK_FALSE(TransferWndSeams::IsValidSecondaryPane(4));
	CHECK_EQ(TransferWndSeams::NormalizeSecondaryPane(-1), TransferWndSeams::kSecondaryPaneUploading);
	CHECK_EQ(TransferWndSeams::NormalizeSecondaryPane(4), TransferWndSeams::kSecondaryPaneUploading);
	CHECK_EQ(TransferWndSeams::NormalizeSecondaryPane(TransferWndSeams::kSecondaryPaneClients), TransferWndSeams::kSecondaryPaneClients);
}

TEST_CASE("Transfer window seam validates primary list ids")
{
	CHECK(TransferWndSeams::IsValidPrimaryListId(TransferWndSeams::kPrimaryListSplit));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_DOWNLOADLIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_UPLOADLIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_QUEUELIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_CLIENTLIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_DOWNLOADCLIENTS));

	CHECK_FALSE(TransferWndSeams::IsValidPrimaryListId(0));
	CHECK_FALSE(TransferWndSeams::IsValidPrimaryListId(IDC_DOWNLOADLIST + IDC_QUEUELIST));
	CHECK_EQ(TransferWndSeams::NormalizePrimaryListId(0), TransferWndSeams::kPrimaryListSplit);
	CHECK_EQ(TransferWndSeams::NormalizePrimaryListId(IDC_CLIENTLIST), static_cast<std::uint32_t>(IDC_CLIENTLIST));
}

TEST_CASE("Transfer window seam keeps detail routing off invalid states")
{
	CHECK_FALSE(TransferWndSeams::IsUserDetailPrimaryListId(TransferWndSeams::kPrimaryListSplit));
	CHECK_FALSE(TransferWndSeams::IsUserDetailPrimaryListId(IDC_DOWNLOADLIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_UPLOADLIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_QUEUELIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_CLIENTLIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_DOWNLOADCLIENTS));
	CHECK_FALSE(TransferWndSeams::IsUserDetailPrimaryListId(0));

	CHECK(TransferWndSeams::IsUserDetailSecondaryPane(TransferWndSeams::kSecondaryPaneUploading));
	CHECK_FALSE(TransferWndSeams::IsUserDetailSecondaryPane(-1));
	CHECK_FALSE(TransferWndSeams::IsUserDetailSecondaryPane(4));
}

TEST_CASE("Transfer window seam logs invalid state only")
{
	CHECK_FALSE(TransferWndSeams::ShouldLogInvalidState(true));
	CHECK(TransferWndSeams::ShouldLogInvalidState(false));
}

TEST_CASE("Transfer window seam commits category drag only after full image drag startup")
{
	CHECK_FALSE(TransferWndSeams::ShouldCommitCategoryDragStart(false, false, false));
	CHECK_FALSE(TransferWndSeams::ShouldCommitCategoryDragStart(true, false, false));
	CHECK_FALSE(TransferWndSeams::ShouldCommitCategoryDragStart(true, true, false));
	CHECK(TransferWndSeams::ShouldCommitCategoryDragStart(true, true, true));
}

TEST_CASE("Transfer window seam cancels category drag when the left button is gone")
{
	CHECK_FALSE(TransferWndSeams::ShouldCancelCategoryDragOnMouseMove(false, false));
	CHECK_FALSE(TransferWndSeams::ShouldCancelCategoryDragOnMouseMove(false, true));
	CHECK_FALSE(TransferWndSeams::ShouldCancelCategoryDragOnMouseMove(true, true));
	CHECK(TransferWndSeams::ShouldCancelCategoryDragOnMouseMove(true, false));
}

TEST_CASE("Transfer window seam maps Ctrl+number category shortcuts")
{
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '0', true, false, false), 0);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', true, false, false), 1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '9', true, false, false), 9);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', false, false, false), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', true, true, false), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', true, false, true), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYUP, '1', true, false, false), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, 'A', true, false, false), -1);
}

TEST_CASE("Transfer window seam maps direct list shortcuts")
{
	using TransferWndSeams::ETransferListShortcutCommand;

	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'D', true, false, false) == ETransferListShortcutCommand::Downloads);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'U', true, false, false) == ETransferListShortcutCommand::Uploading);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'Q', true, false, false) == ETransferListShortcutCommand::OnQueue);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'K', true, false, false) == ETransferListShortcutCommand::KnownClients);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'D', true, false, true) == ETransferListShortcutCommand::DownloadingClients);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'U', false, false, false) == ETransferListShortcutCommand::None);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'U', true, true, false) == ETransferListShortcutCommand::None);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'U', true, false, true) == ETransferListShortcutCommand::None);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYUP, 'U', true, false, false) == ETransferListShortcutCommand::None);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, 'A', true, false, false) == ETransferListShortcutCommand::None);
	CHECK(TransferWndSeams::ClassifyTransferListShortcut(WM_KEYDOWN, '1', true, false, false) == ETransferListShortcutCommand::None);
}

TEST_SUITE_END();
