#include "../third_party/doctest/doctest.h"

#include <cstdint>
#include <limits>

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

TEST_CASE("Transfer window seam formats broadband queue footer")
{
	CHECK_EQ(
		TransferWndSeams::FormatQueueCountText(
			42u,
			0u,
			L"banned",
			10,
			12,
			18,
			50u,
			6000u * 1024u,
			6200u * 1024u),
		std::wstring(L"42 (0 banned) | UL 10/12-18 +50% | 5.9/6.1 MB/s 97%"));
	CHECK_EQ(
		TransferWndSeams::FormatQueueCountText(
			2u,
			1u,
			L"blocked",
			0,
			0,
			0,
			0u,
			0u,
			0u),
		std::wstring(L"2 (1 blocked) | UL 0/0-0 +0% | 0.0/0.0 MB/s 0%"));
	CHECK_EQ(TransferWndSeams::CalculateUploadUtilizationPercent(994u, 1000u), 99u);
	CHECK_EQ(TransferWndSeams::CalculateUploadUtilizationPercent(995u, 1000u), 100u);
	CHECK_EQ(TransferWndSeams::CalculateUploadUtilizationPercent(20000u, 1000u), TransferWndSeams::kUploadUtilizationDisplayPercentMax);
}

TEST_CASE("Transfer window seam calculates download buffer utilization")
{
	CHECK_EQ(TransferWndSeams::CalculateDownloadBufferUtilizationPercent(0u, 0u), 0u);
	CHECK_EQ(TransferWndSeams::CalculateDownloadBufferUtilizationPercent(994u, 1000u), 99u);
	CHECK_EQ(TransferWndSeams::CalculateDownloadBufferUtilizationPercent(995u, 1000u), 100u);
	CHECK_EQ(
		TransferWndSeams::CalculateDownloadBufferUtilizationPercent(20000u, 1000u),
		TransferWndSeams::kDownloadBufferUtilizationDisplayPercentMax);
	CHECK_EQ(
		TransferWndSeams::CalculateDownloadBufferUtilizationPercent((std::numeric_limits<std::uint64_t>::max)(), 1u),
		TransferWndSeams::kDownloadBufferUtilizationDisplayPercentMax);
}

TEST_CASE("Transfer window seam formats compact download metrics")
{
	CHECK_EQ(
		TransferWndSeams::FormatDownloadMetricsText(
			true,
			L"12 MB",
			L"512 MB",
			2u,
			L"",
			4u,
			L"8 MB",
			true,
			L"14 GB",
			61u),
		std::wstring(L"DL buf 12 MB/512 MB 2% | f=4 lg=8 MB | RAM 14 GB free 61%"));
	CHECK_EQ(
		TransferWndSeams::FormatDownloadMetricsText(
			true,
			L"12 MB",
			L"512 MB",
			2u,
			L"",
			4u,
			L"8 MB",
			false,
			L"",
			0u),
		std::wstring(L"DL buf 12 MB/512 MB 2% | f=4 lg=8 MB | RAM n/a"));
	CHECK_EQ(
		TransferWndSeams::FormatDownloadMetricsText(
			false,
			L"12 MB",
			L"",
			0u,
			L"256 KB",
			4u,
			L"8 MB",
			true,
			L"14 GB",
			61u),
		std::wstring(L"DL buf 12 MB | cap=256 KB | f=4 lg=8 MB | RAM 14 GB free 61%"));
	CHECK_EQ(
		TransferWndSeams::FormatDownloadMetricsText(
			false,
			L"12 MB",
			L"",
			0u,
			L"256 KB",
			4u,
			L"8 MB",
			false,
			L"",
			0u),
		std::wstring(L"DL buf 12 MB | cap=256 KB | f=4 lg=8 MB | RAM n/a"));
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
#ifdef EMULEBB_TEST_HAVE_CATEGORY_SHORTCUTS
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '0', true, false, false), 0);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', true, false, false), 1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '9', true, false, false), 9);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', false, false, false), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', true, true, false), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, '1', true, false, true), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYUP, '1', true, false, false), -1);
	CHECK_EQ(TransferWndSeams::GetCategoryShortcutIndex(WM_KEYDOWN, 'A', true, false, false), -1);
#else
	MESSAGE("Transfer category shortcut helpers are not available in this workspace.");
#endif
}

TEST_CASE("Transfer window seam maps direct list shortcuts")
{
#ifdef EMULEBB_TEST_HAVE_TRANSFER_LIST_SHORTCUTS
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
#else
	MESSAGE("Transfer direct list shortcut helpers are not available in this workspace.");
#endif
}

TEST_SUITE_END();
