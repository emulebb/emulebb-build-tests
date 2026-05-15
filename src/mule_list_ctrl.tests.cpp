#include "../third_party/doctest/doctest.h"

#include "BBPreferenceMigrationSeams.h"
#include "MuleListCtrlSeams.h"
#include "MuleListCtrlViewPresets.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("BB preference schema migration is marker driven")
{
	CHECK(BBPreferenceMigrationSeams::ShouldRunPreferenceMigration(0));
	CHECK(BBPreferenceMigrationSeams::ShouldRunPreferenceMigration(BBPreferenceMigrationSeams::kCurrentPreferenceSchema - 1));
	CHECK_FALSE(BBPreferenceMigrationSeams::ShouldRunPreferenceMigration(BBPreferenceMigrationSeams::kCurrentPreferenceSchema));
	CHECK_FALSE(BBPreferenceMigrationSeams::ShouldRunPreferenceMigration(BBPreferenceMigrationSeams::kCurrentPreferenceSchema + 1));
	CHECK(CString(BBPreferenceMigrationSeams::kPreferenceSchemaKey) == CString(_T("BBPreferenceSchema")));
}

TEST_CASE("BB preference schema migration targets only main-grid list controls")
{
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlName(_T("DownloadListCtrl")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlName(_T("SearchListCtrl")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlName(_T("SharedFilesCtrl")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlName(_T("UploadListCtrl")));
	CHECK_FALSE(BBPreferenceMigrationSeams::IsMainGridListControlName(_T("IPFilterDlg")));
	CHECK_FALSE(BBPreferenceMigrationSeams::IsMainGridListControlName(_T("ArchivePreviewDlg")));
}

TEST_CASE("BB preference schema migration resets the reviewed list-control state")
{
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlResetSuffix(_T("ColumnOrders")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlResetSuffix(_T("ColumnHidden")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlResetSuffix(_T("ColumnWidths")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlResetSuffix(_T("TableSortItem")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlResetSuffix(_T("TableSortAscending")));
	CHECK(BBPreferenceMigrationSeams::IsMainGridListControlResetSuffix(_T("SortHistory")));
	CHECK_FALSE(BBPreferenceMigrationSeams::IsMainGridListControlResetSuffix(_T("Unknown")));
	CHECK(BBPreferenceMigrationSeams::BuildListControlSetupKey(_T("DownloadListCtrl"), _T("ColumnOrders")) == CString(_T("DownloadListCtrlColumnOrders")));
}

TEST_CASE("Mule list column order validation requires a complete permutation")
{
	const int valid[] = {0, 2, 1, 3};
	const int duplicate[] = {0, 2, 2, 3};
	const int outOfRange[] = {0, 2, 4, 3};
	const int negative[] = {0, -1, 2, 3};

	CHECK(MuleListCtrlSeams::IsCompleteColumnOrder(valid, _countof(valid)));
	CHECK_FALSE(MuleListCtrlSeams::IsCompleteColumnOrder(duplicate, _countof(duplicate)));
	CHECK_FALSE(MuleListCtrlSeams::IsCompleteColumnOrder(outOfRange, _countof(outOfRange)));
	CHECK_FALSE(MuleListCtrlSeams::IsCompleteColumnOrder(negative, _countof(negative)));
	CHECK_FALSE(MuleListCtrlSeams::IsCompleteColumnOrder(nullptr, 4));
	CHECK_FALSE(MuleListCtrlSeams::IsCompleteColumnOrder(valid, 0));
}

TEST_CASE("Mule list view preset commands map every Tools menu action")
{
	MuleListCtrlViewPresets::ETableViewPreset preset = MuleListCtrlViewPresets::ETableViewPreset::Stock;
	MuleListCtrlViewPresets::EColumnWidthMode widthMode = MuleListCtrlViewPresets::EColumnWidthMode::Preserve;

	CHECK(MuleListCtrlViewPresets::TryGetViewPresetCommand(MP_HM_VIEW_PRESET_STOCK_KEEP_WIDTHS, preset, widthMode));
	CHECK(preset == MuleListCtrlViewPresets::ETableViewPreset::Stock);
	CHECK(widthMode == MuleListCtrlViewPresets::EColumnWidthMode::Preserve);
	CHECK(MuleListCtrlViewPresets::TryGetViewPresetCommand(MP_HM_VIEW_PRESET_STOCK_RESET_WIDTHS, preset, widthMode));
	CHECK(preset == MuleListCtrlViewPresets::ETableViewPreset::Stock);
	CHECK(widthMode == MuleListCtrlViewPresets::EColumnWidthMode::Reset);
	CHECK(MuleListCtrlViewPresets::TryGetViewPresetCommand(MP_HM_VIEW_PRESET_EXTENDED_KEEP_WIDTHS, preset, widthMode));
	CHECK(preset == MuleListCtrlViewPresets::ETableViewPreset::Extended);
	CHECK(widthMode == MuleListCtrlViewPresets::EColumnWidthMode::Preserve);
	CHECK(MuleListCtrlViewPresets::TryGetViewPresetCommand(MP_HM_VIEW_PRESET_EXTENDED_RESET_WIDTHS, preset, widthMode));
	CHECK(preset == MuleListCtrlViewPresets::ETableViewPreset::Extended);
	CHECK(widthMode == MuleListCtrlViewPresets::EColumnWidthMode::Reset);
	CHECK(MuleListCtrlViewPresets::TryGetViewPresetCommand(MP_HM_VIEW_PRESET_FULL_KEEP_WIDTHS, preset, widthMode));
	CHECK(preset == MuleListCtrlViewPresets::ETableViewPreset::Full);
	CHECK(widthMode == MuleListCtrlViewPresets::EColumnWidthMode::Preserve);
	CHECK(MuleListCtrlViewPresets::TryGetViewPresetCommand(MP_HM_VIEW_PRESET_FULL_RESET_WIDTHS, preset, widthMode));
	CHECK(preset == MuleListCtrlViewPresets::ETableViewPreset::Full);
	CHECK(widthMode == MuleListCtrlViewPresets::EColumnWidthMode::Reset);
	CHECK_FALSE(MuleListCtrlViewPresets::TryGetViewPresetCommand(MP_HM_SAVE_PREFERENCES_NOW, preset, widthMode));
}

TEST_CASE("Mule list view preset profiles are complete and scoped to main grids")
{
	for (const MuleListCtrlViewPresets::SListControlViewPresetProfile &profile : MuleListCtrlViewPresets::kProfiles) {
		CHECK(MuleListCtrlViewPresets::IsProfileValid(profile));
		CHECK(BBPreferenceMigrationSeams::IsMainGridListControlName(profile.pszControlName));
		CHECK(MuleListCtrlViewPresets::FindProfile(profile.pszControlName) == &profile);
	}

	const MuleListCtrlViewPresets::SListControlViewPresetProfile *download = MuleListCtrlViewPresets::FindProfile(_T("DownloadListCtrl"));
	REQUIRE(download != nullptr);
	CHECK(download->iStockHiddenColumnCount == 4);
	CHECK(download->iExtendedHiddenColumnCount == 0);

	const MuleListCtrlViewPresets::SListControlViewPresetProfile *search = MuleListCtrlViewPresets::FindProfile(_T("SearchListCtrl"));
	REQUIRE(search != nullptr);
	CHECK(search->iColumnCount == 16);
	CHECK(search->iStockHiddenColumnCount == 3);
	CHECK(search->iExtendedHiddenColumnCount == 2);
	CHECK(search->piExtendedOrder[6] == 14);
	CHECK(search->piExtendedOrder[15] == 15);
	CHECK(search->piStockHiddenColumns[2] == 15);
	CHECK(search->piExtendedHiddenColumns[1] == 15);

	const MuleListCtrlViewPresets::SListControlViewPresetProfile *shared = MuleListCtrlViewPresets::FindProfile(_T("SharedFilesCtrl"));
	REQUIRE(shared != nullptr);
	CHECK(shared->iStockHiddenColumnCount == 9);
	CHECK(shared->iExtendedHiddenColumnCount == 7);

	const MuleListCtrlViewPresets::SListControlViewPresetProfile *server = MuleListCtrlViewPresets::FindProfile(_T("ServerListCtrl"));
	REQUIRE(server != nullptr);
	CHECK(server->iStockHiddenColumnCount == 2);
	CHECK(server->iExtendedHiddenColumnCount == 0);
	CHECK(MuleListCtrlViewPresets::FindProfile(_T("IPFilterDlg")) == nullptr);
}

TEST_CASE("Mule list view preset reset policy preserves widths only by request")
{
	CHECK(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("ColumnOrders"), MuleListCtrlViewPresets::EColumnWidthMode::Preserve));
	CHECK(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("ColumnHidden"), MuleListCtrlViewPresets::EColumnWidthMode::Preserve));
	CHECK(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("TableSortItem"), MuleListCtrlViewPresets::EColumnWidthMode::Preserve));
	CHECK(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("TableSortAscending"), MuleListCtrlViewPresets::EColumnWidthMode::Preserve));
	CHECK(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("SortHistory"), MuleListCtrlViewPresets::EColumnWidthMode::Preserve));
	CHECK_FALSE(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("ColumnWidths"), MuleListCtrlViewPresets::EColumnWidthMode::Preserve));
	CHECK(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("ColumnWidths"), MuleListCtrlViewPresets::EColumnWidthMode::Reset));
	CHECK_FALSE(MuleListCtrlViewPresets::ShouldResetPresetSuffix(_T("Unknown"), MuleListCtrlViewPresets::EColumnWidthMode::Reset));
}

TEST_SUITE_END();
