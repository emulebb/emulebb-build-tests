#include "../third_party/doctest/doctest.h"

#include "BBPreferenceMigrationSeams.h"
#include "MuleListCtrlSeams.h"

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

TEST_SUITE_END();
