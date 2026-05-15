#include "../third_party/doctest/doctest.h"

#include "CategoryDialogSeams.h"

#include <vector>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Category dialog seam normalizes user-entered text")
{
	CHECK(CategoryDialogSeams::NormalizeCategoryTitle(CString(_T("  Movies  "))) == CString(_T("Movies")));
	CHECK(CategoryDialogSeams::NormalizeCategoryText(CString(_T("  C:\\Downloads\\Movies  "))) == CString(_T("C:\\Downloads\\Movies")));
	CHECK(CategoryDialogSeams::AreCategoryTitlesEquivalent(CString(_T(" Movies ")), CString(_T("movies"))));
}

TEST_CASE("Category dialog seam detects duplicate titles outside the edited category")
{
	const std::vector<CString> categoryTitles = {
		CString(),
		CString(_T("Movies")),
		CString(_T("Music")),
		CString(_T("Linux ISOs"))
	};

	CHECK(CategoryDialogSeams::CategoryTitleExists(CString(_T(" music ")), categoryTitles, -1));
	CHECK_FALSE(CategoryDialogSeams::CategoryTitleExists(CString(_T(" music ")), categoryTitles, 2));
	CHECK_FALSE(CategoryDialogSeams::CategoryTitleExists(CString(_T("   ")), categoryTitles, -1));
	CHECK_FALSE(CategoryDialogSeams::CategoryTitleExists(CString(_T("Books")), categoryTitles, -1));
}

TEST_CASE("Category dialog seam clamps unsupported priorities")
{
	CHECK(CategoryDialogSeams::NormalizeCategoryPriority(CategoryDialogSeams::kCategoryPriorityLow) == CategoryDialogSeams::kCategoryPriorityLow);
	CHECK(CategoryDialogSeams::NormalizeCategoryPriority(CategoryDialogSeams::kCategoryPriorityNormal) == CategoryDialogSeams::kCategoryPriorityNormal);
	CHECK(CategoryDialogSeams::NormalizeCategoryPriority(CategoryDialogSeams::kCategoryPriorityHigh) == CategoryDialogSeams::kCategoryPriorityHigh);
	CHECK(CategoryDialogSeams::NormalizeCategoryPriority(99) == CategoryDialogSeams::kCategoryPriorityNormal);
}

TEST_CASE("Category manager seam keeps built-in and assigned categories protected")
{
	CHECK_FALSE(CategoryDialogSeams::IsCustomCategory(0, 3));
	CHECK(CategoryDialogSeams::IsCustomCategory(1, 3));
	CHECK_FALSE(CategoryDialogSeams::IsCustomCategory(3, 3));

	CHECK_FALSE(CategoryDialogSeams::CanRemoveCategory(0, 3, 0));
	CHECK_FALSE(CategoryDialogSeams::CanRemoveCategory(1, 3, 2));
	CHECK(CategoryDialogSeams::CanRemoveCategory(1, 3, 0));
}

TEST_CASE("Category manager seam validates move bounds and captions")
{
	CHECK_FALSE(CategoryDialogSeams::CanMoveCategoryUp(1, 4));
	CHECK(CategoryDialogSeams::CanMoveCategoryUp(2, 4));
	CHECK(CategoryDialogSeams::CanMoveCategoryDown(1, 4));
	CHECK_FALSE(CategoryDialogSeams::CanMoveCategoryDown(3, 4));

	CHECK(CategoryDialogSeams::GetCategoryDialogCaptionResourceId(true) == IDS_CAT_ADD);
	CHECK(CategoryDialogSeams::GetCategoryDialogCaptionResourceId(false) == IDS_EDITCAT);
}

TEST_SUITE_END();
