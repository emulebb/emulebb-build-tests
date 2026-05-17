#include "../third_party/doctest/doctest.h"

#include "CommentDialogSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Comment dialog seam normalizes spam-filter token text")
{
	CHECK(CommentDialogSeams::NormalizeCommentFilterText(CString(_T(" spam |  Fake||Bad Signal "))) == CString(_T("spam|fake|bad signal")));
	CHECK(CommentDialogSeams::NormalizeCommentFilterText(CString(_T("|||"))) == CString());
	CHECK(CommentDialogSeams::NormalizeCommentFilterText(CString(_T(" One | one "))) == CString(_T("one|one")));
}

TEST_CASE("Comment dialog seam validates rating and merged-comment writes")
{
	CHECK(CommentDialogSeams::IsValidRatingSelection(0));
	CHECK(CommentDialogSeams::IsValidRatingSelection(5));
	CHECK_FALSE(CommentDialogSeams::IsValidRatingSelection(-1));
	CHECK_FALSE(CommentDialogSeams::IsValidRatingSelection(6));

	CHECK(CommentDialogSeams::ShouldWriteCommentText(false, true));
	CHECK(CommentDialogSeams::ShouldWriteCommentText(true, false));
	CHECK_FALSE(CommentDialogSeams::ShouldWriteCommentText(true, true));
}

TEST_CASE("Comment dialog seam owns button enablement and queue limits")
{
	CHECK(CommentDialogSeams::ShouldEnableCommentEditing(true));
	CHECK_FALSE(CommentDialogSeams::ShouldEnableCommentEditing(false));

	CHECK(CommentDialogSeams::ShouldEnableKadCommentSearchButton(true, true, true));
	CHECK_FALSE(CommentDialogSeams::ShouldEnableKadCommentSearchButton(false, true, true));
	CHECK_FALSE(CommentDialogSeams::ShouldEnableKadCommentSearchButton(true, false, true));
	CHECK_FALSE(CommentDialogSeams::ShouldEnableKadCommentSearchButton(true, true, false));

	CHECK(CommentDialogSeams::GetKadCommentSearchLimit(10, 3) == 3);
	CHECK(CommentDialogSeams::GetKadCommentSearchLimit(2, 3) == 2);
	CHECK(CommentDialogSeams::GetKadCommentSearchLimit(0, 3) == 0);
	CHECK(CommentDialogSeams::GetKadCommentSearchLimit(3, 0) == 0);
}

TEST_CASE("Comment dialog seam distinguishes editable and read-only Kad search eligibility")
{
	CHECK(CommentDialogSeams::CanQueueEditableKadCommentSearch(true, true, true, true, false, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueEditableKadCommentSearch(true, true, true, false, false, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueEditableKadCommentSearch(true, true, false, true, false, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueEditableKadCommentSearch(true, true, true, true, true, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueEditableKadCommentSearch(true, true, true, true, false, 3, 3));

	CHECK(CommentDialogSeams::CanQueueListKadCommentSearch(true, true, false, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueListKadCommentSearch(false, true, false, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueListKadCommentSearch(true, false, false, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueListKadCommentSearch(true, true, true, 0, 3));
	CHECK_FALSE(CommentDialogSeams::CanQueueListKadCommentSearch(true, true, false, 3, 3));
}

TEST_SUITE_END();
