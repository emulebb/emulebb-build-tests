#include "../third_party/doctest/doctest.h"

#include "SharedDirsTreeCtrlSeams.h"

TEST_SUITE_BEGIN("shared_dirs_tree_ctrl");

TEST_CASE("Shared directories tree commits drag state only after full image drag startup")
{
	using SharedDirsTreeCtrlSeams::ShouldCommitDragStartState;

	CHECK_FALSE(ShouldCommitDragStartState(false, false, false));
	CHECK_FALSE(ShouldCommitDragStartState(true, false, false));
	CHECK_FALSE(ShouldCommitDragStartState(true, true, false));
	CHECK(ShouldCommitDragStartState(true, true, true));
}

TEST_SUITE_END();
