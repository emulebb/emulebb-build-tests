#include "../third_party/doctest/doctest.h"

#include "BackgroundRefreshSeams.h"

TEST_SUITE_BEGIN("background_refresh");

TEST_CASE("Background refresh records attempts only after a worker starts")
{
	CHECK(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(true, true));
	CHECK_FALSE(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(false, true));
	CHECK_FALSE(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(true, false));
	CHECK_FALSE(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(false, false));
}

TEST_CASE("Background refresh queued state is a single-owner atomic gate")
{
	BackgroundRefreshSeams::SRefreshState state;
	CHECK_FALSE(BackgroundRefreshSeams::IsRefreshQueued(state));

	CHECK(BackgroundRefreshSeams::TryMarkRefreshQueued(state));
	CHECK(BackgroundRefreshSeams::IsRefreshQueued(state));
	CHECK_FALSE(BackgroundRefreshSeams::TryMarkRefreshQueued(state));

	BackgroundRefreshSeams::ClearRefreshQueued(state);
	CHECK_FALSE(BackgroundRefreshSeams::IsRefreshQueued(state));
	CHECK(BackgroundRefreshSeams::TryMarkRefreshQueued(state));
}

TEST_CASE("Background refresh completion fallback clears abandoned queued state")
{
	std::shared_ptr<BackgroundRefreshSeams::SRefreshState> state(std::make_shared<BackgroundRefreshSeams::SRefreshState>());
	REQUIRE(BackgroundRefreshSeams::TryMarkRefreshQueued(*state));

	const BackgroundRefreshSeams::SRefreshCompletionPostResult result = BackgroundRefreshSeams::PostRefreshCompletion(NULL, WM_USER + 1, true, state);
	CHECK_FALSE(result.bDelivered);
	CHECK_FALSE(BackgroundRefreshSeams::IsRefreshQueued(*state));
}

TEST_SUITE_END();
