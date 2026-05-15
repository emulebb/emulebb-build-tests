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

TEST_SUITE_END();
