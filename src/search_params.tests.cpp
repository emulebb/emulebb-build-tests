#include "../third_party/doctest/doctest.h"
#include "SearchParamsPolicy.h"

TEST_SUITE_BEGIN("divergence");

TEST_CASE("Removed search methods fall back to the server search type")
{
	CHECK_EQ(SearchParamsPolicy::kDefaultSearchType, 1u);
	CHECK_EQ(SearchParamsPolicy::kMaxSupportedSearchType, 3u);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(0u), 0u);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(1u), 1u);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(2u), 2u);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(3u), 3u);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(4u), 1u);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(-1), 1u);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(256), 1u);
}
