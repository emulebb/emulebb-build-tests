#include "../third_party/doctest/doctest.h"

#include "PacketsSeams.h"

TEST_SUITE_BEGIN("packets");

TEST_CASE("Packet integer tag seam keeps ordinary values compact")
{
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(0u, false), TAGTYPE_UINT32);
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(UINT32_MAX, false), TAGTYPE_UINT32);
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(42u, true), TAGTYPE_UINT64);
}

TEST_CASE("Packet integer tag seam promotes values that cannot fit in uint32")
{
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(static_cast<uint64_t>(UINT32_MAX) + 1u, false), TAGTYPE_UINT64);
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(UINT64_MAX, false), TAGTYPE_UINT64);
}

TEST_SUITE_END();
