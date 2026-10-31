#include "../third_party/doctest/doctest.h"

#include "DiagEventWriterSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Diagnostic writer prunes closed segments outside any retention bound")
{
	const uint64_t ullMaximumTotalBytes = 256ull * 1024ull * 1024ull;

	CHECK(DiagEventWriterSeams::ShouldPruneRetainedSegment(
		false, true, 1u, 1u, ullMaximumTotalBytes));
	CHECK(DiagEventWriterSeams::ShouldPruneRetainedSegment(
		false, false, DiagEventWriterSeams::kDefaultRetainedSegments + 1u, 1u, ullMaximumTotalBytes));
	CHECK(DiagEventWriterSeams::ShouldPruneRetainedSegment(
		false, false, 2u, ullMaximumTotalBytes + 1u, ullMaximumTotalBytes));
	CHECK_FALSE(DiagEventWriterSeams::ShouldPruneRetainedSegment(
		false, false, 2u, ullMaximumTotalBytes, ullMaximumTotalBytes));
}

TEST_CASE("Diagnostic writer never prunes its active segment")
{
	CHECK_FALSE(DiagEventWriterSeams::ShouldPruneRetainedSegment(
		true,
		true,
		DiagEventWriterSeams::kDefaultRetainedSegments + 1u,
		UINT64_MAX,
		0u));
}

TEST_SUITE_END;
