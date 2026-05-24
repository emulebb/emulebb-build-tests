#include "../third_party/doctest/doctest.h"

#include "KnownFileHashOpenSeams.h"

TEST_SUITE_BEGIN("known_file_hash_open");

TEST_CASE("Known-file hashing retries only transient sharing failures")
{
	CHECK(KnownFileHashOpenSeams::IsRetryableHashOpenError(ERROR_SHARING_VIOLATION));
	CHECK(KnownFileHashOpenSeams::IsRetryableHashOpenError(ERROR_LOCK_VIOLATION));
	CHECK_FALSE(KnownFileHashOpenSeams::IsRetryableHashOpenError(ERROR_FILE_NOT_FOUND));
	CHECK_FALSE(KnownFileHashOpenSeams::IsRetryableHashOpenError(ERROR_ACCESS_DENIED));
}

TEST_CASE("Known-file hashing retry budget is bounded")
{
	CHECK(KnownFileHashOpenSeams::ShouldRetryHashOpen(ERROR_SHARING_VIOLATION, 0u, 3u));
	CHECK(KnownFileHashOpenSeams::ShouldRetryHashOpen(ERROR_LOCK_VIOLATION, 1u, 3u));
	CHECK_FALSE(KnownFileHashOpenSeams::ShouldRetryHashOpen(ERROR_SHARING_VIOLATION, 2u, 3u));
	CHECK_FALSE(KnownFileHashOpenSeams::ShouldRetryHashOpen(ERROR_ACCESS_DENIED, 0u, 3u));
}

TEST_SUITE_END();
