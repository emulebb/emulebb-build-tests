#include "../third_party/doctest/doctest.h"
#include "KnownFileListSeams.h"
#include "KnownFileProgressSeams.h"
#if defined(__has_include)
#if __has_include("KnownFileLookupIndex.h")
#include "KnownFileLookupIndex.h"
#define EMULE_TESTS_HAS_KNOWN_FILE_LOOKUP_INDEX 1
#endif
#endif

TEST_SUITE_BEGIN("parity");

TEST_CASE("Known-file AICH purge seam keeps active hashsets for current files")
{
	CHECK_FALSE(ShouldPurgeKnownAICHHashset(true, false));
}

TEST_CASE("Known-file AICH purge seam drops hashsets for partially purged files")
{
	CHECK(ShouldPurgeKnownAICHHashset(true, true));
}

TEST_CASE("Known-file AICH purge seam drops orphaned hashsets without asserting")
{
	CHECK(ShouldPurgeKnownAICHHashset(false, false));
}

TEST_CASE("Known-file AICH purge seam drops orphaned partially purged hashsets too")
{
	CHECK(ShouldPurgeKnownAICHHashset(false, true));
}

#ifdef EMULE_TESTS_HAS_KNOWN_FILE_COLLISION_SEAMS
TEST_CASE("Known-file collision seam keeps existing shared entries")
{
	CHECK_EQ(
		ResolveKnownFileCollision(true, false, false, false),
		KnownFileCollisionDecision::KeepExisting);
}

TEST_CASE("Known-file collision seam keeps existing downloading entries")
{
	CHECK_EQ(
		ResolveKnownFileCollision(false, true, false, false),
		KnownFileCollisionDecision::KeepExisting);
}

TEST_CASE("Known-file collision seam adopts incoming shared entries over inactive existing entries")
{
	CHECK_EQ(
		ResolveKnownFileCollision(false, false, true, false),
		KnownFileCollisionDecision::AdoptIncoming);
}

TEST_CASE("Known-file collision seam adopts incoming downloading entries over inactive existing entries")
{
	CHECK_EQ(
		ResolveKnownFileCollision(false, false, false, true),
		KnownFileCollisionDecision::AdoptIncoming);
}

TEST_CASE("Known-file collision seam keeps existing entries when both sides are inactive")
{
	CHECK_EQ(
		ResolveKnownFileCollision(false, false, false, false),
		KnownFileCollisionDecision::KeepExisting);
}

TEST_CASE("Known-file collision seam keeps existing live entries even when incoming is live too")
{
	CHECK_EQ(
		ResolveKnownFileCollision(true, false, false, true),
		KnownFileCollisionDecision::KeepExisting);
	CHECK_EQ(
		ResolveKnownFileCollision(false, true, true, false),
		KnownFileCollisionDecision::KeepExisting);
}
#endif

#ifdef EMULE_TESTS_HAS_KNOWN_FILE_PUBLISH_SEAMS
TEST_CASE("Known-file publish seam suppresses redundant shared-files UI updates")
{
	CHECK_FALSE(ShouldNotifyPublishedED2KChange(false, false));
	CHECK_FALSE(ShouldNotifyPublishedED2KChange(true, true));
	CHECK(ShouldNotifyPublishedED2KChange(false, true));
	CHECK(ShouldNotifyPublishedED2KChange(true, false));
}
#endif

TEST_CASE("Known-file progress seam posts only for matching known-file owners")
{
	CHECK(IsCompatibleKnownFileProgressOwner(true, 1024u, 1024u));
	CHECK_FALSE(IsCompatibleKnownFileProgressOwner(false, 1024u, 1024u));
	CHECK_FALSE(IsCompatibleKnownFileProgressOwner(true, 1024u, 2048u));
}

TEST_CASE("Known-file progress seam accepts zero-length owners and rejects stale owners")
{
	CHECK(IsCompatibleKnownFileProgressOwner(true, 0u, 0u));
	CHECK_FALSE(IsCompatibleKnownFileProgressOwner(false, 0u, 0u));
	CHECK_FALSE(IsCompatibleKnownFileProgressOwner(true, 0u, 1u));
}

#ifdef EMULE_TESTS_HAS_KNOWN_FILE_LOOKUP_INDEX
TEST_CASE("Known-file lookup index returns the stored value for an exact filename/date/size triple")
{
	TKnownFileLookupIndex<int> index;
	index.Add(L"movie.mkv", 1700000000, 123456789u, 7);

	const auto *pBucket = index.FindBucket(L"movie.mkv", 1700000000, 123456789u);
	REQUIRE(pBucket != nullptr);
	REQUIRE_EQ(pBucket->size(), 1u);
	CHECK_EQ(pBucket->front(), 7);
}

TEST_CASE("Known-file lookup index keeps collision buckets for duplicate triples and removes individual values")
{
	TKnownFileLookupIndex<int> index;
	index.Add(L"duplicate.bin", 42, 99u, 1);
	index.Add(L"duplicate.bin", 42, 99u, 2);

	const auto *pBucket = index.FindBucket(L"duplicate.bin", 42, 99u);
	REQUIRE(pBucket != nullptr);
	CHECK_EQ(pBucket->size(), 2u);
	CHECK(index.Remove(L"duplicate.bin", 42, 99u, 1));

	pBucket = index.FindBucket(L"duplicate.bin", 42, 99u);
	REQUIRE(pBucket != nullptr);
	CHECK_EQ(pBucket->size(), 1u);
	CHECK_EQ(pBucket->front(), 2);
	CHECK(index.Remove(L"duplicate.bin", 42, 99u, 2));
	CHECK(index.FindBucket(L"duplicate.bin", 42, 99u) == nullptr);
}

TEST_CASE("Known-file lookup keys remain distinct when filename, time, or size changes")
{
	const KnownFileLookupKey base = BuildKnownFileLookupKey(L"alpha.iso", 100, 200u);
	CHECK(base == BuildKnownFileLookupKey(L"alpha.iso", 100, 200u));
	CHECK_FALSE(base == BuildKnownFileLookupKey(L"beta.iso", 100, 200u));
	CHECK_FALSE(base == BuildKnownFileLookupKey(L"alpha.iso", 101, 200u));
	CHECK_FALSE(base == BuildKnownFileLookupKey(L"alpha.iso", 100, 201u));
}
#endif

TEST_SUITE_END;
