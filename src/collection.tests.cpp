#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include "CollectionSeams.h"

#include <limits>
#include <vector>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Collection seam builds exact message and signature spans from serialized data")
{
	CollectionSignatureLayout layout = {};
	CHECK(TryBuildCollectionSignatureLayout(24u, 16u, layout));
	CHECK(layout.nMessageLength == 16u);
	CHECK(layout.nSignatureLength == 8u);
}

TEST_CASE("Collection seam rejects impossible signature layouts and oversized serialized lengths")
{
	CollectionSignatureLayout layout = {};
	CHECK_FALSE(TryBuildCollectionSignatureLayout(16u, 16u, layout));
	CHECK_FALSE(TryBuildCollectionSignatureLayout(15u, 16u, layout));
	CHECK_FALSE(TryBuildCollectionSignatureLayout(static_cast<ULONGLONG>((std::numeric_limits<UINT>::max)()) + 1ull, 16u, layout));
}

TEST_CASE("Collection seam validates signed payload length conversion for on-disk writes")
{
	uint32 dwSerializedLength = 0;
	CHECK(TryConvertCollectionSerializedLength(4096u, dwSerializedLength));
	CHECK(dwSerializedLength == 4096u);
	CHECK_FALSE(TryConvertCollectionSerializedLength(static_cast<ULONGLONG>((std::numeric_limits<uint32>::max)()) + 1ull, dwSerializedLength));
}

TEST_CASE("Collection seam keeps malformed single-entry imports skippable")
{
	CHECK(ShouldContinueAfterCollectionEntryFailure());
}

#if defined(EMULE_TEST_HAVE_COLLECTION_FILE_IMPORT_SEAMS)
TEST_CASE("Collection seam rejects hostile collection-file entry tag counts")
{
	CHECK(HasSaneCollectionFileTagCount(4u, 5u, 1u));
	CHECK(HasSaneCollectionFileTagCount(4u, 260u, COLLECTION_FILE_MAX_ENTRY_TAGS));

	CHECK_FALSE(HasSaneCollectionFileTagCount(6u, 5u, 0u));
	CHECK_FALSE(HasSaneCollectionFileTagCount(4u, 4u, 1u));
	CHECK_FALSE(HasSaneCollectionFileTagCount(4u, 300u, COLLECTION_FILE_MAX_ENTRY_TAGS + 1u));
	CHECK_FALSE(HasSaneCollectionFileTagCount(4u, 10u, 7u));
}

TEST_CASE("Collection seam makes collection-file entry failure policy explicit")
{
	CHECK(ShouldSkipMalformedCollectionFileTag());
	CHECK(ShouldRejectCollectionFileWithoutHash());
	CHECK(ShouldIgnoreInvalidCollectionAICHHash());
}
#endif

#if defined(EMULE_TEST_HAVE_COLLECTION_REJECTED_IMPORT_SEAM)
TEST_CASE("Collection seam treats rejected imported entries as caller-owned")
{
	CHECK(ShouldDisposeRejectedCollectionImportEntry());
}
#endif

#if defined(EMULE_TEST_HAVE_COLLECTION_OWNERSHIP_SEAMS)
TEST_CASE("Collection seam keeps author-key ownership and raw-view state in sync")
{
	std::vector<BYTE> keyData;
	uint32 nKeySize = 0;
	const BYTE rawKey[] = {0x10u, 0x20u, 0x30u};

	AssignCollectionAuthorKey(rawKey, 3u, keyData, nKeySize);
	const BYTE *pKeyData = GetCollectionAuthorKeyData(keyData);
	REQUIRE(pKeyData != NULL);
	CHECK(nKeySize == 3u);
	CHECK(keyData.size() == 3u);

	ClearCollectionAuthorKey(keyData, nKeySize);
	pKeyData = GetCollectionAuthorKeyData(keyData);
	CHECK(pKeyData == NULL);
	CHECK(nKeySize == 0u);
}
#endif

TEST_SUITE_END;
