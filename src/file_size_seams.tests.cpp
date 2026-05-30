#include "../third_party/doctest/doctest.h"

#include "FileSizeSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("File-size seam preserves explicit unsigned EMFileSize boundaries")
{
	const EMFileSize nSmall = FileSizeSeams::FromUInt64(32u);

	CHECK(FileSizeSeams::ToUInt64(nSmall) == 32u);
	CHECK(FileSizeSeams::ToUInt64(FileSizeSeams::FromUInt64(MAX_EMULE_FILE_SIZE)) == MAX_EMULE_FILE_SIZE);
}

TEST_CASE("File-size seam rejects signed platform lengths outside network limits")
{
	CHECK(FileSizeSeams::IsSupportedNetworkFileSize(static_cast<sint64>(0)));
	CHECK(FileSizeSeams::IsSupportedNetworkFileSize(static_cast<sint64>(MAX_EMULE_FILE_SIZE)));
	CHECK_FALSE(FileSizeSeams::IsSupportedNetworkFileSize(static_cast<sint64>(-1)));
	CHECK_FALSE(FileSizeSeams::IsSupportedNetworkFileSize(static_cast<sint64>(MAX_EMULE_FILE_SIZE) + 1));

	CHECK(FileSizeSeams::ToUInt64(FileSizeSeams::FromSignedFileLength(0)) == 0u);
	CHECK(FileSizeSeams::ToUInt64(FileSizeSeams::FromSignedFileLength(1234)) == 1234u);
}

TEST_SUITE_END();
