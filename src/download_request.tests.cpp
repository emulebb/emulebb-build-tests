#include "../third_party/doctest/doctest.h"

#include "DownloadRequestSeams.h"

#include <cstdint>

TEST_CASE("Download request reserve preserves legacy slow-peer behavior")
{
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(0u, true), DownloadRequestSeams::kSlowDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kLegacyVerySlowDownloadThresholdBytesPerSec - 1u, true), DownloadRequestSeams::kSlowDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kLegacyVerySlowDownloadThresholdBytesPerSec, true), DownloadRequestSeams::kModerateSlowDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kLegacySlowDownloadThresholdBytesPerSec - 1u, true), DownloadRequestSeams::kModerateSlowDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kLegacySlowDownloadThresholdBytesPerSec, true), DownloadRequestSeams::kNormalDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kLegacyVerySlowDownloadThresholdBytesPerSec - 1u, false), DownloadRequestSeams::kNormalDownloadBlockReserve);
}

TEST_CASE("Download request reserve deepens only for broadband-rate peers")
{
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kFastDownloadThresholdBytesPerSec, false), DownloadRequestSeams::kNormalDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kFastDownloadThresholdBytesPerSec + 1u, false), DownloadRequestSeams::kFastDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kVeryFastDownloadThresholdBytesPerSec + 1u, false), DownloadRequestSeams::kVeryFastDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kBroadbandDownloadThresholdBytesPerSec, false), DownloadRequestSeams::kBroadbandDownloadBlockReserve);
	CHECK_EQ(DownloadRequestSeams::SelectDownloadBlockRequestReserve(DownloadRequestSeams::kVeryFastBroadbandDownloadThresholdBytesPerSec, false), DownloadRequestSeams::kVeryFastBroadbandDownloadBlockReserve);
}

TEST_CASE("Download request reserve rejects invalid local reserve sizes")
{
	CHECK_FALSE(DownloadRequestSeams::IsValidDownloadBlockRequestReserve(0));
	CHECK(DownloadRequestSeams::IsValidDownloadBlockRequestReserve(DownloadRequestSeams::kNormalDownloadBlockReserve));
	CHECK(DownloadRequestSeams::IsValidDownloadBlockRequestReserve(DownloadRequestSeams::kVeryFastBroadbandDownloadBlockReserve));
	CHECK_FALSE(DownloadRequestSeams::IsValidDownloadBlockRequestReserve(DownloadRequestSeams::kVeryFastBroadbandDownloadBlockReserve + 1));
}
