#include "../third_party/doctest/doctest.h"

#include "PreferenceValidationSeams.h"
#include "PartFilePreviewSeams.h"
#include "WebApiSurfaceSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Preference validation seam centralizes core numeric ranges")
{
	CHECK(PreferenceValidationSeams::NormalizeNonNegativeInt(-1, 7u) == 7u);
	CHECK(PreferenceValidationSeams::NormalizeNonNegativeInt(0, 7u) == 0u);
	CHECK(PreferenceValidationSeams::NormalizeBoundedInt(-1, 5u, 2u, 9u) == 5u);
	CHECK(PreferenceValidationSeams::NormalizeBoundedInt(1, 5u, 2u, 9u) == 2u);
	CHECK(PreferenceValidationSeams::NormalizeBoundedInt(12, 5u, 2u, 9u) == 9u);
	CHECK(PreferenceValidationSeams::NormalizePositiveIntOrDefault(0, 11u) == 11u);
	CHECK(PreferenceValidationSeams::NormalizePositiveUIntOrDefault(0u, 11u) == 11u);
	CHECK_FALSE(PreferenceValidationSeams::IsPositiveBounded(0u, 10u));
	CHECK(PreferenceValidationSeams::IsPositiveBounded(10u, 10u));
	CHECK_FALSE(PreferenceValidationSeams::IsPositiveBounded(11u, 10u));
	CHECK(PreferenceValidationSeams::NormalizePositiveBoundedIntOrDefault(0, 3u, 10u) == 3u);
	CHECK(PreferenceValidationSeams::NormalizePositiveBoundedIntOrDefault(9, 3u, 10u) == 9u);
	CHECK(PreferenceValidationSeams::NormalizePositiveBoundedIntOrDefault(11, 3u, 10u) == 3u);

	CHECK(PreferenceValidationSeams::NormalizeConfiguredUploadLimitKiB(0u) == PreferenceValidationSeams::kDefaultConfiguredUploadLimitKiB);
	CHECK(PreferenceValidationSeams::NormalizeConfiguredUploadLimitKiB(PreferenceValidationSeams::kUnlimitedBandwidthSentinelKiB) == PreferenceValidationSeams::kDefaultConfiguredUploadLimitKiB);
	CHECK(PreferenceValidationSeams::NormalizeConfiguredUploadLimitKiB(512u) == 512u);
	CHECK(PreferenceValidationSeams::NormalizeConfiguredDownloadLimitKiB(0u) == 1u);
	CHECK(PreferenceValidationSeams::NormalizeConfiguredDownloadLimitKiB(4096u) == 4096u);

	CHECK(PreferenceValidationSeams::NormalizeQueueSize(1) == static_cast<std::int64_t>(PreferenceValidationSeams::kMinQueueSize));
	CHECK(PreferenceValidationSeams::NormalizeQueueSize(5000) == 5000);
	CHECK(PreferenceValidationSeams::NormalizeQueueSize(20000) == static_cast<std::int64_t>(PreferenceValidationSeams::kMaxQueueSize));
	CHECK(PreferenceValidationSeams::NormalizeUploadSlots(0u) == static_cast<std::uint32_t>(PreferenceValidationSeams::kMinUploadSlots));
	CHECK(PreferenceValidationSeams::NormalizeUploadSlots(99u) == static_cast<std::uint32_t>(PreferenceValidationSeams::kMaxUploadSlots));
}

TEST_CASE("Preference validation seam centralizes public REST preference ranges")
{
	CHECK_FALSE(PreferenceValidationSeams::IsFiniteBandwidthLimitKiB(0u));
	CHECK(PreferenceValidationSeams::IsFiniteBandwidthLimitKiB(1u));
	CHECK(PreferenceValidationSeams::IsFiniteBandwidthLimitKiB(PreferenceValidationSeams::kMaxFiniteBandwidthLimitKiB));
	CHECK_FALSE(PreferenceValidationSeams::IsFiniteBandwidthLimitKiB(PreferenceValidationSeams::kUnlimitedBandwidthSentinelKiB));

	CHECK_FALSE(PreferenceValidationSeams::IsPositiveSignedIntValue(0u));
	CHECK(PreferenceValidationSeams::IsPositiveSignedIntValue(PreferenceValidationSeams::kMaxSignedIntPreference));
	CHECK_FALSE(PreferenceValidationSeams::IsPositiveSignedIntValue(PreferenceValidationSeams::kMaxSignedIntPreference + 1u));
	CHECK(PreferenceValidationSeams::IsPositiveUInt32Value(UINT32_MAX));

	CHECK_FALSE(PreferenceValidationSeams::IsQueueSize(PreferenceValidationSeams::kMinQueueSize - 1u));
	CHECK(PreferenceValidationSeams::IsQueueSize(PreferenceValidationSeams::kMinQueueSize));
	CHECK(PreferenceValidationSeams::IsQueueSize(PreferenceValidationSeams::kMaxQueueSize));
	CHECK_FALSE(PreferenceValidationSeams::IsQueueSize(PreferenceValidationSeams::kMaxQueueSize + 1u));

	CHECK_FALSE(PreferenceValidationSeams::IsUploadSlotCount(0u));
	CHECK(PreferenceValidationSeams::IsUploadSlotCount(PreferenceValidationSeams::kMinUploadSlots));
	CHECK(PreferenceValidationSeams::IsUploadSlotCount(PreferenceValidationSeams::kMaxUploadSlots));
	CHECK_FALSE(PreferenceValidationSeams::IsUploadSlotCount(PreferenceValidationSeams::kMaxUploadSlots + 1u));

	CHECK(WebApiSurfaceSeams::kMutablePreferenceMaxFiniteKiBps == PreferenceValidationSeams::kMaxFiniteBandwidthLimitKiB);
	CHECK(WebApiSurfaceSeams::IsFiniteKiBpsPreferenceValue(PreferenceValidationSeams::kMaxFiniteBandwidthLimitKiB));
	CHECK(WebApiSurfaceSeams::IsQueueSizePreferenceValue(PreferenceValidationSeams::kDefaultQueueSize));
	CHECK(WebApiSurfaceSeams::IsUploadSlotPreferenceValue(PreferenceValidationSeams::kMaxUploadSlots));
}

TEST_CASE("Preference validation seam centralizes video thumbnail interval bounds")
{
	CHECK(PreferenceValidationSeams::NormalizeVideoThumbnailIntervalSeconds(0u) == 0u);
	CHECK(PreferenceValidationSeams::NormalizeVideoThumbnailIntervalSeconds(1u) == PreferenceValidationSeams::kVideoThumbnailMinIntervalSeconds);
	CHECK(PreferenceValidationSeams::NormalizeVideoThumbnailIntervalSeconds(90u) == 90u);
	CHECK(PreferenceValidationSeams::NormalizeVideoThumbnailIntervalSeconds(901u) == PreferenceValidationSeams::kVideoThumbnailMaxIntervalSeconds);

	CHECK(PartFilePreviewSeams::kVideoThumbnailDefaultIntervalSeconds == PreferenceValidationSeams::kVideoThumbnailDefaultIntervalSeconds);
	CHECK(PartFilePreviewSeams::kVideoThumbnailMinIntervalSeconds == PreferenceValidationSeams::kVideoThumbnailMinIntervalSeconds);
	CHECK(PartFilePreviewSeams::kVideoThumbnailMaxIntervalSeconds == PreferenceValidationSeams::kVideoThumbnailMaxIntervalSeconds);
	CHECK(PartFilePreviewSeams::NormalizeVideoThumbnailIntervalSeconds(29u) == PreferenceValidationSeams::kVideoThumbnailMinIntervalSeconds);
}

TEST_SUITE_END();
