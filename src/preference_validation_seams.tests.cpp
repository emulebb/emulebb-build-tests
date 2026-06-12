#include "../third_party/doctest/doctest.h"

#include "PreferenceValidationSeams.h"
#include "PartFilePreviewSeams.h"
#include "WebApiSurfaceSeams.h"

#include <limits>

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
	CHECK(PreferenceValidationSeams::kDefaultConfiguredUploadLimitKiB == 6200u);
	CHECK(PreferenceValidationSeams::NormalizeConfiguredUploadLimitKiB(512u) == 512u);
	CHECK(PreferenceValidationSeams::NormalizeConfiguredDownloadLimitKiB(0u) == 1u);
	CHECK(PreferenceValidationSeams::NormalizeConfiguredDownloadLimitKiB(4096u) == 4096u);

	CHECK(PreferenceValidationSeams::NormalizeQueueSize(1) == static_cast<std::int64_t>(PreferenceValidationSeams::kMinQueueSize));
	CHECK(PreferenceValidationSeams::NormalizeQueueSize(5000) == 5000);
	CHECK(PreferenceValidationSeams::NormalizeQueueSize(20000) == static_cast<std::int64_t>(PreferenceValidationSeams::kMaxQueueSize));
	CHECK(PreferenceValidationSeams::NormalizeUploadSlots(0u) == static_cast<std::uint32_t>(PreferenceValidationSeams::kMinUploadSlots));
	CHECK(PreferenceValidationSeams::NormalizeUploadSlots(99u) == static_cast<std::uint32_t>(PreferenceValidationSeams::kMaxUploadSlots));
	CHECK(PreferenceValidationSeams::kMaxUploadSlots == 64u);
	CHECK(PreferenceValidationSeams::kMaxEffectiveUploadSlots == 128u);
	CHECK(PreferenceValidationSeams::kDefaultMaxUploadSlots == 12u);
	CHECK(PreferenceValidationSeams::kDefaultUploadSlotElasticPercent == 80u);
	CHECK(PreferenceValidationSeams::NormalizeUploadSlotElasticPercent(101u) == PreferenceValidationSeams::kMaxUploadSlotElasticPercent);
	CHECK(PreferenceValidationSeams::GetElasticUploadSlotCap(10u, 50u) == 15u);
	CHECK(PreferenceValidationSeams::GetElasticUploadSlotCap(63u, 1u) == 64u);
	CHECK(PreferenceValidationSeams::GetElasticUploadSlotCap(64u, 100u) == PreferenceValidationSeams::kMaxEffectiveUploadSlots);
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
	CHECK(WebApiSurfaceSeams::IsUploadSlotElasticPercentPreferenceValue(PreferenceValidationSeams::kMaxUploadSlotElasticPercent));
	CHECK_FALSE(WebApiSurfaceSeams::IsUploadSlotElasticPercentPreferenceValue(PreferenceValidationSeams::kMaxUploadSlotElasticPercent + 1u));
}

TEST_CASE("Preference validation seam centralizes random listener port range")
{
	CHECK(PreferenceValidationSeams::kRandomListenerPortMin == 49152u);
	CHECK(PreferenceValidationSeams::kRandomListenerPortMax == 65535u);
	CHECK(PreferenceValidationSeams::kRandomListenerPortRange == 16384u);

	CHECK_FALSE(PreferenceValidationSeams::IsRandomListenerPort(49151u));
	CHECK(PreferenceValidationSeams::IsRandomListenerPort(49152u));
	CHECK(PreferenceValidationSeams::IsRandomListenerPort(65535u));

	CHECK(PreferenceValidationSeams::GetAdjacentRandomListenerPort(49152u) == 49153u);
	CHECK(PreferenceValidationSeams::GetAdjacentRandomListenerPort(50000u) == 49999u);
	CHECK(PreferenceValidationSeams::GetAdjacentRandomListenerPort(65535u) == 65534u);
}

TEST_CASE("Preference validation seam centralizes broadband upload policy ranges")
{
	CHECK(PreferenceValidationSeams::NormalizeUploadSlots(PreferenceValidationSeams::kDefaultMaxUploadSlots) == PreferenceValidationSeams::kDefaultMaxUploadSlots);
	CHECK(PreferenceValidationSeams::NormalizeUploadSlotElasticPercent(PreferenceValidationSeams::kDefaultUploadSlotElasticPercent) == PreferenceValidationSeams::kDefaultUploadSlotElasticPercent);

	CHECK(PreferenceValidationSeams::NormalizeSlowUploadThresholdFactor(0.01f) == PreferenceValidationSeams::kMinSlowUploadThresholdFactor);
	CHECK(PreferenceValidationSeams::kDefaultSlowUploadThresholdFactor == 0.75f);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadThresholdFactor(0.70f) == 0.70f);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadThresholdFactor(2.0f) == PreferenceValidationSeams::kMaxSlowUploadThresholdFactor);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadThresholdFactor(std::numeric_limits<float>::quiet_NaN()) == PreferenceValidationSeams::kDefaultSlowUploadThresholdFactor);

	CHECK(PreferenceValidationSeams::NormalizeSlowUploadGraceSeconds(0u) == PreferenceValidationSeams::kMinSlowUploadGraceSeconds);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadGraceSeconds(30u) == 30u);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadGraceSeconds(301u) == PreferenceValidationSeams::kMaxSlowUploadGraceSeconds);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadWarmupSeconds(0u) == 0u);
	CHECK(PreferenceValidationSeams::kDefaultSlowUploadWarmupSeconds == 30u);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadWarmupSeconds(3601u) == PreferenceValidationSeams::kMaxSlowUploadWarmupSeconds);
	CHECK(PreferenceValidationSeams::NormalizeZeroUploadRateGraceSeconds(0u) == PreferenceValidationSeams::kMinZeroUploadRateGraceSeconds);
	CHECK(PreferenceValidationSeams::kDefaultZeroUploadRateGraceSeconds == 5u);
	CHECK(PreferenceValidationSeams::NormalizeZeroUploadRateGraceSeconds(121u) == PreferenceValidationSeams::kMaxZeroUploadRateGraceSeconds);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadCooldownSeconds(0u) == PreferenceValidationSeams::kMinSlowUploadCooldownSeconds);
	CHECK(PreferenceValidationSeams::kDefaultSlowUploadCooldownSeconds == 30u);
	CHECK(PreferenceValidationSeams::NormalizeSlowUploadCooldownSeconds(3601u) == PreferenceValidationSeams::kMaxSlowUploadCooldownSeconds);

	CHECK(PreferenceValidationSeams::NormalizeLowRatioThreshold(-1.0f) == PreferenceValidationSeams::kMinLowRatioThreshold);
	CHECK(PreferenceValidationSeams::NormalizeLowRatioThreshold(0.5f) == PreferenceValidationSeams::kDefaultLowRatioThreshold);
	CHECK(PreferenceValidationSeams::NormalizeLowRatioThreshold(3.0f) == PreferenceValidationSeams::kMaxLowRatioThreshold);
	CHECK(PreferenceValidationSeams::NormalizeLowRatioBonus(501u) == PreferenceValidationSeams::kMaxLowRatioBonus);
	CHECK(PreferenceValidationSeams::NormalizeLowIDDivisor(0u) == PreferenceValidationSeams::kMinLowIDDivisor);
	CHECK(PreferenceValidationSeams::NormalizeLowIDDivisor(9u) == PreferenceValidationSeams::kMaxLowIDDivisor);

	CHECK(PreferenceValidationSeams::kDefaultSessionTransferPercent == 90u);
	CHECK(PreferenceValidationSeams::kDefaultSessionTimeLimitSeconds == 7200u);
	CHECK(PreferenceValidationSeams::NormalizeSessionTransferLimitMode(9) == PreferenceValidationSeams::kSessionTransferModePercentOfFile);
	CHECK(PreferenceValidationSeams::NormalizeSessionTransferLimitValue(PreferenceValidationSeams::kSessionTransferModePercentOfFile, 0u) == PreferenceValidationSeams::kMinSessionTransferPercent);
	CHECK(PreferenceValidationSeams::NormalizeSessionTransferLimitValue(PreferenceValidationSeams::kSessionTransferModeAbsoluteMiB, 4097u) == PreferenceValidationSeams::kMaxSessionTransferMiB);
	CHECK(PreferenceValidationSeams::NormalizeSessionTransferLimitValue(PreferenceValidationSeams::kSessionTransferModeDisabled, 5000u) == PreferenceValidationSeams::kMaxSessionTransferMiB);
	CHECK(PreferenceValidationSeams::NormalizeSessionTimeLimitSeconds(0u) == 0u);
	CHECK(PreferenceValidationSeams::NormalizeSessionTimeLimitSeconds(86401u) == PreferenceValidationSeams::kMaxSessionTimeLimitSeconds);
}

TEST_CASE("Preference validation seam derives upload slots from requested client data rate")
{
	CHECK(PreferenceValidationSeams::DeriveUploadSlotsForClientDataRate(12u, 3u * 1024u) == 4u);
	CHECK(PreferenceValidationSeams::DeriveUploadSlotsForClientDataRate(1u, 1024u * 1024u) == PreferenceValidationSeams::kMinUploadSlots);
	CHECK(PreferenceValidationSeams::DeriveUploadSlotsForClientDataRate(1024u, 1u) == PreferenceValidationSeams::kMaxUploadSlots);
	CHECK(PreferenceValidationSeams::DeriveUploadSlotsForClientDataRate(0u, 1024u) == 3u);
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
