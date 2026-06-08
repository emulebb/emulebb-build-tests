#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include "FileBufferSlider.h"
#include "BroadbandIoSeams.h"
#include "Opcodes.h"

namespace
{
	constexpr unsigned kDefaultMaxHalfOpenConnections = 50u;
	constexpr unsigned kDefaultMaxConnectionsPerFiveSeconds = 50u;
	constexpr unsigned kMinTimeoutSeconds = 5u;
	constexpr unsigned kDefaultConnectionTimeoutSeconds = 30u;
	constexpr unsigned kDefaultDownloadTimeoutSeconds = 75u;
	constexpr unsigned kDefaultKadFileSearchTotal = 750u;
	constexpr unsigned kDefaultKadKeywordSearchTotal = 750u;
	constexpr unsigned kDefaultKadFileSearchLifetimeSeconds = 90u;
	constexpr unsigned kDefaultKadKeywordSearchLifetimeSeconds = 90u;
	constexpr unsigned kMinKadSearchTotal = 100u;
	constexpr unsigned kMaxKadSearchTotal = 5000u;
	constexpr unsigned kMinKadSearchLifetimeSeconds = 30u;
	constexpr unsigned kMaxKadSearchLifetimeSeconds = 180u;
	constexpr bool kDefaultGeoLocationEnabled = true;
	constexpr unsigned kDefaultGeoLocationCheckDays = 30u;
	constexpr int kDefaultCreateCrashDumpMode = 1;

	constexpr unsigned long NormalizeTimeoutSeconds(const unsigned seconds, const unsigned defaultSeconds) noexcept
	{
		const unsigned normalizedSeconds = (seconds == 0u) ? defaultSeconds : ((seconds < kMinTimeoutSeconds) ? kMinTimeoutSeconds : seconds);
		return static_cast<unsigned long>(normalizedSeconds) * 1000ul;
	}

	constexpr unsigned TimeoutMsToSeconds(const unsigned long milliseconds) noexcept
	{
		return static_cast<unsigned>(milliseconds / 1000ul);
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Modern limits default timeouts match the FEAT_018 targets")
{
	CHECK_EQ(kDefaultConnectionTimeoutSeconds, 30u);
	CHECK_EQ(kDefaultDownloadTimeoutSeconds, 75u);
	CHECK_EQ(static_cast<unsigned long>(UDPMAXQUEUETIME), static_cast<unsigned long>(SEC2MS(20)));
	CHECK_EQ(static_cast<unsigned>(CONNECTION_LATENCY), 15000u);
}

TEST_CASE("Modern limits exposed defaults match the FEAT_019 targets")
{
	CHECK_EQ(kDefaultMaxHalfOpenConnections, 50u);
	CHECK_EQ(kDefaultMaxConnectionsPerFiveSeconds, 50u);
	CHECK_EQ(static_cast<unsigned>(MAX_SOURCES_FILE_SOFT), 1000u);
	CHECK_EQ(static_cast<unsigned>(MAX_SOURCES_FILE_UDP), 100u);
	CHECK_EQ(static_cast<unsigned>(UPLOAD_CLIENT_MAXDATARATE), 8u * 1024u * 1024u);
}

TEST_CASE("Search and bootstrap defaults match the reviewed preference targets")
{
	CHECK_EQ(kDefaultKadFileSearchTotal, 750u);
	CHECK_EQ(kDefaultKadKeywordSearchTotal, 750u);
	CHECK_EQ(kDefaultKadFileSearchLifetimeSeconds, 90u);
	CHECK_EQ(kDefaultKadKeywordSearchLifetimeSeconds, 90u);
	CHECK_EQ(kMinKadSearchTotal, 100u);
	CHECK_EQ(kMaxKadSearchTotal, 5000u);
	CHECK_EQ(kMinKadSearchLifetimeSeconds, 30u);
	CHECK_EQ(kMaxKadSearchLifetimeSeconds, 180u);
	CHECK(kDefaultGeoLocationEnabled);
	CHECK_EQ(kDefaultGeoLocationCheckDays, 30u);
	CHECK_EQ(kDefaultCreateCrashDumpMode, 1);
}

TEST_CASE("Modern limits timeout normalization keeps invalid values bounded")
{
	CHECK_EQ(NormalizeTimeoutSeconds(0u, kDefaultConnectionTimeoutSeconds), 30000ul);
	CHECK_EQ(NormalizeTimeoutSeconds(1u, kDefaultConnectionTimeoutSeconds), 5000ul);
	CHECK_EQ(NormalizeTimeoutSeconds(75u, kDefaultDownloadTimeoutSeconds), 75000ul);
}

TEST_CASE("Modern limits timeout serialization round-trips whole seconds")
{
	CHECK_EQ(TimeoutMsToSeconds(NormalizeTimeoutSeconds(30u, kDefaultConnectionTimeoutSeconds)), 30u);
	CHECK_EQ(TimeoutMsToSeconds(NormalizeTimeoutSeconds(75u, kDefaultDownloadTimeoutSeconds)), 75u);
}

TEST_CASE("File buffer slider preserves small KiB values and reaches the larger MiB range")
{
	CHECK_EQ(FileBufferSlider::PositionToBytes(FileBufferSlider::kMinPosition), 16u * 1024u);
	CHECK_EQ(FileBufferSlider::PositionToBytes(FileBufferSlider::BytesToPosition(256u * 1024u)), 256u * 1024u);
	CHECK_EQ(FileBufferSlider::PositionToBytes(FileBufferSlider::BytesToPosition(1024u * 1024u)), 1024u * 1024u);
	CHECK_EQ(FileBufferSlider::PositionToBytes(FileBufferSlider::BytesToPosition(64u * 1024u * 1024u)), 64u * 1024u * 1024u);
	CHECK_EQ(FileBufferSlider::PositionToBytes(FileBufferSlider::kMaxPosition), FileBufferSlider::kMaxFileBufferSizeBytes);
}

TEST_CASE("Broadband IO auto mode derives adaptive global download budget from available memory")
{
	CHECK_EQ(
		BroadbandIoSeams::BuildAdaptiveGlobalDownloadBufferBudgetBytes(0u),
		BroadbandIoSeams::kMinAdaptiveGlobalDownloadBufferBudgetBytes);
	CHECK_EQ(
		BroadbandIoSeams::BuildAdaptiveGlobalDownloadBufferBudgetBytes(1024ull * 1024ull * 1024ull),
		BroadbandIoSeams::kMinAdaptiveGlobalDownloadBufferBudgetBytes);
	CHECK_EQ(
		BroadbandIoSeams::BuildAdaptiveGlobalDownloadBufferBudgetBytes(8ull * 1024ull * 1024ull * 1024ull),
		2ull * 1024ull * 1024ull * 1024ull);
	CHECK_EQ(
		BroadbandIoSeams::BuildAdaptiveGlobalDownloadBufferBudgetBytes(64ull * 1024ull * 1024ull * 1024ull),
		BroadbandIoSeams::kMaxAdaptiveGlobalDownloadBufferBudgetBytes);
}

TEST_CASE("Broadband IO auto mode allocates file buffer allowance by demand")
{
	constexpr std::uint64_t configured = 64ull * 1024ull * 1024ull;
	constexpr std::uint64_t budget = 1024ull * 1024ull * 1024ull;

	CHECK_EQ(BroadbandIoSeams::BuildDemandBasedFileBufferSizeBytes(false, configured, budget, 0u, 8u, 0u), configured);
	CHECK_EQ(BroadbandIoSeams::BuildDemandBasedFileBufferSizeBytes(true, configured, budget, 0u, 1u, 0u), budget);
	CHECK_EQ(BroadbandIoSeams::BuildDemandBasedFileBufferSizeBytes(true, configured, budget, 128ull * 1024ull * 1024ull, 8u, 4ull * 1024ull * 1024ull), configured);
	CHECK_EQ(BroadbandIoSeams::BuildDemandBasedFileBufferSizeBytes(true, configured, budget, 512ull * 1024ull * 1024ull, 8u, 256ull * 1024ull * 1024ull), 768ull * 1024ull * 1024ull);
	CHECK_EQ(BroadbandIoSeams::BuildDemandBasedFileBufferSizeBytes(true, configured, budget, budget, 8u, 512ull * 1024ull * 1024ull), 512ull * 1024ull * 1024ull);
}

TEST_CASE("Broadband IO auto mode treats zero global budget as no adaptive cap")
{
	constexpr std::uint64_t configured = 64ull * 1024ull * 1024ull;
	CHECK_EQ(BroadbandIoSeams::BuildDemandBasedFileBufferSizeBytes(true, configured, 0u, 0u, 64u, 0u), configured);
}

TEST_CASE("Broadband IO auto mode selects largest buffered file when global budget is exhausted")
{
	constexpr std::uint64_t budget = 1024ull * 1024ull * 1024ull;
	CHECK_FALSE(BroadbandIoSeams::ShouldFlushLargestFileForAdaptiveGlobalBudget(false, budget, budget + 1u, budget + 1u, budget + 1u));
	CHECK_FALSE(BroadbandIoSeams::ShouldFlushLargestFileForAdaptiveGlobalBudget(true, budget, budget, budget, budget));
	CHECK_FALSE(BroadbandIoSeams::ShouldFlushLargestFileForAdaptiveGlobalBudget(true, budget, budget + 1u, 128ull * 1024ull * 1024ull, 256ull * 1024ull * 1024ull));
	CHECK(BroadbandIoSeams::ShouldFlushLargestFileForAdaptiveGlobalBudget(true, budget, budget + 1u, 256ull * 1024ull * 1024ull, 256ull * 1024ull * 1024ull));
}

TEST_CASE("Broadband IO seam exposes legacy metadata file buffer sizes")
{
	CHECK_EQ(BroadbandIoSeams::kLegacyStandardMetadataFileBufferBytes, static_cast<std::size_t>(16u * 1024u));
	CHECK_EQ(BroadbandIoSeams::kLegacyLargeMetadataFileBufferBytes, static_cast<std::size_t>(32u * 1024u));
}
