#include "../third_party/doctest/doctest.h"

#include <cstdint>
#include <limits>

namespace
{
bool IsDeadlineReached(std::uint64_t nowTick, std::uint64_t startTick, std::uint64_t intervalMs)
{
	return nowTick - startTick >= intervalMs;
}

std::uint64_t RemainingIntervalMs(std::uint64_t nowTick, std::uint64_t startTick, std::uint64_t intervalMs)
{
	const std::uint64_t elapsedMs = nowTick - startTick;
	return elapsedMs < intervalMs ? intervalMs - elapsedMs : 0;
}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("64-bit deadline checks stay correct well beyond DWORD_MAX")
{
	const std::uint64_t startTick = 0x1'0000'0000ULL + 1234;
	const std::uint64_t intervalMs = 5000;

	CHECK_FALSE(IsDeadlineReached(startTick + intervalMs - 1, startTick, intervalMs));
	CHECK(IsDeadlineReached(startTick + intervalMs, startTick, intervalMs));
	CHECK(IsDeadlineReached(startTick + intervalMs + 1, startTick, intervalMs));
}

TEST_CASE("64-bit remaining-interval math preserves reask timing past the legacy rollover boundary")
{
	const std::uint64_t lastAskedTick = 0x1'0000'0000ULL + 42;
	const std::uint64_t reaskIntervalMs = 30'000;

	CHECK(RemainingIntervalMs(lastAskedTick, lastAskedTick, reaskIntervalMs) == reaskIntervalMs);
	CHECK(RemainingIntervalMs(lastAskedTick + reaskIntervalMs - 1, lastAskedTick, reaskIntervalMs) == 1);
	CHECK(RemainingIntervalMs(lastAskedTick + reaskIntervalMs, lastAskedTick, reaskIntervalMs) == 0);
}

TEST_CASE("64-bit fixed-window expiry math preserves ban and cleanup thresholds after 49 days")
{
	const std::uint64_t baseTick = 0x1'0000'0000ULL + 10'000;
	const std::uint64_t banWindowMs = 2ULL * 60 * 60 * 1000;
	const std::uint64_t cleanupWindowMs = 20ULL * 60 * 1000;

	CHECK_FALSE(IsDeadlineReached(baseTick + banWindowMs - 1, baseTick, banWindowMs));
	CHECK(IsDeadlineReached(baseTick + banWindowMs, baseTick, banWindowMs));

	CHECK_FALSE(IsDeadlineReached(baseTick + cleanupWindowMs - 1, baseTick, cleanupWindowMs));
	CHECK(IsDeadlineReached(baseTick + cleanupWindowMs, baseTick, cleanupWindowMs));
}

TEST_CASE("Elapsed tick math preserves ban and timeout thresholds when 64-bit addition would wrap")
{
	const std::uint64_t startTick = std::numeric_limits<std::uint64_t>::max() - 10;
	const std::uint64_t intervalMs = 25;
	const std::uint64_t beforeDeadline = startTick + intervalMs - 1;
	const std::uint64_t atDeadline = startTick + intervalMs;

	CHECK_FALSE(IsDeadlineReached(beforeDeadline, startTick, intervalMs));
	CHECK_EQ(RemainingIntervalMs(beforeDeadline, startTick, intervalMs), static_cast<std::uint64_t>(1u));
	CHECK(IsDeadlineReached(atDeadline, startTick, intervalMs));
	CHECK_EQ(RemainingIntervalMs(atDeadline, startTick, intervalMs), static_cast<std::uint64_t>(0u));
}
