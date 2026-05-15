#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "IPFilterSeams.h"
#include "IPFilterUpdateSeams.h"

#include <vector>

namespace
{
	/**
	 * @brief Builds a compact IP filter seam range for overlap-normalization tests.
	 */
	IPFilterSeams::IPRange MakeRange(uint32_t uStart, uint32_t uEnd, uint32_t uLevel, LPCSTR pszDescription)
	{
		IPFilterSeams::IPRange range;
		range.Start = uStart;
		range.End = uEnd;
		range.Level = uLevel;
		range.Description = pszDescription;
		return range;
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("IP-filter seam classifies long path names without fixed-buffer truncation")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x49504649u));

	const std::wstring guardingPath = fixture.MakeDirectoryChildPath(L"guarding.p2p.txt");
	const std::wstring prefixPath = fixture.MakeDirectoryChildPath(L"custom odd-[filter].prefix");
	const std::wstring pgPath = fixture.MakeDirectoryChildPath(L"custom odd-[guard].p2p");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(211u, 0x505047u);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(guardingPath, payload));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(prefixPath, payload));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(pgPath, payload));

	CHECK(IPFilterSeams::DetectFileTypeFromPath(CString(guardingPath.c_str())) == IPFilterSeams::PathHintPeerGuardian);
	CHECK(IPFilterSeams::DetectFileTypeFromPath(CString(prefixPath.c_str())) == IPFilterSeams::PathHintFilterDat);
	CHECK(IPFilterSeams::DetectFileTypeFromPath(CString(pgPath.c_str())) == IPFilterSeams::PathHintPeerGuardian);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(guardingPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(prefixPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(pgPath));
}

TEST_CASE("IP-filter seam leaves unknown file hints to content sniffing")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x554E4Bu));

	const std::wstring unknownPath = fixture.MakeDirectoryChildPath(L"list odd-[unknown].txt");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(unknownPath, LongPathTestSupport::BuildDeterministicPayload(77u, 0x123u)));

	CHECK(IPFilterSeams::DetectFileTypeFromPath(CString(_T("ipfilter.dat"))) == IPFilterSeams::PathHintUnknown);
	CHECK(IPFilterSeams::DetectFileTypeFromPath(CString(unknownPath.c_str())) == IPFilterSeams::PathHintUnknown);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(unknownPath));
}

TEST_CASE("IP-filter update seam clamps automatic update periods")
{
	CHECK(IPFilterUpdateSeams::NormalizeUpdatePeriodDays(0u) == IPFilterUpdateSeams::MinUpdatePeriodDays);
	CHECK(IPFilterUpdateSeams::NormalizeUpdatePeriodDays(1u) == 1u);
	CHECK(IPFilterUpdateSeams::NormalizeUpdatePeriodDays(7u) == 7u);
	CHECK(IPFilterUpdateSeams::NormalizeUpdatePeriodDays(366u) == IPFilterUpdateSeams::MaxUpdatePeriodDays);
}

TEST_CASE("IP-filter update seam detects due automatic refreshes")
{
	const __time64_t now = 1000000;
	CHECK(IPFilterUpdateSeams::IsAutomaticRefreshDue(now, 0, 7u));
	CHECK(IPFilterUpdateSeams::IsAutomaticRefreshDue(now, now - static_cast<__time64_t>(7) * 24 * 60 * 60, 7u));
	CHECK_FALSE(IPFilterUpdateSeams::IsAutomaticRefreshDue(now, now - static_cast<__time64_t>(6) * 24 * 60 * 60, 7u));
	CHECK_FALSE(IPFilterUpdateSeams::IsAutomaticRefreshDue(0, 0, 7u));
}

TEST_CASE("IP-filter update seam rejects markup download payloads")
{
	CHECK(IPFilterUpdateSeams::LooksLikeMarkupPayload(" \r\n<html><body>404</body>", 24u));
	CHECK(IPFilterUpdateSeams::LooksLikeMarkupPayload("\t<?xml version=\"1.0\"?>", 22u));
	CHECK(IPFilterUpdateSeams::LooksLikeMarkupPayload("<!DOCTYPE html>", 15u));
	CHECK_FALSE(IPFilterUpdateSeams::LooksLikeMarkupPayload("1.2.3.4 - 5.6.7.8 , 100 , test", 33u));
	CHECK_FALSE(IPFilterUpdateSeams::LooksLikeMarkupPayload("", 0u));
}

TEST_CASE("IP-filter seam bypasses runtime filtering when disabled")
{
	CHECK(IPFilterSeams::ShouldEvaluateFilter(true, 1u, 0x01020304u));
	CHECK_FALSE(IPFilterSeams::ShouldEvaluateFilter(false, 1u, 0x01020304u));
	CHECK_FALSE(IPFilterSeams::ShouldEvaluateFilter(true, 0u, 0x01020304u));
	CHECK_FALSE(IPFilterSeams::ShouldEvaluateFilter(true, 1u, 0u));
}

TEST_CASE("IP-filter startup load follows enabled preference")
{
	CHECK(IPFilterSeams::ShouldLoadAtStartup(true));
	CHECK_FALSE(IPFilterSeams::ShouldLoadAtStartup(false));
}

TEST_CASE("IP-filter automatic refresh requires filtering and auto update")
{
	CHECK(IPFilterSeams::ShouldQueueAutomaticRefresh(true, true));
	CHECK_FALSE(IPFilterSeams::ShouldQueueAutomaticRefresh(false, true));
	CHECK_FALSE(IPFilterSeams::ShouldQueueAutomaticRefresh(true, false));
	CHECK_FALSE(IPFilterSeams::ShouldQueueAutomaticRefresh(false, false));
}

TEST_CASE("IP-filter normalization lets a lower-level narrow overlap win only inside the overlap")
{
	const std::vector<IPFilterSeams::IPRange> normalized = IPFilterSeams::NormalizeIPRanges({
		MakeRange(10, 20, 100, "broad"),
		MakeRange(15, 17, 50, "narrow"),
	});

	REQUIRE(normalized.size() == 3u);
	CHECK(normalized[0].Start == 10u);
	CHECK(normalized[0].End == 14u);
	CHECK(normalized[0].Level == 100u);
	CHECK(normalized[1].Start == 15u);
	CHECK(normalized[1].End == 17u);
	CHECK(normalized[1].Level == 50u);
	CHECK(normalized[1].Description == "narrow");
	CHECK(normalized[2].Start == 18u);
	CHECK(normalized[2].End == 20u);
	CHECK(normalized[2].Level == 100u);
}

TEST_CASE("IP-filter normalization keeps a lower-level broad range effective across narrower overlaps")
{
	const std::vector<IPFilterSeams::IPRange> normalized = IPFilterSeams::NormalizeIPRanges({
		MakeRange(10, 20, 50, "broad"),
		MakeRange(15, 17, 100, "narrow"),
	});

	REQUIRE(normalized.size() == 1u);
	CHECK(normalized[0].Start == 10u);
	CHECK(normalized[0].End == 20u);
	CHECK(normalized[0].Level == 50u);
	CHECK(normalized[0].Description == "broad");
}

TEST_CASE("IP-filter normalization chooses the lowest level for identical ranges")
{
	const std::vector<IPFilterSeams::IPRange> normalized = IPFilterSeams::NormalizeIPRanges({
		MakeRange(10, 20, 100, "original"),
		MakeRange(10, 20, 25, "stricter"),
	});

	REQUIRE(normalized.size() == 1u);
	CHECK(normalized[0].Start == 10u);
	CHECK(normalized[0].End == 20u);
	CHECK(normalized[0].Level == 25u);
	CHECK(normalized[0].Description == "stricter");
}

TEST_CASE("IP-filter normalization merges adjacent same-level ranges")
{
	const std::vector<IPFilterSeams::IPRange> normalized = IPFilterSeams::NormalizeIPRanges({
		MakeRange(10, 20, 100, "first"),
		MakeRange(21, 30, 100, "second"),
	});

	REQUIRE(normalized.size() == 1u);
	CHECK(normalized[0].Start == 10u);
	CHECK(normalized[0].End == 30u);
	CHECK(normalized[0].Level == 100u);
	CHECK(normalized[0].Description == "first");
}

TEST_CASE("IP-filter normalization keeps adjacent different-level ranges separate")
{
	const std::vector<IPFilterSeams::IPRange> normalized = IPFilterSeams::NormalizeIPRanges({
		MakeRange(10, 20, 100, "first"),
		MakeRange(21, 30, 50, "second"),
	});

	REQUIRE(normalized.size() == 2u);
	CHECK(normalized[0].Start == 10u);
	CHECK(normalized[0].End == 20u);
	CHECK(normalized[0].Level == 100u);
	CHECK(normalized[1].Start == 21u);
	CHECK(normalized[1].End == 30u);
	CHECK(normalized[1].Level == 50u);
}

TEST_CASE("IP-filter normalization produces sorted non-overlapping output for stacked overlaps")
{
	const std::vector<IPFilterSeams::IPRange> normalized = IPFilterSeams::NormalizeIPRanges({
		MakeRange(30, 40, 100, "late"),
		MakeRange(10, 35, 80, "early"),
		MakeRange(20, 25, 20, "strict"),
		MakeRange(24, 45, 60, "middle"),
	});

	REQUIRE(normalized.size() == 3u);
	CHECK(normalized[0].Start == 10u);
	CHECK(normalized[0].End == 19u);
	CHECK(normalized[0].Level == 80u);
	CHECK(normalized[1].Start == 20u);
	CHECK(normalized[1].End == 25u);
	CHECK(normalized[1].Level == 20u);
	CHECK(normalized[2].Start == 26u);
	CHECK(normalized[2].End == 45u);
	CHECK(normalized[2].Level == 60u);
}

TEST_SUITE_END;
