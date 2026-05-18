#include "../third_party/doctest/doctest.h"

#include "MediaMetadataFallbackSeams.h"

#include <cstring>
#include <vector>

namespace
{
void AppendBe32(std::vector<std::uint8_t> &bytes, std::uint32_t value)
{
	bytes.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
	bytes.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
	bytes.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
	bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::vector<std::uint8_t> Box(std::uint32_t type, const std::vector<std::uint8_t> &payload)
{
	std::vector<std::uint8_t> box;
	AppendBe32(box, static_cast<std::uint32_t>(payload.size() + 8));
	AppendBe32(box, type);
	box.insert(box.end(), payload.begin(), payload.end());
	return box;
}

std::vector<std::uint8_t> BuildMp4Fixture()
{
	std::vector<std::uint8_t> bytes = Box(0x66747970u, {'i', 's', 'o', 'm', 0, 0, 0, 0});
	std::vector<std::uint8_t> mvhd(12, 0);
	AppendBe32(mvhd, 1000);
	AppendBe32(mvhd, 125000);
	std::vector<std::uint8_t> tkhd(84, 0);
	tkhd[76] = 0x07;
	tkhd[77] = 0x80;
	tkhd[80] = 0x04;
	tkhd[81] = 0x38;
	std::vector<std::uint8_t> trak = Box(0x746b6864u, tkhd);
	trak = Box(0x7472616bu, trak);
	std::vector<std::uint8_t> moov = Box(0x6d766864u, mvhd);
	moov.insert(moov.end(), trak.begin(), trak.end());
	moov = Box(0x6d6f6f76u, moov);
	bytes.insert(bytes.end(), moov.begin(), moov.end());
	return bytes;
}

std::vector<std::uint8_t> BuildEbmlFixture()
{
	std::vector<std::uint8_t> bytes = {0x1A, 0x45, 0xDF, 0xA3, 0x80};
	bytes.insert(bytes.end(), {0x2A, 0xD7, 0xB1, 0x83, 0x0F, 0x42, 0x40});
	double duration = 120000.0;
	std::uint64_t raw = 0;
	memcpy(&raw, &duration, sizeof raw);
	bytes.insert(bytes.end(), {0x44, 0x89, 0x88});
	for (int shift = 56; shift >= 0; shift -= 8)
		bytes.push_back(static_cast<std::uint8_t>((raw >> shift) & 0xff));
	bytes.insert(bytes.end(), {0xB0, 0x82, 0x07, 0x80});
	bytes.insert(bytes.end(), {0xBA, 0x82, 0x04, 0x38});
	return bytes;
}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Media metadata fallback seam parses MP4 duration and dimensions")
{
	const std::vector<std::uint8_t> bytes = BuildMp4Fixture();
	MediaMetadataFallbackSeams::SBasicMediaInfo info;

	REQUIRE(MediaMetadataFallbackSeams::TryReadMp4Basics(bytes.data(), bytes.size(), info));

	CHECK(info.strContainer == CString(_T("MP4")));
	CHECK(info.fDurationSec == doctest::Approx(125.0));
	CHECK(info.uWidth == 1920);
	CHECK(info.uHeight == 1080);
	CHECK(info.iVideoStreams >= 1);
}

TEST_CASE("Media metadata fallback seam parses EBML duration and dimensions")
{
	const std::vector<std::uint8_t> bytes = BuildEbmlFixture();
	MediaMetadataFallbackSeams::SBasicMediaInfo info;

	REQUIRE(MediaMetadataFallbackSeams::TryReadEbmlBasics(bytes.data(), bytes.size(), info));

	CHECK(info.strContainer == CString(_T("Matroska/WebM")));
	CHECK(info.fDurationSec == doctest::Approx(120.0));
	CHECK(info.uWidth == 1920);
	CHECK(info.uHeight == 1080);
	CHECK(info.iVideoStreams == 1);
}

TEST_CASE("Media metadata fallback seam reports only material variant divergence")
{
	MediaMetadataFallbackSeams::SVariantSummary expected;
	expected.strName = _T("MediaInfo.dll");
	expected.bSucceeded = true;
	expected.info.fDurationSec = 120.0;
	expected.info.uWidth = 1920;
	expected.info.uHeight = 1080;
	MediaMetadataFallbackSeams::SVariantSummary actual = expected;
	actual.strName = _T("Media Foundation");
	actual.info.fDurationSec = 120.4;
	std::vector<CString> findings;

	MediaMetadataFallbackSeams::AppendDivergenceFindings(expected, actual, findings);
	CHECK(findings.empty());

	actual.info.uWidth = 1280;
	MediaMetadataFallbackSeams::AppendDivergenceFindings(expected, actual, findings);
	REQUIRE(findings.size() == 1);
	CHECK(findings[0].Find(_T("width differs")) >= 0);
}

TEST_SUITE_END;
