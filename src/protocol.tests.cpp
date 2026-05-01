#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"
#include <cstring>
#include <limits>
#include <vector>
#include "ProtocolGuards.h"
#include "ProtocolParsers.h"
#include "ServerConnectionGuards.h"

/**
 * @brief Enables the target-only protocol guard coverage that depends on newer helper APIs.
 */
#if defined(__has_include)
#if __has_include("MappedFileReader.h")
#define EMULE_HAS_EXTENDED_PROTOCOL_GUARDS 1
#endif
#endif

namespace
{
	static const size_t TCP_READ_BUFFER_SIZE = 2000000u;
	static const uint32 MAX_PROTOCOL_TAGS = 256u;
	static const uint32 IPV4_BROADCAST = 0xFFFFFFFFu;
	static const unsigned long long FNV1A64_OFFSET = 14695981039346656037ull;
	static const unsigned long long FNV1A64_PRIME = 1099511628211ull;

	struct ReleaseSearchPacketGoldenVector
	{
		const char *pszTerm;
		uint32 nPacketLength;
		size_t nTagTotalSize;
		unsigned long long nFnv1a64;
	};

	/**
	 * Computes the stable FNV-1a digest used by protocol golden-vector tests.
	 */
	unsigned long long ComputeFnv1a64(const std::vector<BYTE> &rBytes)
	{
		unsigned long long nHash = FNV1A64_OFFSET;
		for (BYTE byValue : rBytes) {
			nHash ^= static_cast<unsigned long long>(byValue);
			nHash *= FNV1A64_PRIME;
		}
		return nHash;
	}

	/**
	 * Builds the canonical release live-wire search packet fixture.
	 */
	std::vector<BYTE> BuildReleaseSearchPacketFixture(const char *pszTerm)
	{
		const size_t nTermLength = std::strlen(pszTerm);
		REQUIRE(nTermLength <= 0xFFFFu);
		const uint32 nPacketLength = static_cast<uint32>(1u + 2u + 2u + nTermLength);
		std::vector<BYTE> bytes;
		bytes.reserve(static_cast<size_t>(PROTOCOL_PACKET_HEADER_SIZE) + nPacketLength - 1u);
		bytes.push_back(static_cast<BYTE>(OP_EDONKEYPROT));
		bytes.push_back(static_cast<BYTE>(nPacketLength & 0xFFu));
		bytes.push_back(static_cast<BYTE>((nPacketLength >> 8) & 0xFFu));
		bytes.push_back(static_cast<BYTE>((nPacketLength >> 16) & 0xFFu));
		bytes.push_back(static_cast<BYTE>((nPacketLength >> 24) & 0xFFu));
		bytes.push_back(static_cast<BYTE>(OP_SEARCHREQUEST));
		bytes.push_back(static_cast<BYTE>(TAGTYPE_STRING | 0x80u));
		bytes.push_back(static_cast<BYTE>(CT_NAME));
		bytes.push_back(static_cast<BYTE>(nTermLength & 0xFFu));
		bytes.push_back(static_cast<BYTE>((nTermLength >> 8) & 0xFFu));
		for (size_t i = 0; i < nTermLength; ++i)
			bytes.push_back(static_cast<BYTE>(pszTerm[i]));
		return bytes;
	}

	/**
	 * Keeps the packet fixtures readable when asserting serialized header decode paths.
	 */
	ProtocolPacketHeader ParsePacketHeaderFixture(const BYTE *pFixture, size_t nFixtureSize)
	{
		ProtocolPacketHeader header = {};
		REQUIRE(TryParsePacketHeader(pFixture, nFixtureSize, &header));
		return header;
	}

	/**
	 * Keeps the tag fixtures readable when asserting serialized tag span decode paths.
	 */
	ProtocolTagSpan ParseTagFixture(const BYTE *pFixture, size_t nFixtureSize)
	{
		ProtocolTagSpan span = {};
		REQUIRE(TryParseTagSpan(pFixture, nFixtureSize, &span));
		return span;
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Protocol guard rejects oversized TCP payloads")
{
	CHECK_FALSE(CanReadTcpPacketPayload(static_cast<uint32>(TCP_READ_BUFFER_SIZE + 2), TCP_READ_BUFFER_SIZE));
}

TEST_CASE("Protocol guard accepts the largest TCP payload that fits the receive buffer")
{
	CHECK(CanReadTcpPacketPayload(static_cast<uint32>(TCP_READ_BUFFER_SIZE + 1), TCP_READ_BUFFER_SIZE));
}

TEST_CASE("Protocol guard rejects zero-length TCP headers at the receive gate")
{
	CHECK_FALSE(CanReadTcpPacketPayload(0, TCP_READ_BUFFER_SIZE));
}

TEST_CASE("Protocol guard accepts a reasonable tag count for the remaining packet bytes")
{
	CHECK(HasSaneTagCount(8, 16, 4, MAX_PROTOCOL_TAGS));
}

TEST_CASE("Protocol guard accepts compressed UDP payloads that include at least one body byte")
{
	CHECK(HasCompressedUdpPayload(3));
}

TEST_CASE("Protocol guard accepts exact-fit packet spans and bounded size arithmetic")
{
#if defined(EMULE_HAS_EXTENDED_PROTOCOL_GUARDS)
	size_t nCombinedSize = 0;
	size_t nExpandedSize = 0;
	CHECK(CanReadPacketSpan(24, 16, 8));
	CHECK(TryAddSize(32, 10, &nCombinedSize));
	CHECK_EQ(nCombinedSize, static_cast<size_t>(42));
	CHECK(TryMultiplyAddSize(32, 10, 300, &nExpandedSize));
	CHECK_EQ(nExpandedSize, static_cast<size_t>(620));
#else
	MESSAGE("Extended protocol guard helpers are not available in this workspace.");
#endif
}

TEST_CASE("Protocol guard accepts restorable TCP header fragments and minimal callback or block packet headers")
{
#if defined(EMULE_HAS_EXTENDED_PROTOCOL_GUARDS)
	CHECK(CanRestoreTcpPendingHeader(PROTOCOL_PACKET_HEADER_SIZE - 1, PROTOCOL_PACKET_HEADER_SIZE, TCP_READ_BUFFER_SIZE));
	CHECK(CanStoreTcpPendingHeader(PROTOCOL_PACKET_HEADER_SIZE - 1, PROTOCOL_PACKET_HEADER_SIZE));
	CHECK(CanContinuePacketAssembly(100, 100));
	CHECK(HasUdpCallbackPayload(17));
	CHECK(HasDownloadBlockPacketHeader(24, false, false));
#else
	MESSAGE("Extended protocol guard helpers are not available in this workspace.");
#endif
}

TEST_CASE("Protocol guard accepts blob payloads that stay within the remaining packet bytes")
{
	CHECK(CanReadBlobPayload(8, 16, 4));
}

TEST_CASE("Protocol guard keeps integer progress percentages stable for valid denominators")
{
	CHECK_EQ(CalculateProgressPercent(25, 100), static_cast<uint32>(25));
}

TEST_CASE("Protocol guard keeps floating-point progress ratios stable for valid denominators")
{
	CHECK_EQ(CalculateProgressRatio(25.0f, 100.0f), doctest::Approx(0.25f));
}

TEST_CASE("Protocol guard parses ordinary dotted IPv4 literals")
{
	uint32 nAddress = 0;
	CHECK(TryParseDottedIPv4Literal("1.2.3.4", &nAddress));
	CHECK_EQ(nAddress, static_cast<uint32>(0x04030201u));
}

TEST_CASE("Protocol parser decodes the smallest legal packet header from serialized bytes")
{
	const BYTE fixture[] = {
		OP_EDONKEYPROT,
		0x01, 0x00, 0x00, 0x00,
		OP_HELLO
	};

	const ProtocolPacketHeader header = ParsePacketHeaderFixture(fixture, sizeof(fixture));
	CHECK_EQ(header.nProtocol, static_cast<uint8>(OP_EDONKEYPROT));
	CHECK_EQ(header.nOpcode, static_cast<uint8>(OP_HELLO));
	CHECK_EQ(header.nPacketLength, static_cast<uint32>(1));
	CHECK_EQ(header.nPayloadLength, static_cast<uint32>(0));
}

TEST_CASE("Protocol parser preserves release live-wire search packet golden vectors")
{
	static const ReleaseSearchPacketGoldenVector vectors[] = {
		{"linux", 10u, 9u, 0x3E754120FCC3EB84ull},
		{"ubuntu", 11u, 10u, 0xCE7D5C38D51E41FDull},
		{"fedora", 11u, 10u, 0xD13803A7A5A9EF97ull},
		{"freebsd", 12u, 11u, 0x9AF6C316F24A8DD1ull},
		{"debian", 11u, 10u, 0x17F39CB63770AA53ull},
		{"emule", 10u, 9u, 0x27C377811D510298ull},
	};

	for (const ReleaseSearchPacketGoldenVector &rVector : vectors) {
		CAPTURE(rVector.pszTerm);
		const std::vector<BYTE> packet = BuildReleaseSearchPacketFixture(rVector.pszTerm);
		const ProtocolPacketHeader header = ParsePacketHeaderFixture(packet.data(), packet.size());
		const ProtocolTagSpan tag = ParseTagFixture(packet.data() + PROTOCOL_PACKET_HEADER_SIZE, packet.size() - PROTOCOL_PACKET_HEADER_SIZE);
		const size_t nTermLength = std::strlen(rVector.pszTerm);

		CHECK_EQ(ComputeFnv1a64(packet), rVector.nFnv1a64);
		CHECK_EQ(header.nProtocol, static_cast<uint8>(OP_EDONKEYPROT));
		CHECK_EQ(header.nOpcode, static_cast<uint8>(OP_SEARCHREQUEST));
		CHECK_EQ(header.nPacketLength, rVector.nPacketLength);
		CHECK_EQ(header.nPayloadLength, static_cast<uint32>(rVector.nTagTotalSize));
		CHECK_EQ(tag.Header.nType, static_cast<uint8>(TAGTYPE_STRING));
		CHECK(tag.Header.bUsesNameId);
		CHECK_EQ(tag.Header.nNameId, static_cast<uint8>(CT_NAME));
		CHECK_EQ(tag.nValueSize, static_cast<size_t>(2u + nTermLength));
		CHECK_EQ(tag.nTotalSize, rVector.nTagTotalSize);
	}
}

TEST_CASE("Protocol parser reads little-endian packet primitives without sign extension")
{
	const BYTE byWord[] = { 0x34, 0x12 };
	const BYTE byDword[] = { 0x78, 0x56, 0x34, 0x12 };

	CHECK_EQ(ReadLittleEndianUInt16(byWord), static_cast<uint16>(0x1234u));
	CHECK_EQ(ReadLittleEndianUInt32(byDword), static_cast<uint32>(0x12345678u));
}

TEST_CASE("Protocol parser decodes a named-by-id uint32 tag from serialized bytes")
{
	const BYTE fixture[] = {
		static_cast<BYTE>(TAGTYPE_UINT32 | 0x80),
		CT_VERSION,
		0x34, 0x12, 0x00, 0x00
	};

	const ProtocolTagSpan span = ParseTagFixture(fixture, sizeof(fixture));
	CHECK_EQ(span.Header.nType, static_cast<uint8>(TAGTYPE_UINT32));
	CHECK(span.Header.bUsesNameId);
	CHECK_EQ(span.Header.nNameId, static_cast<uint8>(CT_VERSION));
	CHECK_EQ(span.Header.nHeaderSize, static_cast<size_t>(2));
	CHECK_EQ(span.nValueSize, static_cast<size_t>(4));
	CHECK_EQ(span.nTotalSize, sizeof(fixture));
}

TEST_CASE("Protocol parser decodes an explicit-name string tag whose payload exactly fits the serialized bytes")
{
	const BYTE fixture[] = {
		TAGTYPE_STRING,
		0x03, 0x00,
		'e', 'd', '2',
		0x04, 0x00,
		'l', 'i', 'n', 'k'
	};

	const ProtocolTagSpan span = ParseTagFixture(fixture, sizeof(fixture));
	CHECK_EQ(span.Header.nType, static_cast<uint8>(TAGTYPE_STRING));
	CHECK_FALSE(span.Header.bUsesNameId);
	CHECK_EQ(span.Header.nNameLength, static_cast<uint16>(3));
	CHECK_EQ(span.Header.nHeaderSize, static_cast<size_t>(2 + 3 + 1));
	CHECK_EQ(span.nValueSize, static_cast<size_t>(2 + 4));
	CHECK_EQ(span.nTotalSize, sizeof(fixture));
}

TEST_CASE("Protocol parser decodes the legacy explicit-name-id header form")
{
	const BYTE fixture[] = {
		TAGTYPE_UINT16,
		0x01, 0x00,
		CT_PORT,
		0x39, 0x30
	};

	const ProtocolTagSpan span = ParseTagFixture(fixture, sizeof(fixture));
	CHECK_EQ(span.Header.nType, static_cast<uint8>(TAGTYPE_UINT16));
	CHECK(span.Header.bUsesNameId);
	CHECK_EQ(span.Header.nNameId, static_cast<uint8>(CT_PORT));
	CHECK_EQ(span.Header.nHeaderSize, static_cast<size_t>(4));
	CHECK_EQ(span.nValueSize, static_cast<size_t>(2));
}

TEST_CASE("Protocol parser decodes fixed-size integer, hash, and compact string tags")
{
	const BYTE uint64Fixture[] = {
		static_cast<BYTE>(TAGTYPE_UINT64 | 0x80),
		CT_EMULE_UDPPORTS,
		1, 2, 3, 4, 5, 6, 7, 8
	};
	const BYTE hashFixture[] = {
		static_cast<BYTE>(TAGTYPE_HASH | 0x80),
		FT_FILEHASH,
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15
	};
	const BYTE compactFixture[] = {
		TAGTYPE_STR1 + 2,
		0x02, 0x00,
		'i', 'd',
		'a', 'b', 'c'
	};

	const ProtocolTagSpan uint64Span = ParseTagFixture(uint64Fixture, sizeof(uint64Fixture));
	const ProtocolTagSpan hashSpan = ParseTagFixture(hashFixture, sizeof(hashFixture));
	const ProtocolTagSpan compactSpan = ParseTagFixture(compactFixture, sizeof(compactFixture));

	CHECK_EQ(uint64Span.nValueSize, static_cast<size_t>(8));
	CHECK_EQ(hashSpan.nValueSize, static_cast<size_t>(16));
	CHECK_EQ(compactSpan.Header.nType, static_cast<uint8>(TAGTYPE_STR1 + 2));
	CHECK_EQ(compactSpan.nValueSize, static_cast<size_t>(3));
	CHECK_EQ(compactSpan.nTotalSize, sizeof(compactFixture));
}

TEST_CASE("Protocol parser decodes bool-array tags with exact-fit payloads")
{
	const BYTE fixture[] = {
		static_cast<BYTE>(TAGTYPE_BOOLARRAY | 0x80),
		FT_CORRUPTEDPARTS,
		0x09, 0x00,
		0xA5, 0x01
	};

	const ProtocolTagSpan span = ParseTagFixture(fixture, sizeof(fixture));
	CHECK_EQ(span.Header.nType, static_cast<uint8>(TAGTYPE_BOOLARRAY));
	CHECK_EQ(span.nValueSize, static_cast<size_t>(4));
	CHECK_EQ(span.nTotalSize, sizeof(fixture));
}

TEST_CASE("Protocol parser decodes float, bool, and unknown custom tag headers without overrunning")
{
	const BYTE floatFixture[] = {
		static_cast<BYTE>(TAGTYPE_FLOAT32 | 0x80),
		FT_FILERATING,
		0x00, 0x00, 0x20, 0x41
	};
	const BYTE boolFixture[] = {
		static_cast<BYTE>(TAGTYPE_BOOL | 0x80),
		FT_DL_PREVIEW,
		0x01
	};
	const BYTE unknownFixture[] = {
		0x7Fu,
		0x02, 0x00,
		'x', 'y'
	};

	const ProtocolTagSpan floatSpan = ParseTagFixture(floatFixture, sizeof(floatFixture));
	const ProtocolTagSpan boolSpan = ParseTagFixture(boolFixture, sizeof(boolFixture));
	const ProtocolTagSpan unknownSpan = ParseTagFixture(unknownFixture, sizeof(unknownFixture));

	CHECK_EQ(floatSpan.nValueSize, static_cast<size_t>(4));
	CHECK_EQ(boolSpan.nValueSize, static_cast<size_t>(1));
	CHECK_EQ(unknownSpan.nValueSize, static_cast<size_t>(0));
	CHECK_EQ(unknownSpan.nTotalSize, unknownSpan.Header.nHeaderSize);
}

TEST_CASE("Protocol parser accepts a blob tag whose payload exactly fits the serialized bytes")
{
	const BYTE fixture[] = {
		static_cast<BYTE>(TAGTYPE_BLOB | 0x80),
		FT_MEDIA_ARTIST,
		0x03, 0x00, 0x00, 0x00,
		0xAA, 0xBB, 0xCC
	};

	const ProtocolTagSpan span = ParseTagFixture(fixture, sizeof(fixture));
	CHECK_EQ(span.Header.nType, static_cast<uint8>(TAGTYPE_BLOB));
	CHECK_EQ(span.nBlobSize, static_cast<uint32>(3));
	CHECK_EQ(span.nTotalSize, sizeof(fixture));
}

TEST_CASE("Protocol guard bounds zero-length packet payloads instead of underflowing")
{
	CHECK_EQ(GetPacketPayloadSize(0), static_cast<uint32>(0));
}

TEST_CASE("Protocol guard rejects hostile hello tag counts before tag parsing starts")
{
	CHECK_FALSE(HasSaneTagCount(8, 16, MAX_PROTOCOL_TAGS + 1, MAX_PROTOCOL_TAGS));
}

TEST_CASE("Protocol guard validates serialized byte windows and bool-array payload lengths")
{
	CHECK(CanReadSerializedBytes(8, 16, 8));
	CHECK(CanReadBoolArrayPayload(8, 12, 8));
	CHECK_FALSE(CanReadSerializedBytes(17, 16, 0));
	CHECK_FALSE(CanReadSerializedBytes(8, 16, 9));
	CHECK_FALSE(CanReadBoolArrayPayload(11, 12, 16));
}

TEST_CASE("Protocol guard rejects short server UDP payloads before reading the header bytes")
{
	CHECK_FALSE(HasUdpPayloadHeader(1));
}

TEST_CASE("Protocol guard rejects compressed UDP payloads that have no compressed body bytes")
{
	CHECK_FALSE(HasCompressedUdpPayload(2));
}

TEST_CASE("Protocol guard rejects truncated packet spans and impossible TCP partial-header states")
{
#if defined(EMULE_HAS_EXTENDED_PROTOCOL_GUARDS)
	CHECK_FALSE(CanReadPacketSpan(23, 16, 8));
	CHECK_FALSE(CanRestoreTcpPendingHeader(PROTOCOL_PACKET_HEADER_SIZE + 1, PROTOCOL_PACKET_HEADER_SIZE, TCP_READ_BUFFER_SIZE));
	CHECK_FALSE(CanStoreTcpPendingHeader(PROTOCOL_PACKET_HEADER_SIZE, PROTOCOL_PACKET_HEADER_SIZE));
	CHECK_FALSE(CanContinuePacketAssembly(100, 101));
#else
	MESSAGE("Extended protocol guard helpers are not available in this workspace.");
#endif
}

TEST_CASE("Protocol guard rejects overflowed size arithmetic and truncated callback or block packet headers")
{
#if defined(EMULE_HAS_EXTENDED_PROTOCOL_GUARDS)
	size_t nIgnoredSize = 0;
	CHECK_FALSE(TryAddSize(std::numeric_limits<size_t>::max(), 1, &nIgnoredSize));
	CHECK_FALSE(TryMultiplyAddSize(std::numeric_limits<size_t>::max(), 2, 1, &nIgnoredSize));
	CHECK_FALSE(HasUdpCallbackPayload(16));
	CHECK_FALSE(HasDownloadBlockPacketHeader(23, false, false));
#else
	MESSAGE("Extended protocol guard helpers are not available in this workspace.");
#endif
}

TEST_CASE("Protocol guard rejects blob reads once the parser position has moved past the packet length")
{
	CHECK_FALSE(CanReadBlobPayload(17, 16, 1));
}

TEST_CASE("Protocol guard treats zero-denominator integer progress as 0 instead of an ASSERT-only contract")
{
	CHECK_EQ(CalculateProgressPercent(5, 0), static_cast<uint32>(0));
}

TEST_CASE("Protocol guard treats zero-denominator floating-point progress as empty progress")
{
	CHECK_EQ(CalculateProgressRatio(5.0f, 0.0f), doctest::Approx(0.0f));
}

TEST_CASE("Protocol guard accepts the dotted broadcast IPv4 literal as a valid parse")
{
	uint32 nAddress = 0;
	CHECK(TryParseDottedIPv4Literal("255.255.255.255", &nAddress));
	CHECK_EQ(nAddress, IPV4_BROADCAST);
}

TEST_CASE("Protocol guard rejects invalid IPv4 parser inputs and clamps bounded progress")
{
	size_t nExpandedSize = 0;
	uint32 nAddress = 0;

	CHECK_FALSE(TryMultiplyAddSize(4u, 2u, 3u, NULL));
	CHECK_EQ(CalculateProgressPercent(150u, 100u), static_cast<uint32>(100));
	CHECK_EQ(CalculateProgressRatio(-5.0f, 10.0f), doctest::Approx(0.0f));
	CHECK_EQ(CalculateProgressRatio(15.0f, 10.0f), doctest::Approx(1.0f));
	REQUIRE(TryMultiplyAddSize(4u, 0u, 7u, &nExpandedSize));
	CHECK_EQ(nExpandedSize, static_cast<size_t>(7));
	CHECK_FALSE(TryParseDottedIPv4Literal(NULL, &nAddress));
	CHECK_FALSE(TryParseDottedIPv4Literal("1.2.3.4", NULL));
	CHECK_FALSE(TryParseDottedIPv4Literal("a.2.3.4", &nAddress));
	CHECK_FALSE(TryParseDottedIPv4Literal("256.2.3.4", &nAddress));
	CHECK_FALSE(TryParseDottedIPv4Literal("1-2.3.4", &nAddress));
	CHECK_FALSE(TryParseDottedIPv4Literal("1.2.3.4x", &nAddress));
}

TEST_CASE("Protocol guard accepts boundary UDP and block packet shapes")
{
	CHECK(HasUdpPayloadHeader(2));
	CHECK_EQ(GetDownloadBlockPacketHeaderSize(true, true), static_cast<uint32>(28));
	CHECK(HasDownloadBlockPacketHeader(28, true, true));
	CHECK_FALSE(HasDownloadBlockPacketHeader(27, true, true));
}

TEST_CASE("Connected-server seam accepts a cached current-server snapshot when connected")
{
	const void *pCurrentServer = reinterpret_cast<const void*>(1);
	CHECK(HasConnectedServerSnapshot(true, pCurrentServer));
	CHECK(HasConnectedServerCapability(true, pCurrentServer, true));
	CHECK(MatchesConnectedServerEndpoint(true, pCurrentServer, 0x01020304u, 4661, 0x01020304u, 4661));
}

TEST_CASE("Connected-server seam rejects missing capability bits and mismatched endpoints even with a snapshot")
{
	const void *pCurrentServer = reinterpret_cast<const void*>(1);
	CHECK_FALSE(HasConnectedServerCapability(true, pCurrentServer, false));
	CHECK_FALSE(MatchesConnectedServerEndpoint(true, pCurrentServer, 0x01020304u, 4661, 0x05060708u, 4661));
	CHECK_FALSE(MatchesConnectedServerEndpoint(true, pCurrentServer, 0x01020304u, 4661, 0x01020304u, 4662));
}

TEST_SUITE_END;

TEST_SUITE_BEGIN("parity");

TEST_CASE("Protocol parser rejects zero-length packet headers before payload math underflows")
{
	const BYTE fixture[] = {
		OP_EDONKEYPROT,
		0x00, 0x00, 0x00, 0x00,
		OP_HELLO
	};

	ProtocolPacketHeader header = {};
	CHECK_FALSE(TryParsePacketHeader(fixture, sizeof(fixture), &header));
}

TEST_CASE("Protocol parser rejects truncated serialized packet headers before the opcode read")
{
	const BYTE fixture[] = {
		OP_EDONKEYPROT,
		0x01, 0x00, 0x00, 0x00
	};

	ProtocolPacketHeader header = {};
	CHECK_FALSE(TryParsePacketHeader(fixture, sizeof(fixture), &header));
}

TEST_CASE("Protocol parser rejects explicit-name tags whose serialized name bytes are truncated")
{
	const BYTE fixture[] = {
		TAGTYPE_UINT8,
		0x03, 0x00,
		'A', 'B'
	};

	ProtocolTagHeader header = {};
	CHECK_FALSE(TryParseTagHeader(fixture, sizeof(fixture), &header));
}

TEST_CASE("Protocol parser rejects null decode targets and short name-id headers")
{
	const BYTE validPacket[] = {
		OP_EDONKEYPROT,
		0x01, 0x00, 0x00, 0x00,
		OP_HELLO
	};
	const BYTE shortNameIdFixture[] = {
		static_cast<BYTE>(TAGTYPE_UINT16 | 0x80)
	};
	ProtocolPacketHeader header = {};
	ProtocolTagHeader tagHeader = {};
	ProtocolTagSpan span = {};

	CHECK_FALSE(TryParsePacketHeader(nullptr, sizeof(validPacket), &header));
	CHECK_FALSE(TryParsePacketHeader(validPacket, sizeof(validPacket), nullptr));
	CHECK_FALSE(TryParseTagHeader(nullptr, 1, &tagHeader));
	CHECK_FALSE(TryParseTagHeader(shortNameIdFixture, sizeof(shortNameIdFixture), &tagHeader));
	CHECK_FALSE(TryParseTagSpan(nullptr, 0, &span));
}

TEST_CASE("Protocol parser rejects headers that end before the explicit-name-id byte can be read")
{
	const BYTE fixture[] = {
		TAGTYPE_UINT16,
		0x01, 0x00
	};

	ProtocolTagHeader header = {};
	CHECK_FALSE(TryParseTagHeader(fixture, sizeof(fixture), &header));
}

TEST_CASE("Protocol parser rejects named-by-id uint32 tags whose serialized value bytes are truncated")
{
	const BYTE fixture[] = {
		static_cast<BYTE>(TAGTYPE_UINT32 | 0x80),
		CT_VERSION,
		0x34, 0x12, 0x00
	};

	ProtocolTagSpan span = {};
	CHECK_FALSE(TryParseTagSpan(fixture, sizeof(fixture), &span));
}

TEST_CASE("Protocol parser rejects string tags whose serialized payload is truncated")
{
	const BYTE fixture[] = {
		static_cast<BYTE>(TAGTYPE_STRING | 0x80),
		CT_NAME,
		0x03, 0x00,
		'A', 'B'
	};

	ProtocolTagSpan span = {};
	CHECK_FALSE(TryParseTagSpan(fixture, sizeof(fixture), &span));
}

TEST_CASE("Protocol parser rejects blob tags whose serialized payload exceeds the remaining bytes")
{
	const BYTE fixture[] = {
		static_cast<BYTE>(TAGTYPE_BLOB | 0x80),
		FT_MEDIA_ARTIST,
		0x04, 0x00, 0x00, 0x00,
		0xAA, 0xBB, 0xCC
	};

	ProtocolTagSpan span = {};
	CHECK_FALSE(TryParseTagSpan(fixture, sizeof(fixture), &span));
}

TEST_CASE("Protocol parser rejects truncated bool-array and fixed-width payloads")
{
	const BYTE boolArrayFixture[] = {
		static_cast<BYTE>(TAGTYPE_BOOLARRAY | 0x80),
		FT_CORRUPTEDPARTS,
		0x09, 0x00,
		0xA5
	};
	const BYTE hashFixture[] = {
		static_cast<BYTE>(TAGTYPE_HASH | 0x80),
		FT_FILEHASH,
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14
	};

	ProtocolTagSpan span = {};
	CHECK_FALSE(TryParseTagSpan(boolArrayFixture, sizeof(boolArrayFixture), &span));
	CHECK_FALSE(TryParseTagSpan(hashFixture, sizeof(hashFixture), &span));
}

TEST_CASE("Protocol parser rejects truncated float and compact-string payloads")
{
	const BYTE floatFixture[] = {
		static_cast<BYTE>(TAGTYPE_FLOAT32 | 0x80),
		FT_FILERATING,
		0x00, 0x00, 0x20
	};
	const BYTE compactFixture[] = {
		TAGTYPE_STR1 + 1,
		0x02, 0x00,
		'i', 'd',
		'a'
	};

	ProtocolTagSpan span = {};
	CHECK_FALSE(TryParseTagSpan(floatFixture, sizeof(floatFixture), &span));
	CHECK_FALSE(TryParseTagSpan(compactFixture, sizeof(compactFixture), &span));
}

TEST_CASE("Connected-server seam rejects a connected session that lost its current-server snapshot")
{
	CHECK_FALSE(HasConnectedServerSnapshot(true, NULL));
}

TEST_CASE("Connected-server seam rejects capability checks once the current-server snapshot is missing")
{
	CHECK_FALSE(HasConnectedServerCapability(true, NULL, true));
}

TEST_CASE("Connected-server seam rejects endpoint matches once the current-server snapshot is missing")
{
	CHECK_FALSE(MatchesConnectedServerEndpoint(true, NULL, 0x01020304u, 4661, 0x01020304u, 4661));
}

TEST_CASE("Connected-server seam rejects every helper while disconnected")
{
	const void *pCurrentServer = reinterpret_cast<const void*>(1);
	CHECK_FALSE(HasConnectedServerSnapshot(false, pCurrentServer));
	CHECK_FALSE(HasConnectedServerCapability(false, pCurrentServer, true));
	CHECK_FALSE(MatchesConnectedServerEndpoint(false, pCurrentServer, 0x01020304u, 4661, 0x01020304u, 4661));
}

TEST_SUITE_END;
