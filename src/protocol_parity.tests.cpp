#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include <cstring>
#include <vector>

#include "BaseClientFriendBuddySeams.h"
#include "DownloadQueueHostnameResolverSeams.h"
#include "EncryptedDatagramFramingSeams.h"
#include "ProtocolParsers.h"
#include "ServerSocketSeams.h"
#include "kademlia/kademlia/Defines.h"
#include "opcodes.h"

namespace
{
	const unsigned long long FNV1A64_OFFSET = 14695981039346656037ull;
	const unsigned long long FNV1A64_PRIME = 1099511628211ull;

	struct SearchPacketVector
	{
		const char *pszTerm;
		uint32 uPacketLength;
		unsigned long long uDigest;
	};

	/**
	 * Computes a stable digest for serialized wire fixtures.
	 */
	unsigned long long ComputeFnv1a64(const std::vector<BYTE> &rBytes)
	{
		unsigned long long uHash = FNV1A64_OFFSET;
		for (BYTE byValue : rBytes) {
			uHash ^= static_cast<unsigned long long>(byValue);
			uHash *= FNV1A64_PRIME;
		}
		return uHash;
	}

	/**
	 * Builds the compact eD2K search request shape used by the community client.
	 */
	std::vector<BYTE> BuildEd2kSearchPacket(const char *pszTerm)
	{
		const size_t uTermLength = std::strlen(pszTerm);
		REQUIRE(uTermLength <= 0xFFFFu);
		const uint32 uPacketLength = static_cast<uint32>(1u + 2u + 2u + uTermLength);
		std::vector<BYTE> bytes;
		bytes.reserve(static_cast<size_t>(PROTOCOL_PACKET_HEADER_SIZE) + uPacketLength - 1u);
		bytes.push_back(static_cast<BYTE>(OP_EDONKEYPROT));
		bytes.push_back(static_cast<BYTE>(uPacketLength & 0xFFu));
		bytes.push_back(static_cast<BYTE>((uPacketLength >> 8) & 0xFFu));
		bytes.push_back(static_cast<BYTE>((uPacketLength >> 16) & 0xFFu));
		bytes.push_back(static_cast<BYTE>((uPacketLength >> 24) & 0xFFu));
		bytes.push_back(static_cast<BYTE>(OP_SEARCHREQUEST));
		bytes.push_back(static_cast<BYTE>(TAGTYPE_STRING | 0x80u));
		bytes.push_back(static_cast<BYTE>(CT_NAME));
		bytes.push_back(static_cast<BYTE>(uTermLength & 0xFFu));
		bytes.push_back(static_cast<BYTE>((uTermLength >> 8) & 0xFFu));
		for (size_t i = 0; i < uTermLength; ++i)
			bytes.push_back(static_cast<BYTE>(pszTerm[i]));
		return bytes;
	}
}

TEST_SUITE_BEGIN("protocol-parity");

TEST_CASE("eD2K packet parser preserves community search request wire vectors")
{
	static const SearchPacketVector vectors[] = {
		{"linux", 10u, 0x3E754120FCC3EB84ull},
		{"ubuntu", 11u, 0xCE7D5C38D51E41FDull},
		{"fedora", 11u, 0xD13803A7A5A9EF97ull},
		{"freebsd", 12u, 0x9AF6C316F24A8DD1ull},
		{"debian", 11u, 0x17F39CB63770AA53ull},
		{"emule", 10u, 0x27C377811D510298ull},
	};

	for (const SearchPacketVector &rVector : vectors) {
		CAPTURE(rVector.pszTerm);
		const std::vector<BYTE> packet = BuildEd2kSearchPacket(rVector.pszTerm);
		ProtocolPacketHeader header = {};
		ProtocolTagSpan tag = {};

		REQUIRE(TryParsePacketHeader(packet.data(), packet.size(), &header));
		REQUIRE(TryParseTagSpan(packet.data() + PROTOCOL_PACKET_HEADER_SIZE, packet.size() - PROTOCOL_PACKET_HEADER_SIZE, &tag));

		CHECK_EQ(ComputeFnv1a64(packet), rVector.uDigest);
		CHECK_EQ(header.nProtocol, static_cast<uint8>(OP_EDONKEYPROT));
		CHECK_EQ(header.nOpcode, static_cast<uint8>(OP_SEARCHREQUEST));
		CHECK_EQ(header.nPacketLength, rVector.uPacketLength);
		CHECK_EQ(header.nPayloadLength, rVector.uPacketLength - 1u);
		CHECK_EQ(tag.Header.nType, static_cast<uint8>(TAGTYPE_STRING));
		CHECK(tag.Header.bUsesNameId);
		CHECK_EQ(tag.Header.nNameId, static_cast<uint8>(CT_NAME));
		CHECK_EQ(tag.nTotalSize, static_cast<size_t>(4u + std::strlen(rVector.pszTerm)));
	}
}

TEST_CASE("eD2K tag parser keeps compact and explicit tag encodings bounded")
{
	const BYTE compactString[] = {
		TAGTYPE_STR1 + 2,
		0x02, 0x00,
		'i', 'd',
		'a', 'b', 'c'
	};
	const BYTE explicitPort[] = {
		TAGTYPE_UINT16,
		0x01, 0x00,
		CT_PORT,
		0x36, 0x12
	};
	const BYTE blob[] = {
		static_cast<BYTE>(TAGTYPE_BLOB | 0x80),
		FT_MEDIA_ARTIST,
		0x03, 0x00, 0x00, 0x00,
		0xAA, 0xBB, 0xCC
	};

	ProtocolTagSpan span = {};
	REQUIRE(TryParseTagSpan(compactString, sizeof compactString, &span));
	CHECK_EQ(span.Header.nType, static_cast<uint8>(TAGTYPE_STR1 + 2));
	CHECK_EQ(span.nValueSize, static_cast<size_t>(3));
	CHECK_EQ(span.nTotalSize, sizeof compactString);

	REQUIRE(TryParseTagSpan(explicitPort, sizeof explicitPort, &span));
	CHECK(span.Header.bUsesNameId);
	CHECK_EQ(span.Header.nNameId, static_cast<uint8>(CT_PORT));
	CHECK_EQ(span.nValueSize, static_cast<size_t>(2));

	REQUIRE(TryParseTagSpan(blob, sizeof blob, &span));
	CHECK_EQ(span.Header.nType, static_cast<uint8>(TAGTYPE_BLOB));
	CHECK_EQ(span.nBlobSize, static_cast<uint32>(3));
	CHECK_EQ(span.nTotalSize, sizeof blob);
}

TEST_CASE("Kad and eD2K UDP obfuscation markers stay classified by community framing")
{
	const EncryptedDatagramFrameSnapshot plain = InspectEncryptedDatagramFrame(OP_EMULEPROT, 32u, false);
	const EncryptedDatagramFrameSnapshot ed2k = InspectEncryptedDatagramFrame(0x05u, 8u, false);
	const EncryptedDatagramFrameSnapshot kadNodeId = InspectEncryptedDatagramFrame(0x10u, 16u, false);
	const EncryptedDatagramFrameSnapshot kadReceiverKey = InspectEncryptedDatagramFrame(0x12u, 16u, false);

	CHECK(plain.eMarkerKind == EEncryptedDatagramMarkerKind::PlainProtocol);
	CHECK_FALSE(plain.bRequiresVerifyKeys);
	CHECK(ed2k.eMarkerKind == EEncryptedDatagramMarkerKind::Ed2kCandidate);
	CHECK_EQ(ed2k.nExpectedOverhead, 8u);
	CHECK(kadNodeId.eMarkerKind == EEncryptedDatagramMarkerKind::KadNodeIdCandidate);
	CHECK(kadNodeId.bRequiresVerifyKeys);
	CHECK(kadReceiverKey.eMarkerKind == EEncryptedDatagramMarkerKind::KadReceiverKeyCandidate);
	CHECK(kadReceiverKey.bRequiresVerifyKeys);
}

TEST_CASE("Server packet failures keep search and source responses recoverable")
{
	CHECK(ServerSocketSeams::GetProcessPacketFailureAction(ServerSocketSeams::kServerOpcodeSearchResult) == ServerSocketSeams::EServerPacketFailureAction::KeepConnection);
	CHECK(ServerSocketSeams::GetProcessPacketFailureAction(ServerSocketSeams::kServerOpcodeFoundSources) == ServerSocketSeams::EServerPacketFailureAction::KeepConnection);
	CHECK(ServerSocketSeams::GetProcessPacketFailureAction(ServerSocketSeams::kServerOpcodeReject) == ServerSocketSeams::EServerPacketFailureAction::Disconnect);
	CHECK(ServerSocketSeams::ShouldConsumePackedPacketUnpackFailure());
}

TEST_CASE("Source exchange decisions keep buddy, packed source, and URL source order stable")
{
	std::vector<int> trace;
	const BuddyHelloSnapshot buddySnapshot = BuildBuddyHelloSnapshot(true, true, 0x0A0B0C0Du, 4662u);
	if (buddySnapshot.bShouldAdvertise)
		trace.push_back(1);
	if (GetDownloadHostnameResolveDispatch(true, true, true, false) == EDownloadHostnameResolveDispatch::AddPackedSource)
		trace.push_back(2);
	if (ShouldSearchReplacementFriend({true, true, false, false, false}))
		trace.push_back(3);
	if (GetDownloadHostnameResolveDispatch(true, true, true, true) == EDownloadHostnameResolveDispatch::AddUrlSource)
		trace.push_back(4);

	CHECK(trace == std::vector<int>{1, 2, 3, 4});
}

TEST_CASE("Kad search constants preserve community-compatible boundaries")
{
	CHECK_EQ(static_cast<unsigned>(K), 10u);
	CHECK_EQ(static_cast<unsigned>(KBASE), 4u);
	CHECK_EQ(static_cast<unsigned>(KK), 5u);
	CHECK_EQ(static_cast<unsigned>(ALPHA_QUERY), 3u);
	CHECK(SEARCHFILE_LIFETIME >= SEARCHNODECOMP_LIFETIME);
	CHECK(SEARCHFINDSOURCE_TOTAL >= SEARCHSTOREFILE_TOTAL);
}

TEST_CASE("Protocol parsers reject malformed Kad/eD2K-adjacent frames before payload reads")
{
	const BYTE zeroLengthPacket[] = {
		OP_EDONKEYPROT,
		0x00, 0x00, 0x00, 0x00,
		OP_HELLO
	};
	const BYTE truncatedString[] = {
		static_cast<BYTE>(TAGTYPE_STRING | 0x80),
		CT_NAME,
		0x03, 0x00,
		'A', 'B'
	};
	const BYTE truncatedHash[] = {
		static_cast<BYTE>(TAGTYPE_HASH | 0x80),
		FT_FILEHASH,
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14
	};

	ProtocolPacketHeader header = {};
	ProtocolTagSpan span = {};
	CHECK_FALSE(TryParsePacketHeader(zeroLengthPacket, sizeof zeroLengthPacket, &header));
	CHECK_FALSE(TryParseTagSpan(truncatedString, sizeof truncatedString, &span));
	CHECK_FALSE(TryParseTagSpan(truncatedHash, sizeof truncatedHash, &span));
}

TEST_SUITE_END;
