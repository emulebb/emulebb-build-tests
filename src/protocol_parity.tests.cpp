#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "BaseClientFriendBuddySeams.h"
#include "ClientUDPSocketSeams.h"
#include "DownloadQueueHostnameResolverSeams.h"
#include "EncryptedDatagramFramingSeams.h"
#include "ProtocolParsers.h"
#include "ProtocolReceiveFlowSeams.h"
#include "SearchParamsPolicy.h"
#include "ServerSocketSeams.h"
#include "SourceExchangeSeams.h"
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

	/**
	 * Replays a TCP packet stream through the receive-flow seam using caller-selected chunk sizes.
	 */
	std::vector<size_t> ReplayProtocolStream(const std::vector<BYTE> &rStream, const std::vector<size_t> &rChunkSizes, bool *pbRejected = nullptr)
	{
		std::vector<size_t> payloadLengths;
		std::vector<BYTE> pendingHeaderBytes;
		pendingHeaderBytes.reserve(PROTOCOL_PACKET_HEADER_SIZE);
		ProtocolReceiveFlowState state = CreateProtocolReceiveFlowState();

		size_t uStreamOffset = 0;
		for (size_t uChunkSize : rChunkSizes) {
			if (uStreamOffset >= rStream.size())
				break;

			size_t uChunkOffset = 0;
			const size_t uReadableChunkSize = (uStreamOffset + uChunkSize <= rStream.size()) ? uChunkSize : (rStream.size() - uStreamOffset);
			while (uChunkOffset < uReadableChunkSize) {
				bool bHeaderValid = false;
				size_t uPayloadLength = 0;
				if (!state.bHeaderDecoded) {
					const size_t uHeaderBytesNeeded = PROTOCOL_PACKET_HEADER_SIZE - state.nHeaderBytesBuffered;
					const size_t uProbeBytes = (uReadableChunkSize - uChunkOffset < uHeaderBytesNeeded)
						? (uReadableChunkSize - uChunkOffset)
						: uHeaderBytesNeeded;
					for (size_t i = 0; i < uProbeBytes; ++i)
						pendingHeaderBytes.push_back(rStream[uStreamOffset + uChunkOffset + i]);

					if (pendingHeaderBytes.size() == PROTOCOL_PACKET_HEADER_SIZE) {
						ProtocolPacketHeader header = {};
						bHeaderValid = TryParsePacketHeader(pendingHeaderBytes.data(), pendingHeaderBytes.size(), &header);
						if (bHeaderValid)
							uPayloadLength = header.nPayloadLength;
					}
				}

				const ProtocolReceiveFlowAction action = AdvanceProtocolReceiveFlow(state, uReadableChunkSize - uChunkOffset, bHeaderValid, uPayloadLength);
				uChunkOffset += action.nBytesConsumed;
				if (action.bShouldAttemptHeaderParse && !action.bShouldRejectPacket)
					pendingHeaderBytes.clear();
				if (action.bShouldRejectPacket) {
					if (pbRejected != nullptr)
						*pbRejected = true;
					return payloadLengths;
				}
				if (action.bShouldEmitPacket) {
					payloadLengths.push_back(state.nPayloadBytesExpected);
					ResetProtocolReceiveFlow(state);
					pendingHeaderBytes.clear();
				}
				if (action.nBytesConsumed == 0)
					break;
			}
			uStreamOffset += uReadableChunkSize;
		}

		if (pbRejected != nullptr)
			*pbRejected = state.bRejected;
		return payloadLengths;
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

TEST_CASE("Client UDP encryption gating preserves eD2K and Kad compatibility policy")
{
	CHECK(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, true, true, false, 0u));
	CHECK(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, true, true, false));

	CHECK(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, true, false, true, 0x12345678u));
	CHECK(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, true, false, true));

	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(false, true, true, false, 0u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(false, true, false, true, 0x12345678u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, false, true, false, 0u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldQueueOutgoingClientUdpEncryption(true, true, false, true, 0u));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, false, true, false));
	CHECK_FALSE(ClientUDPSocketSeams::ShouldApplyOutgoingClientUdpEncryptionOverhead(true, true, false, false));
}

TEST_CASE("Client UDP diagnostics read opcodes only from complete protocol markers")
{
	const unsigned char packet[] = {0xC5, 0x91};
	unsigned char opcode = 0xFF;

	CHECK_FALSE(ClientUDPSocketSeams::TryGetPacketOpcodeForLog(nullptr, 2, opcode));
	CHECK_EQ(opcode, static_cast<unsigned char>(0xFF));
	CHECK_FALSE(ClientUDPSocketSeams::TryGetPacketOpcodeForLog(packet, 1, opcode));
	CHECK_EQ(opcode, static_cast<unsigned char>(0xFF));
	CHECK(ClientUDPSocketSeams::TryGetPacketOpcodeForLog(packet, 2, opcode));
	CHECK_EQ(opcode, static_cast<unsigned char>(0x91));
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

TEST_CASE("Source exchange policy requires extended protocol peers and SX2 response shape")
{
	CHECK(SourceExchangeSeams::ShouldAllowSourceExchangeRequest(true, true));
	CHECK_FALSE(SourceExchangeSeams::ShouldAllowSourceExchangeRequest(true, false));
	CHECK_FALSE(SourceExchangeSeams::ShouldAllowSourceExchangeRequest(false, true));

	const SourceExchangeSeams::ResponsePlan plan = SourceExchangeSeams::ResolveSourceExchangeResponsePlan(true, 9);
	CHECK(plan.bShouldSend);
	CHECK_EQ(plan.byUsedVersion, static_cast<std::uint8_t>(SOURCEEXCHANGE2_VERSION));
	CHECK_EQ(plan.byAnswerOpcode, static_cast<std::uint8_t>(OP_ANSWERSOURCES2));
	CHECK_EQ(plan.nCountSeekOffset, static_cast<std::uint8_t>(17u));
	CHECK(SourceExchangeSeams::IsValidSourceExchange2Request(1));
	CHECK_FALSE(SourceExchangeSeams::IsValidSourceExchange2Request(0));
	CHECK_FALSE(SourceExchangeSeams::ResolveSourceExchangeResponsePlan(true, 0).bShouldSend);
}

TEST_CASE("Search method policy rejects unsupported persisted search types")
{
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(static_cast<std::uint8_t>(0)), static_cast<std::uint8_t>(0));
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(static_cast<std::uint8_t>(1)), SearchParamsPolicy::kDefaultSearchType);
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(static_cast<std::uint8_t>(2)), static_cast<std::uint8_t>(2));
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(static_cast<std::uint8_t>(3)), static_cast<std::uint8_t>(3));
	CHECK_EQ(SearchParamsPolicy::NormalizeStoredSearchType(static_cast<std::uint8_t>(4)), SearchParamsPolicy::kDefaultSearchType);
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

TEST_CASE("TCP protocol receive flow preserves fragmented eD2K packet boundaries")
{
	const std::vector<BYTE> stream = {
		OP_EDONKEYPROT, 0x04, 0x00, 0x00, 0x00, OP_HELLO, 0xAA, 0xBB, 0xCC,
		OP_EDONKEYPROT, 0x03, 0x00, 0x00, 0x00, OP_MESSAGE, 0xDD, 0xEE
	};

	const std::vector<size_t> payloadLengths = ReplayProtocolStream(stream, {2u, 4u, 3u, 2u, 6u});

	CHECK(payloadLengths == std::vector<size_t>{3u, 2u});
}

TEST_CASE("TCP protocol receive flow rejects malformed zero-length packet headers")
{
	const std::vector<BYTE> stream = {
		OP_EDONKEYPROT, 0x00, 0x00, 0x00, 0x00, OP_HELLO
	};

	bool bRejected = false;
	const std::vector<size_t> payloadLengths = ReplayProtocolStream(stream, {stream.size()}, &bRejected);

	CHECK(payloadLengths.empty());
	CHECK(bRejected);
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
