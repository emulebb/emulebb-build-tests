#include "doctest.h"

#include <cstdint>

#include "ServerSocketSeams.h"

TEST_SUITE_BEGIN("parity");

namespace
{
struct TestServerPacket
{
	std::uint8_t prot;
	std::uint8_t opcode;
	std::uint32_t size;
};
}

TEST_CASE("ServerSocket seam keeps search and source packet failures recoverable")
{
	CHECK(ServerSocketSeams::GetProcessPacketFailureAction(ServerSocketSeams::kServerOpcodeSearchResult) == ServerSocketSeams::EServerPacketFailureAction::KeepConnection);
	CHECK(ServerSocketSeams::GetProcessPacketFailureAction(ServerSocketSeams::kServerOpcodeFoundSources) == ServerSocketSeams::EServerPacketFailureAction::KeepConnection);
}

TEST_CASE("ServerSocket seam disconnects after non-recoverable packet failures")
{
	CHECK(ServerSocketSeams::GetProcessPacketFailureAction(ServerSocketSeams::kServerOpcodeReject) == ServerSocketSeams::EServerPacketFailureAction::Disconnect);
	CHECK(ServerSocketSeams::GetProcessPacketFailureAction(static_cast<std::uint8_t>(0xffu)) == ServerSocketSeams::EServerPacketFailureAction::Disconnect);
}

TEST_CASE("ServerSocket seam consumes failed packed-packet unpack attempts")
{
	CHECK(ServerSocketSeams::ShouldConsumePackedPacketUnpackFailure());
}

TEST_CASE("ServerSocket seam supplies safe packet log defaults")
{
	const TestServerPacket packet = { ServerSocketSeams::kServerProtocolEdonkey, ServerSocketSeams::kServerOpcodeSearchResult, 1234u };

	CHECK(ServerSocketSeams::GetPacketFieldOrDefault(&packet, &TestServerPacket::prot, static_cast<std::uint8_t>(0)) == ServerSocketSeams::kServerProtocolEdonkey);
	CHECK(ServerSocketSeams::GetPacketFieldOrDefault(&packet, &TestServerPacket::opcode, static_cast<std::uint8_t>(0)) == ServerSocketSeams::kServerOpcodeSearchResult);
	CHECK(ServerSocketSeams::GetPacketFieldOrDefault(&packet, &TestServerPacket::size, static_cast<std::uint32_t>(0)) == 1234u);
	CHECK(ServerSocketSeams::GetPacketFieldOrDefault(static_cast<const TestServerPacket *>(NULL), &TestServerPacket::prot, static_cast<std::uint8_t>(0)) == 0u);
	CHECK(ServerSocketSeams::GetPacketFieldOrDefault(static_cast<const TestServerPacket *>(NULL), &TestServerPacket::opcode, static_cast<std::uint8_t>(0)) == 0u);
	CHECK(ServerSocketSeams::GetPacketFieldOrDefault(static_cast<const TestServerPacket *>(NULL), &TestServerPacket::size, static_cast<std::uint32_t>(0)) == 0u);
}

TEST_CASE("ServerSocket seam decodes concatenated outbound TCP frames")
{
	const std::uint8_t buffer[] = {
		0xE3u, 0x03u, 0x00u, 0x00u, 0x00u, 0x23u, 0xAAu, 0xBBu,
		0xD4u, 0x02u, 0x00u, 0x00u, 0x00u, 0x15u, 0xCCu,
	};

	CHECK(ServerSocketSeams::IsCompleteEmbeddedTcpFrameBuffer(buffer, sizeof buffer));

	size_t offset = 0;
	ServerSocketSeams::ServerPacketFrameView frame = {};
	REQUIRE(ServerSocketSeams::TryReadEmbeddedTcpFrame(buffer, sizeof buffer, &offset, &frame));
	CHECK(frame.protocol == ServerSocketSeams::kServerProtocolEdonkey);
	CHECK(frame.opcode == 0x23u);
	CHECK(frame.payloadSize == 2u);
	CHECK(frame.payload[0] == 0xAAu);
	CHECK(frame.payload[1] == 0xBBu);

	REQUIRE(ServerSocketSeams::TryReadEmbeddedTcpFrame(buffer, sizeof buffer, &offset, &frame));
	CHECK(frame.protocol == ServerSocketSeams::kServerProtocolPacked);
	CHECK(frame.opcode == 0x15u);
	CHECK(frame.payloadSize == 1u);
	CHECK(frame.payload[0] == 0xCCu);
	CHECK(offset == sizeof buffer);
}

TEST_CASE("ServerSocket seam rejects incomplete outbound TCP frame batches")
{
	const std::uint8_t truncated[] = { 0xE3u, 0x03u, 0x00u, 0x00u, 0x00u, 0x23u, 0xAAu };
	const std::uint8_t invalidMarker[] = { 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x23u };

	CHECK_FALSE(ServerSocketSeams::IsCompleteEmbeddedTcpFrameBuffer(truncated, sizeof truncated));
	CHECK_FALSE(ServerSocketSeams::IsCompleteEmbeddedTcpFrameBuffer(invalidMarker, sizeof invalidMarker));
	CHECK_FALSE(ServerSocketSeams::IsCompleteEmbeddedTcpFrameBuffer(NULL, 0));
}

TEST_SUITE_END();
