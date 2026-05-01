#include "doctest.h"

#include <cstdint>

#include "ServerSocketSeams.h"

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
