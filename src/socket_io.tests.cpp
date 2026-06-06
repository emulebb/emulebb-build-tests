#include "../third_party/doctest/doctest.h"

#include <cstdint>
#include <limits>

#include "SocketIoSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Socket IO seam accepts bounded receive results and rejects impossible byte counts")
{
	CHECK(HasValidSocketReceiveResult(0, 1024u));
	CHECK(HasValidSocketReceiveResult(512, 1024u));
	CHECK_FALSE(HasValidSocketReceiveResult(-1, 1024u));
	CHECK_FALSE(HasValidSocketReceiveResult(2048, 1024u));
}

TEST_CASE("Socket IO seam exposes broadband socket buffer targets")
{
	CHECK_EQ(kBroadbandUdpReceiveBufferBytes, static_cast<std::uint32_t>(1024u * 1024u));
	CHECK_EQ(kBroadbandTcpUploadSendBufferBytes, static_cast<std::uint32_t>(32u * 1024u * 1024u));
	CHECK_EQ(GetBroadbandTcpUploadSendBufferBytes(0u), static_cast<std::uint32_t>(1024u * 1024u));
	CHECK_EQ(GetBroadbandTcpUploadSendBufferBytes(6200u * 1024u / 8u), static_cast<std::uint32_t>(6200u * 1024u));
	CHECK_EQ(GetBroadbandTcpUploadSendBufferBytes(128u * 1024u * 1024u / 8u), kBroadbandTcpUploadSendBufferBytes);
}

TEST_CASE("Socket IO seam clamps receive-budget accounting without unsigned underflow")
{
	CHECK_EQ(ClampSocketReceiveBudget(4096u, 512), static_cast<std::uint32_t>(3584));
	CHECK_EQ(ClampSocketReceiveBudget(4096u, 4096), static_cast<std::uint32_t>(0));
	CHECK_EQ(ClampSocketReceiveBudget(4096u, 8192), static_cast<std::uint32_t>(0));
	CHECK_EQ(ClampSocketReceiveBudget(4096u, 0), static_cast<std::uint32_t>(4096));
}

TEST_CASE("Socket IO seam advances send progress only for positive in-range send results")
{
	std::uint32_t nNextSent = 0;

	CHECK(TryAccumulateSocketSendProgress(128u, 256u, 1024u, 128u, &nNextSent));
	CHECK_EQ(nNextSent, static_cast<std::uint32_t>(256));
	CHECK(TryAccumulateSocketSendProgress(0u, 128u, 128u, 128u, &nNextSent));
	CHECK_EQ(nNextSent, static_cast<std::uint32_t>(128));

	CHECK_FALSE(TryAccumulateSocketSendProgress(128u, 256u, 1024u, 0u, &nNextSent));
	CHECK_FALSE(TryAccumulateSocketSendProgress(128u, 256u, 1024u, 300u, &nNextSent));
	CHECK_FALSE(TryAccumulateSocketSendProgress(900u, 200u, 1024u, 150u, &nNextSent));
}

TEST_CASE("Socket IO seam rejects null or overflowed send-progress bookkeeping")
{
	std::uint32_t nNextSent = 0;

	CHECK_FALSE(TryAccumulateSocketSendProgress(0u, 64u, 128u, 32u, nullptr));
	CHECK_FALSE(TryAccumulateSocketSendProgress(0u, 0u, 128u, 32u, &nNextSent));
	CHECK_FALSE(TryAccumulateSocketSendProgress(129u, 16u, 128u, 1u, &nNextSent));
	CHECK_FALSE(TryAccumulateSocketSendProgress((std::numeric_limits<std::uint32_t>::max)(), 1u, (std::numeric_limits<std::uint32_t>::max)(), 1u, &nNextSent));
}

TEST_CASE("Socket IO seam rejects SOCKET_ERROR after unsigned promotion")
{
	std::uint32_t nNextSent = 0;
	const std::uint32_t nSocketError = static_cast<std::uint32_t>(-1);

	CHECK_FALSE(TryAccumulateSocketSendProgress(0u, 128u, 128u, nSocketError, &nNextSent));
}

TEST_SUITE_END;
