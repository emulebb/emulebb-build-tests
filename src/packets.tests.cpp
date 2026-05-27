#include "../third_party/doctest/doctest.h"

#include "PacketsSeams.h"

TEST_SUITE_BEGIN("packets");

TEST_CASE("Packet integer tag seam keeps ordinary values compact")
{
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(0u, false), TAGTYPE_UINT32);
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(UINT32_MAX, false), TAGTYPE_UINT32);
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(42u, true), TAGTYPE_UINT64);
}

TEST_CASE("Packet integer tag seam promotes values that cannot fit in uint32")
{
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(static_cast<uint64_t>(UINT32_MAX) + 1u, false), TAGTYPE_UINT64);
	CHECK_EQ(PacketsSeams::SelectIntegerTagType(UINT64_MAX, false), TAGTYPE_UINT64);
}

TEST_CASE("Packet allocation seam keeps legacy slack while rejecting wrapped sizes")
{
	size_t allocationSize = 0;

	CHECK(PacketsSeams::TryGetTcpPacketAllocationSize(42u, &allocationSize));
	CHECK_EQ(allocationSize, static_cast<size_t>(52u));

	CHECK_FALSE(PacketsSeams::TryGetTcpPacketAllocationSize(UINT32_MAX, &allocationSize));
	CHECK_FALSE(PacketsSeams::TryGetTcpPacketAllocationSize(UINT32_MAX, NULL));
}

TEST_CASE("Packet length seam rejects payloads that cannot include the opcode byte")
{
	uint32_t packetLength = 0;

	CHECK(PacketsSeams::TryGetTcpPacketLengthField(0u, &packetLength));
	CHECK_EQ(packetLength, static_cast<uint32_t>(1u));
	CHECK(PacketsSeams::TryGetTcpPacketLengthField(UINT32_MAX - 1u, &packetLength));
	CHECK_EQ(packetLength, UINT32_MAX);
	CHECK_FALSE(PacketsSeams::TryGetTcpPacketLengthField(UINT32_MAX, &packetLength));
}

TEST_CASE("Packet constructor span seam rejects values before narrowing")
{
	uint32_t payloadSize = 0;

	CHECK(PacketsSeams::TryGetTcpPacketPayloadSizeFromSpan(42u, &payloadSize));
	CHECK_EQ(payloadSize, static_cast<uint32_t>(42u));
	CHECK_FALSE(PacketsSeams::TryGetTcpPacketPayloadSizeFromSpan(UINT32_MAX, &payloadSize));
	CHECK_FALSE(PacketsSeams::TryGetTcpPacketPayloadSizeFromSpan(static_cast<uint64_t>(UINT32_MAX) + 1u, &payloadSize));
	CHECK_FALSE(PacketsSeams::TryGetTcpPacketPayloadSizeFromSpan(42u, NULL));
}

TEST_CASE("Packet payload addition seam preserves the 32-bit wire limit")
{
	uint32_t combinedSize = 0;

	CHECK(PacketsSeams::TryAddPacketPayloadSizes(10u, 20u, &combinedSize));
	CHECK_EQ(combinedSize, static_cast<uint32_t>(30u));
	CHECK_FALSE(PacketsSeams::TryAddPacketPayloadSizes(UINT32_MAX, 1u, &combinedSize));
	CHECK_FALSE(PacketsSeams::TryAddPacketPayloadSizes(0u, static_cast<size_t>(UINT32_MAX) + 1u, &combinedSize));
}

TEST_CASE("Packet blob seam rejects local blob producers that would truncate")
{
	uint32_t blobSize = 0;

	CHECK(PacketsSeams::TryGetBlobPayloadSize(16u, &blobSize));
	CHECK_EQ(blobSize, static_cast<uint32_t>(16u));
	CHECK_FALSE(PacketsSeams::TryGetBlobPayloadSize(static_cast<size_t>(UINT32_MAX) + 1u, &blobSize));
}

TEST_CASE("Raw packet span seam accepts the full raw 32-bit payload range")
{
	uint32_t payloadSize = 0;

	CHECK(PacketsSeams::TryGetRawPacketPayloadSizeFromSpan(UINT32_MAX, &payloadSize));
	CHECK_EQ(payloadSize, UINT32_MAX);
	CHECK_FALSE(PacketsSeams::TryGetRawPacketPayloadSizeFromSpan(static_cast<uint64_t>(UINT32_MAX) + 1u, &payloadSize));
	CHECK_FALSE(PacketsSeams::TryGetRawPacketPayloadSizeFromSpan(1u, NULL));
}

TEST_CASE("Packet compression work seam rejects wrapped scratch spans")
{
	size_t workSize = 0;

	CHECK(PacketsSeams::TryGetPacketCompressionWorkSize(42u, &workSize));
	CHECK_EQ(workSize, static_cast<size_t>(342u));
	CHECK(PacketsSeams::TryGetPacketCompressionWorkSize(UINT32_MAX - 300u, &workSize));
	CHECK_EQ(workSize, static_cast<size_t>(UINT32_MAX));
	CHECK_FALSE(PacketsSeams::TryGetPacketCompressionWorkSize(UINT32_MAX - 299u, &workSize));
	CHECK_FALSE(PacketsSeams::TryGetPacketCompressionWorkSize(1u, NULL));
}

TEST_SUITE_END();
