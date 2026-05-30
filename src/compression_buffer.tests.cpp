#include "../third_party/doctest/doctest.h"

#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#include "CompressionBufferSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Compression buffer seam derives a bounded initial zlib work buffer")
{
	size_t nBufferSize = 0;

	CHECK(TryDeriveZlibBufferSize(32u, 10u, 300u, 250000u, &nBufferSize));
	CHECK_EQ(nBufferSize, static_cast<size_t>(620));
}

TEST_CASE("Compression buffer seam clamps overflowed initial requests to the configured cap")
{
	size_t nBufferSize = 0;

	CHECK(TryDeriveZlibBufferSize(std::numeric_limits<size_t>::max(), 10u, 300u, 250000u, &nBufferSize));
	CHECK_EQ(nBufferSize, static_cast<size_t>(250000));
}

TEST_CASE("Compression buffer seam doubles retries and caps the last growth step")
{
	size_t nNextSize = 0;

	CHECK(TryGrowZlibBufferSize(1024u, 4096u, &nNextSize));
	CHECK_EQ(nNextSize, static_cast<size_t>(2048));

	CHECK(TryGrowZlibBufferSize(3000u, 4096u, &nNextSize));
	CHECK_EQ(nNextSize, static_cast<size_t>(4096));

	CHECK_FALSE(TryGrowZlibBufferSize(4096u, 4096u, &nNextSize));
}

TEST_CASE("Compression buffer seam copies temporary vector data into legacy-owned storage")
{
	const std::vector<unsigned char> payload{0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu};

	std::unique_ptr<unsigned char[]> pOwned = MakeOwnedByteBufferCopy(payload, 4u);
	REQUIRE(pOwned != nullptr);
	CHECK(std::memcmp(pOwned.get(), payload.data(), 4u) == 0);

	CHECK_FALSE(MakeOwnedByteBufferCopy(payload, 6u));
}

TEST_CASE("Compression buffer seam rejects zero-byte ownership handoff")
{
	const std::vector<unsigned char> payload{0x11u, 0x22u};

	CHECK_FALSE(MakeOwnedByteBufferCopy(payload, 0u));
}

TEST_CASE("Compression buffer seam grows legacy-owned buffers without losing inflated bytes")
{
#ifdef EMULEBB_TEST_HAVE_OWNED_BYTE_BUFFER_GROWTH
	std::unique_ptr<unsigned char[]> buffer(new unsigned char[2]);
	buffer[0] = 0x11u;
	buffer[1] = 0x22u;

	CHECK(TryGrowOwnedByteBuffer(buffer, 2u, 4u));
	REQUIRE(buffer != nullptr);
	CHECK_EQ(buffer[0], static_cast<unsigned char>(0x11u));
	CHECK_EQ(buffer[1], static_cast<unsigned char>(0x22u));
	CHECK_FALSE(TryGrowOwnedByteBuffer(buffer, 5u, 4u));
#else
	MESSAGE("Compression owned-buffer growth helper is not available in this workspace.");
#endif
}

TEST_SUITE_END;
