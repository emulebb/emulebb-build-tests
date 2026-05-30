#include "../third_party/doctest/doctest.h"
#include "EncryptedStreamSocketSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Delayed server send completes once the pending negotiation buffer is fully flushed")
{
	CHECK(EncryptedStreamSocketSeams::ShouldCompleteDelayedServerSendAfterFlush(true, false));
}

TEST_CASE("Delayed server send stays pending while buffered negotiation data remains")
{
	CHECK_FALSE(EncryptedStreamSocketSeams::ShouldCompleteDelayedServerSendAfterFlush(true, true));
}

TEST_CASE("Non-delayed send states do not complete through the delayed-flush helper")
{
	CHECK_FALSE(EncryptedStreamSocketSeams::ShouldCompleteDelayedServerSendAfterFlush(false, false));
	CHECK_FALSE(EncryptedStreamSocketSeams::ShouldCompleteDelayedServerSendAfterFlush(false, true));
}

TEST_CASE("Encrypted stream seam validates negotiation send spans before pointer arithmetic")
{
#ifdef EMULEBB_TEST_HAVE_ENCRYPTED_STREAM_NEGOTIATION_BUFFER_LIMITS
	CHECK(EncryptedStreamSocketSeams::IsNegotiationSendSpanValid(0, 0));
	CHECK(EncryptedStreamSocketSeams::IsNegotiationSendSpanValid(1024, 512));
	CHECK_FALSE(EncryptedStreamSocketSeams::IsNegotiationSendSpanValid(-1, 0));
	CHECK_FALSE(EncryptedStreamSocketSeams::IsNegotiationSendSpanValid(1, -1));
	CHECK_FALSE(EncryptedStreamSocketSeams::IsNegotiationSendSpanValid(1, 2));
	CHECK_FALSE(EncryptedStreamSocketSeams::IsNegotiationSendSpanValid(
		static_cast<int>(EncryptedStreamSocketSeams::kMaxNegotiationSendBufferBytes + 1u),
		0));
#else
	MESSAGE("Encrypted stream negotiation span helper is not available in this workspace.");
#endif
}

TEST_CASE("Encrypted stream seam bounds delayed negotiation buffer appends")
{
#ifdef EMULEBB_TEST_HAVE_ENCRYPTED_STREAM_NEGOTIATION_BUFFER_LIMITS
	CHECK(EncryptedStreamSocketSeams::CanAppendNegotiationSendBuffer(0u, 1024u));
	CHECK(EncryptedStreamSocketSeams::CanAppendNegotiationSendBuffer(
		EncryptedStreamSocketSeams::kMaxNegotiationSendBufferBytes - 1024u,
		1024u));
	CHECK_FALSE(EncryptedStreamSocketSeams::CanAppendNegotiationSendBuffer(
		EncryptedStreamSocketSeams::kMaxNegotiationSendBufferBytes,
		1u));
	CHECK_FALSE(EncryptedStreamSocketSeams::CanAppendNegotiationSendBuffer(
		0u,
		static_cast<uint32_t>(EncryptedStreamSocketSeams::kMaxNegotiationSendBufferBytes + 1u)));
#else
	MESSAGE("Encrypted stream negotiation buffer append helper is not available in this workspace.");
#endif
}

TEST_CASE("Encrypted stream seam narrows buffered negotiation lengths explicitly")
{
#ifdef EMULEBB_TEST_HAVE_ENCRYPTED_STREAM_NEGOTIATION_BUFFER_LIMITS
	uint32_t bufferBytes = 0;

	CHECK(EncryptedStreamSocketSeams::TryGetNegotiationSendBufferLength(1024u, &bufferBytes));
	CHECK_EQ(bufferBytes, static_cast<uint32_t>(1024u));
	CHECK_FALSE(EncryptedStreamSocketSeams::TryGetNegotiationSendBufferLength(
		EncryptedStreamSocketSeams::kMaxNegotiationSendBufferBytes + 1u,
		&bufferBytes));
	CHECK_FALSE(EncryptedStreamSocketSeams::TryGetNegotiationSendBufferLength(1024u, NULL));
#else
	MESSAGE("Encrypted stream negotiation length helper is not available in this workspace.");
#endif
}
