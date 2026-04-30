#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include "ClientCreditsSeams.h"

#include <limits>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Client credits seam builds bounded secure-ident challenge layouts")
{
	ClientCreditsChallengeLayout layout = {};
	CHECK(TryBuildClientCreditsChallengeLayout(kClientCreditsMaxPublicKeySize, false, layout));
	CHECK(layout.nMessageLength == kClientCreditsMaxPublicKeySize + 4u);
	CHECK(layout.nChallengeIpLength == 0u);

	CHECK(TryBuildClientCreditsChallengeLayout(kClientCreditsMaxPublicKeySize, true, layout));
	CHECK(layout.nMessageLength == kClientCreditsMaxPublicKeySize + 9u);
	CHECK(layout.nChallengeIpLength == 5u);

	CHECK_FALSE(TryBuildClientCreditsChallengeLayout(kClientCreditsMaxPublicKeySize + 1u, true, layout));
}

TEST_CASE("Client credits seam validates signature buffer capacity")
{
	CHECK(CanStoreClientCreditsSignature(0u, 0));
	CHECK(CanStoreClientCreditsSignature(80u, 80));
	CHECK_FALSE(CanStoreClientCreditsSignature(81u, 80));
}

#if defined(EMULE_TEST_HAVE_CLIENT_CREDITS_FAILURE_POLICY_SEAMS)
TEST_CASE("Client credits seam keeps secure-ident failure policy stable")
{
	CHECK(GetClientCreditsSignatureFailureResult() == 0u);
	CHECK(ShouldLogClientCreditsFailureDetail(true));
	CHECK_FALSE(ShouldLogClientCreditsFailureDetail(false));
}
#endif

#if defined(EMULE_TEST_HAVE_CLIENT_CREDITS_BUFFER_SEAMS)
TEST_CASE("Client credits seam sizes transient save buffers without overflow")
{
	size_t nBufferSize = 0;
	CHECK(TryBuildClientCreditsSaveBufferSize(4u, sizeof(uint32), &nBufferSize));
	CHECK(nBufferSize == 4u * sizeof(uint32));
	CHECK_FALSE(TryBuildClientCreditsSaveBufferSize((std::numeric_limits<size_t>::max)(), 2u, &nBufferSize));
}

TEST_CASE("Client credits seam resets secure-ident runtime state safely")
{
	int nDummySigner = 7;
	int *pSigner = &nDummySigner;
	unsigned char abyPublicKey[4] = {1, 2, 3, 4};
	unsigned char nPublicKeyLen = 4;

	ResetClientCreditsCryptState(pSigner, abyPublicKey, nPublicKeyLen);
	CHECK(pSigner == nullptr);
	CHECK(nPublicKeyLen == 0);
	CHECK(abyPublicKey[0] == 0);
	CHECK(abyPublicKey[1] == 0);
	CHECK(abyPublicKey[2] == 0);
	CHECK(abyPublicKey[3] == 0);

	ResetClientCreditsCryptState(pSigner, abyPublicKey, nPublicKeyLen);
	CHECK(pSigner == nullptr);
	CHECK(nPublicKeyLen == 0);
}
#endif

TEST_CASE("Client credits seam keeps the existing verify-failure state transition")
{
	CHECK(GetClientCreditsStateAfterVerifyFailure(1, 1, 3) == 3);
	CHECK(GetClientCreditsStateAfterVerifyFailure(2, 1, 3) == 2);
	CHECK(GetClientCreditsStateAfterVerifyFailure(4, 1, 3) == 4);
}

TEST_SUITE_END;
