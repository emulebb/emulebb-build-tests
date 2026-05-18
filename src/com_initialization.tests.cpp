#include "../third_party/doctest/doctest.h"

#include "ComInitializationSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("COM initialization seam keeps changed mode usable without ownership")
{
	using namespace ComInitializationSeams;

	CHECK(IsInitializationUsable(S_OK));
	CHECK(IsInitializationUsable(S_FALSE));
	CHECK(IsInitializationUsable(RPC_E_CHANGED_MODE));
	CHECK_FALSE(IsInitializationUsable(E_FAIL));

	CHECK(ShouldUninitializeAfterInitialization(S_OK));
	CHECK(ShouldUninitializeAfterInitialization(S_FALSE));
	CHECK_FALSE(ShouldUninitializeAfterInitialization(RPC_E_CHANGED_MODE));
	CHECK_FALSE(ShouldUninitializeAfterInitialization(E_FAIL));
}

TEST_SUITE_END;
