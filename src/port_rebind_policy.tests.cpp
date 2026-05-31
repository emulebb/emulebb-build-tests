#include "../third_party/doctest/doctest.h"

#include "PortRebindPolicySeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Port rebind policy requires an application restart")
{
	CHECK_FALSE(PortRebindPolicySeams::CanApplyRuntimePortRebind());
}

TEST_SUITE_END();
