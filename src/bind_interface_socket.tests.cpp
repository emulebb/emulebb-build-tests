#include "../third_party/doctest/doctest.h"

#include <winsock2.h>

#ifndef ASSERT
#define ASSERT(expr) ((void)0)
#endif

#include "BindInterfaceSocketSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("IPv4 unicast interface option is required only for a resolved explicit bind interface")
{
	CHECK(BindInterfaceSocketSeams::ShouldApplyIpv4UnicastInterfaceOption(true, true, 12));

	CHECK_FALSE(BindInterfaceSocketSeams::ShouldApplyIpv4UnicastInterfaceOption(false, true, 12));
	CHECK_FALSE(BindInterfaceSocketSeams::ShouldApplyIpv4UnicastInterfaceOption(true, false, 12));
	CHECK_FALSE(BindInterfaceSocketSeams::ShouldApplyIpv4UnicastInterfaceOption(true, true, 0));
}
