#include "../third_party/doctest/doctest.h"

#include "DirectDownloadSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("DirectDownload seam rejects handle registration after owner cancellation")
{
	CHECK(DirectDownloadSeams::ShouldRegisterInternetHandleForCancellationState(false));
	CHECK_FALSE(DirectDownloadSeams::ShouldRegisterInternetHandleForCancellationState(true));
}

TEST_SUITE_END();
