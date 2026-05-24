#include "doctest.h"

#include "ServerConnectSeams.h"

TEST_SUITE_BEGIN("server_connect");

TEST_CASE("Server connect falls back from exhausted optional obfuscation to plain")
{
	CHECK(ServerConnectSeams::SelectServerListExhaustionAction(false, true, false) == ServerConnectSeams::EServerListExhaustionAction::FallbackToPlain);
	CHECK(ServerConnectSeams::SelectServerListExhaustionAction(false, true, true) == ServerConnectSeams::EServerListExhaustionAction::ScheduleRetry);
	CHECK(ServerConnectSeams::SelectServerListExhaustionAction(false, false, false) == ServerConnectSeams::EServerListExhaustionAction::ScheduleRetry);
	CHECK(ServerConnectSeams::SelectServerListExhaustionAction(true, true, false) == ServerConnectSeams::EServerListExhaustionAction::None);
}

TEST_CASE("Server connect retries a single obfuscated server as plain only when allowed")
{
	CHECK(ServerConnectSeams::ShouldRetrySingleServerWithoutObfuscation(true, true, true, false));
	CHECK_FALSE(ServerConnectSeams::ShouldRetrySingleServerWithoutObfuscation(true, true, true, true));
	CHECK_FALSE(ServerConnectSeams::ShouldRetrySingleServerWithoutObfuscation(true, false, true, false));
	CHECK_FALSE(ServerConnectSeams::ShouldRetrySingleServerWithoutObfuscation(false, true, true, false));
	CHECK_FALSE(ServerConnectSeams::ShouldRetrySingleServerWithoutObfuscation(true, true, false, false));
}

TEST_CASE("Server connect suppresses duplicate automatic connection attempts")
{
	CHECK(ServerConnectSeams::ShouldSuppressDuplicateConnectRequest(false, true, true));
	CHECK_FALSE(ServerConnectSeams::ShouldSuppressDuplicateConnectRequest(true, true, true));
	CHECK_FALSE(ServerConnectSeams::ShouldSuppressDuplicateConnectRequest(false, false, true));
	CHECK_FALSE(ServerConnectSeams::ShouldSuppressDuplicateConnectRequest(false, true, false));
}

TEST_SUITE_END();
