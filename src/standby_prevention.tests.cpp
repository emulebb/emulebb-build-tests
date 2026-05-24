#include "../third_party/doctest/doctest.h"

#include "StandbyPreventionSeams.h"

TEST_SUITE_BEGIN("standby_prevention");

TEST_CASE("Standby prevention is activity gated by the user preference")
{
	CHECK_FALSE(StandbyPreventionSeams::ShouldPreventSystemSleep(false, true, 1, 1));
	CHECK_FALSE(StandbyPreventionSeams::ShouldPreventSystemSleep(true, false, 0, 0));

	CHECK(StandbyPreventionSeams::ShouldPreventSystemSleep(true, true, 0, 0));
	CHECK(StandbyPreventionSeams::ShouldPreventSystemSleep(true, false, 1, 0));
	CHECK(StandbyPreventionSeams::ShouldPreventSystemSleep(true, false, 0, 1));
}

TEST_CASE("Standby prevention keeps system awake without forcing display awake")
{
	const EXECUTION_STATE preventFlags = StandbyPreventionSeams::GetPreventSystemSleepFlags();

	CHECK((preventFlags & ES_CONTINUOUS) != 0);
	CHECK((preventFlags & ES_SYSTEM_REQUIRED) != 0);
	CHECK((preventFlags & ES_DISPLAY_REQUIRED) == 0);
	CHECK(StandbyPreventionSeams::GetReleaseSystemSleepFlags() == ES_CONTINUOUS);
}

TEST_CASE("Standby prevention releases only previously asserted sleep prevention")
{
	CHECK(StandbyPreventionSeams::ShouldReleaseSystemSleepAssertion(true, false));
	CHECK_FALSE(StandbyPreventionSeams::ShouldReleaseSystemSleepAssertion(true, true));
	CHECK_FALSE(StandbyPreventionSeams::ShouldReleaseSystemSleepAssertion(false, false));
	CHECK_FALSE(StandbyPreventionSeams::ShouldReleaseSystemSleepAssertion(false, true));
}

TEST_SUITE_END();
