#include "../third_party/doctest/doctest.h"

#include "SchedulerPolicySeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Scheduler policy seam validates day and action domains")
{
	CHECK(SchedulerPolicySeams::NormalizeScheduleDay(DAY_DAILY) == DAY_DAILY);
	CHECK(SchedulerPolicySeams::NormalizeScheduleDay(DAY_SA_SO) == DAY_SA_SO);
	CHECK(SchedulerPolicySeams::NormalizeScheduleDay(99u) == DAY_DAILY);

	CHECK(SchedulerPolicySeams::IsValidScheduleAction(ACTION_SETUPL));
	CHECK(SchedulerPolicySeams::IsValidScheduleAction(ACTION_CATRESUME));
	CHECK_FALSE(SchedulerPolicySeams::IsValidScheduleAction(ACTION_NONE));
	CHECK_FALSE(SchedulerPolicySeams::IsValidScheduleAction(99));

	CHECK(SchedulerPolicySeams::CanAddScheduleAction(0));
	CHECK(SchedulerPolicySeams::CanAddScheduleAction(15));
	CHECK_FALSE(SchedulerPolicySeams::CanAddScheduleAction(16));
	CHECK_FALSE(SchedulerPolicySeams::CanAddScheduleAction(-1));
}

TEST_CASE("Scheduler policy seam gates duplicate and disabled checks")
{
	CHECK(SchedulerPolicySeams::ShouldCheckScheduler(true, 1, false, false, 10, 9));
	CHECK(SchedulerPolicySeams::ShouldCheckScheduler(true, 1, false, true, 10, 10));
	CHECK_FALSE(SchedulerPolicySeams::ShouldCheckScheduler(false, 1, false, true, 10, 10));
	CHECK_FALSE(SchedulerPolicySeams::ShouldCheckScheduler(true, 0, false, true, 10, 10));
	CHECK_FALSE(SchedulerPolicySeams::ShouldCheckScheduler(true, 1, true, true, 10, 10));
	CHECK_FALSE(SchedulerPolicySeams::ShouldCheckScheduler(true, 1, false, false, 10, 10));
}

TEST_CASE("Scheduler policy seam matches daily weekday and weekend selectors")
{
	CHECK(SchedulerPolicySeams::MatchesScheduleDay(DAY_DAILY, 1));
	CHECK(SchedulerPolicySeams::MatchesScheduleDay(DAY_MO, 2));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleDay(DAY_MO, 3));
	CHECK(SchedulerPolicySeams::MatchesScheduleDay(DAY_MO_FR, 2));
	CHECK(SchedulerPolicySeams::MatchesScheduleDay(DAY_MO_FR, 6));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleDay(DAY_MO_FR, 1));
	CHECK(SchedulerPolicySeams::MatchesScheduleDay(DAY_MO_SA, 7));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleDay(DAY_MO_SA, 1));
	CHECK(SchedulerPolicySeams::MatchesScheduleDay(DAY_SA_SO, 1));
	CHECK(SchedulerPolicySeams::MatchesScheduleDay(DAY_SA_SO, 7));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleDay(DAY_SA_SO, 4));
}

TEST_CASE("Scheduler policy seam matches normal overnight and no-end spans")
{
	CHECK(SchedulerPolicySeams::MatchesScheduleTime(600, 720, 600));
	CHECK(SchedulerPolicySeams::MatchesScheduleTime(600, 720, 719));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleTime(600, 720, 720));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleTime(600, 720, 599));

	CHECK(SchedulerPolicySeams::MatchesScheduleTime(1410, 310, 1439));
	CHECK(SchedulerPolicySeams::MatchesScheduleTime(1410, 310, 120));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleTime(1410, 310, 600));

	CHECK(SchedulerPolicySeams::MatchesScheduleTime(600, 0, 600));
	CHECK(SchedulerPolicySeams::MatchesScheduleTime(600, 0, 1439));
	CHECK_FALSE(SchedulerPolicySeams::MatchesScheduleTime(600, 0, 599));
}

TEST_CASE("Scheduler policy seam combines row eligibility")
{
	CHECK(SchedulerPolicySeams::ShouldActivateSchedule(true, true, DAY_MO, 600, 720, 2, 650));
	CHECK_FALSE(SchedulerPolicySeams::ShouldActivateSchedule(false, true, DAY_MO, 600, 720, 2, 650));
	CHECK_FALSE(SchedulerPolicySeams::ShouldActivateSchedule(true, false, DAY_MO, 600, 720, 2, 650));
	CHECK_FALSE(SchedulerPolicySeams::ShouldActivateSchedule(true, true, DAY_MO, 600, 720, 3, 650));
	CHECK_FALSE(SchedulerPolicySeams::ShouldActivateSchedule(true, true, DAY_MO, 600, 720, 2, 721));
}

TEST_CASE("Scheduler policy seam strictly parses action values")
{
	CString normalized;
	CHECK(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_SETUPL, CString(_T(" 42 ")), normalized));
	CHECK(normalized == CString(_T("42")));
	CHECK(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_CATSTOP, CString(_T("-2")), normalized));
	CHECK(normalized == CString(_T("-2")));
	CHECK(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_CATRESUME, CString(_T("-1")), normalized));
	CHECK(normalized == CString(_T("-1")));

	CHECK_FALSE(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_SETUPL, CString(_T("-1")), normalized));
	CHECK_FALSE(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_CATSTOP, CString(_T("-3")), normalized));
	CHECK_FALSE(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_CONS, CString(_T("12x")), normalized));
	CHECK_FALSE(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_NONE, CString(_T("1")), normalized));
	CHECK_FALSE(SchedulerPolicySeams::TryNormalizeScheduleActionValueText(ACTION_CONS, CString(_T("999999999999999999999")), normalized));
}

TEST_SUITE_END();
