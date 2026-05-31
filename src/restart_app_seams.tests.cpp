#include "doctest.h"

#include "RestartAppSeams.h"

TEST_SUITE_BEGIN("restart_app");

TEST_CASE("Restart app seam quotes command-line arguments for CreateProcess")
{
	CHECK(RestartAppSeams::QuoteCommandLineArgument(_T("plain")) == CString(_T("plain")));
	CHECK(RestartAppSeams::QuoteCommandLineArgument(_T("C:\\Program Files\\eMuleBB\\emulebb.exe")) == CString(_T("\"C:\\Program Files\\eMuleBB\\emulebb.exe\"")));
	CHECK(RestartAppSeams::QuoteCommandLineArgument(_T("C:\\path\\with\\trailing\\\\")) == CString(_T("C:\\path\\with\\trailing\\\\")));
	CHECK(RestartAppSeams::QuoteCommandLineArgument(_T("quoted\"value")) == CString(_T("\"quoted\\\"value\"")));
	CHECK(RestartAppSeams::QuoteCommandLineArgument(_T("")) == CString(_T("\"\"")));
}

TEST_CASE("Restart app seam builds profile-only restart arguments")
{
	const std::vector<CString> noProfile = RestartAppSeams::BuildProfileRestartArguments(false, _T(""));
	CHECK(noProfile.empty());

	const std::vector<CString> profile = RestartAppSeams::BuildProfileRestartArguments(true, _T("C:\\profiles\\one\\"));
	REQUIRE(profile.size() == 2);
	CHECK(profile[0] == CString(_T("-c")));
	CHECK(profile[1] == CString(_T("C:\\profiles\\one\\")));
}

TEST_CASE("Restart app seam classifies sidecar wait outcomes")
{
	CHECK(RestartAppSeams::GetRestartActionAfterParentWait(WAIT_OBJECT_0) == RestartAppSeams::ERestartSidecarAction::LaunchRestart);
	CHECK(RestartAppSeams::GetRestartActionAfterParentWait(WAIT_TIMEOUT) == RestartAppSeams::ERestartSidecarAction::ExitWithoutLaunch);
	CHECK(RestartAppSeams::GetRestartActionAfterParentWait(WAIT_FAILED) == RestartAppSeams::ERestartSidecarAction::ExitWithoutLaunch);
	CHECK(RestartAppSeams::GetRestartActionAfterOpenParentFailure(ERROR_INVALID_PARAMETER) == RestartAppSeams::ERestartSidecarAction::LaunchRestart);
	CHECK(RestartAppSeams::GetRestartActionAfterOpenParentFailure(ERROR_ACCESS_DENIED) == RestartAppSeams::ERestartSidecarAction::ExitWithoutLaunch);
}

TEST_CASE("Restart app seam validates canonical absolute restart request paths")
{
	CHECK(RestartAppSeams::IsAbsoluteRequestFilePath(_T("C:\\profiles\\one\\config\\emulebb-restart-request-pid42.json")));
	CHECK_FALSE(RestartAppSeams::IsAbsoluteRequestFilePath(_T("restart.json")));
	CHECK_FALSE(RestartAppSeams::IsAbsoluteRequestFilePath(_T("C:/profiles/one/restart.json")));
}

TEST_SUITE_END();
