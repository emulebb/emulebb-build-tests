#include "doctest.h"

#include "WindowsMaintenanceActionsSeams.h"

TEST_SUITE_BEGIN("windows_maintenance_actions");

TEST_CASE("long path policy script enables only the expected registry value")
{
	const CString script = WindowsMaintenanceActionsSeams::BuildEnableLongPathsScript(
		_T("C:\\Temp\\long-paths-result.json"));

	CHECK(script.Find(_T("LongPathsEnabled")) >= 0);
	CHECK(script.Find(_T("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem")) >= 0);
	CHECK(script.Find(_T("New-ItemProperty")) >= 0);
	CHECK(script.Find(_T("-PropertyType DWord -Value 1")) >= 0);
	CHECK(script.Find(_T("emulebb.longPathPolicyResult.v1")) >= 0);
	CHECK(script.Find(_T("Press Enter to close this window")) >= 0);
	CHECK(script.Find(_T("Remove-Item")) < 0);
	CHECK(script.Find(_T("Set-ExecutionPolicy")) < 0);
}

TEST_CASE("defender exclusion script quotes requested paths and skips existing exclusions")
{
	std::vector<CString> paths;
	paths.push_back(_T("C:\\Downloads\\eMule Incoming\\"));
	paths.push_back(_T("C:\\Users\\O'Brien\\Temp\\"));

	const CString script = WindowsMaintenanceActionsSeams::BuildDefenderExclusionScript(
		paths,
		_T("C:\\Temp\\defender-result.json"));

	CHECK(script.Find(_T("'C:\\Downloads\\eMule Incoming\\'")) >= 0);
	CHECK(script.Find(_T("'C:\\Users\\O''Brien\\Temp\\'")) >= 0);
	CHECK(script.Find(_T("Get-MpPreference")) >= 0);
	CHECK(script.Find(_T("Add-MpPreference -ExclusionPath $path")) >= 0);
	CHECK(script.Find(_T("alreadyExcluded")) >= 0);
	CHECK(script.Find(_T("emulebb.defenderExclusionResult.v1")) >= 0);
	CHECK(script.Find(_T("Press Enter to close this window")) >= 0);
	CHECK(script.Find(_T("Remove-MpPreference")) < 0);
	CHECK(script.Find(_T("Set-MpPreference")) < 0);
}

TEST_SUITE_END();
