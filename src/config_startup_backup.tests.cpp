#include "../third_party/doctest/doctest.h"

#include "ConfigStartupBackup.h"
#include "ConfigStartupBackupSeams.h"
#include "LongPathSeams.h"
#include "PathHelpers.h"
#include "LongPathTestSupport.h"

#include <vector>

namespace
{
	bool ContainsName(const std::vector<CString> &rNames, LPCTSTR pszName)
	{
		for (size_t i = 0; i < rNames.size(); ++i) {
			if (rNames[i] == pszName)
				return true;
		}
		return false;
	}

	bool DeleteDirectoryTree(const CString &rstrDirectory)
	{
		DWORD dwEnumerateError = ERROR_SUCCESS;
		if (!PathHelpers::ForEachDirectoryEntry(rstrDirectory, [&](const WIN32_FIND_DATA &findData) -> bool {
			const CString strChildPath(PathHelpers::AppendPathComponent(rstrDirectory, findData.cFileName));
			if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
				return DeleteDirectoryTree(strChildPath);
			return LongPathSeams::DeleteFileIfExists(strChildPath);
		}, &dwEnumerateError)) {
			if (dwEnumerateError != ERROR_FILE_NOT_FOUND && dwEnumerateError != ERROR_PATH_NOT_FOUND)
				return false;
		}
		return LongPathSeams::RemoveDirectory(rstrDirectory) != FALSE;
	}

	CString BuildTodaysBackupName()
	{
		SYSTEMTIME localTime = {};
		::GetLocalTime(&localTime);
		return ConfigStartupBackupSeams::BuildBackupDirectoryName(localTime.wYear, localTime.wMonth, localTime.wDay);
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Config startup backup seams format daily backup and staging names")
{
	CHECK(ConfigStartupBackupSeams::BuildBackupDirectoryName(2026, 5, 14) == CString(_T("config_bak_20260514")));
	CHECK(ConfigStartupBackupSeams::BuildBackupWorkingDirectoryName(2026, 5, 14) == CString(_T("config_bak_20260514.tmp")));
}

TEST_CASE("Config startup backup seams only accept exact backup directory names")
{
	CHECK(ConfigStartupBackupSeams::IsConfigBackupDirectoryName(_T("config_bak_20260514")));
	CHECK(ConfigStartupBackupSeams::IsConfigBackupDirectoryName(_T("CONFIG_BAK_20260514")));

	CHECK_FALSE(ConfigStartupBackupSeams::IsConfigBackupDirectoryName(_T("config_bak_20260514.tmp")));
	CHECK_FALSE(ConfigStartupBackupSeams::IsConfigBackupDirectoryName(_T("config_bak_2026-05-14")));
	CHECK_FALSE(ConfigStartupBackupSeams::IsConfigBackupDirectoryName(_T("config_bak_2026051")));
	CHECK_FALSE(ConfigStartupBackupSeams::IsConfigBackupDirectoryName(_T("config_bak_2026051x")));
	CHECK_FALSE(ConfigStartupBackupSeams::IsConfigBackupDirectoryName(_T("config_backup_20260514")));
}

TEST_CASE("Config startup backup seams skip backup directories and generated artifacts during copy")
{
	CHECK(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("config_bak_20260514"), true));
	CHECK(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("config_bak_20260514.tmp"), true));
	CHECK(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("sharedcache.dat"), false));
	CHECK(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("shareddups.dat"), false));
	CHECK(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("dbip-city-lite.mmdb"), false));
	CHECK(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("GeoIPCountryWhois.csv"), false));

	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("config_bak_20260514"), false));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("preferences.ini"), false));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("known.met"), false));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("known2.met"), false));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("known2_64.met"), false));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("clients.met"), false));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("ipfilter.dat"), false));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("incoming"), true));
	CHECK_FALSE(ConfigStartupBackupSeams::ShouldSkipConfigBackupEntry(_T("config_bak_custom"), true));
}

TEST_CASE("Config startup backup seams prune oldest valid daily backups and ignore malformed names")
{
	const std::vector<CString> names = {
		_T("config_bak_20260501"),
		_T("config_bak_20260502"),
		_T("config_bak_20260503"),
		_T("config_bak_20260504"),
		_T("config_bak_20260505"),
		_T("config_bak_20260506"),
		_T("config_bak_20260507"),
		_T("config_bak_20260508"),
		_T("config_bak_20260509"),
		_T("config_bak_20260510"),
		_T("config_bak_20260511.tmp"),
		_T("config_bak_custom"),
		_T("notes")
	};

	const std::vector<CString> pruneNames(ConfigStartupBackupSeams::SelectConfigBackupDirectoriesToPrune(names, 7));
	REQUIRE(pruneNames.size() == 3);
	CHECK(ContainsName(pruneNames, _T("config_bak_20260501")));
	CHECK(ContainsName(pruneNames, _T("config_bak_20260502")));
	CHECK(ContainsName(pruneNames, _T("config_bak_20260503")));
	CHECK_FALSE(ContainsName(pruneNames, _T("config_bak_20260504")));
	CHECK_FALSE(ContainsName(pruneNames, _T("config_bak_20260511.tmp")));
	CHECK_FALSE(ContainsName(pruneNames, _T("config_bak_custom")));
}

TEST_CASE("Config startup backup seams keep all backups when retention covers them")
{
	const std::vector<CString> names = {
		_T("config_bak_20260501"),
		_T("config_bak_20260502"),
		_T("config_bak_20260503")
	};

	CHECK(ConfigStartupBackupSeams::SelectConfigBackupDirectoriesToPrune(names, 7).empty());
}

TEST_CASE("Config startup backup runtime copies config files and skips backup directories")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	REQUIRE(fixture.Initialize(false, 4, 0xC0FFEEu));

	const CString strConfigDirectory(fixture.MakeDirectoryChildPath(L"config").c_str());
	REQUIRE(LongPathSeams::CreateDirectory(strConfigDirectory) != FALSE);

	const CString strPreferencesPath(PathHelpers::AppendPathComponent(strConfigDirectory, _T("preferences.ini")));
	const CString strKnown2Path(PathHelpers::AppendPathComponent(strConfigDirectory, _T("known2_64.met")));
	const CString strGeneratedCachePath(PathHelpers::AppendPathComponent(strConfigDirectory, _T("sharedcache.dat")));
	const CString strNestedDirectory(PathHelpers::AppendPathComponent(strConfigDirectory, _T("nested")));
	const CString strNestedFile(PathHelpers::AppendPathComponent(strNestedDirectory, _T("fileinfo.ini")));
	const CString strExistingBackup(PathHelpers::AppendPathComponent(strConfigDirectory, _T("config_bak_20000101")));
	const CString strExistingBackupFile(PathHelpers::AppendPathComponent(strExistingBackup, _T("old.ini")));
	const std::vector<BYTE> payload = { 'o', 'k' };

	REQUIRE(LongPathSeams::WriteAllBytes(strPreferencesPath, payload));
	REQUIRE(LongPathSeams::WriteAllBytes(strKnown2Path, payload));
	REQUIRE(LongPathSeams::WriteAllBytes(strGeneratedCachePath, payload));
	REQUIRE(LongPathSeams::CreateDirectory(strNestedDirectory) != FALSE);
	REQUIRE(LongPathSeams::WriteAllBytes(strNestedFile, payload));
	REQUIRE(LongPathSeams::CreateDirectory(strExistingBackup) != FALSE);
	REQUIRE(LongPathSeams::WriteAllBytes(strExistingBackupFile, payload));

	const ConfigStartupBackup::StartupConfigBackupResult result =
		ConfigStartupBackup::RunDailyStartupConfigBackup(strConfigDirectory, ConfigStartupBackupSeams::kDefaultBackupRetentionCount);

	const CString strTodayBackup(PathHelpers::AppendPathComponent(strConfigDirectory, BuildTodaysBackupName()));
	CHECK(result.bCreated);
	CHECK_FALSE(result.bCopyFailed);
	CHECK(LongPathSeams::PathExists(PathHelpers::AppendPathComponent(strTodayBackup, _T("preferences.ini"))));
	CHECK(LongPathSeams::PathExists(PathHelpers::AppendPathComponent(strTodayBackup, _T("nested\\fileinfo.ini"))));
	CHECK(LongPathSeams::PathExists(PathHelpers::AppendPathComponent(strTodayBackup, _T("known2_64.met"))));
	CHECK_FALSE(LongPathSeams::PathExists(PathHelpers::AppendPathComponent(strTodayBackup, _T("sharedcache.dat"))));
	CHECK_FALSE(LongPathSeams::PathExists(PathHelpers::AppendPathComponent(strTodayBackup, _T("config_bak_20000101\\old.ini"))));

	(void)DeleteDirectoryTree(strTodayBackup);
	(void)DeleteDirectoryTree(strExistingBackup);
	(void)DeleteDirectoryTree(strNestedDirectory);
	(void)LongPathSeams::DeleteFileIfExists(strKnown2Path);
	(void)LongPathSeams::DeleteFileIfExists(strGeneratedCachePath);
	(void)LongPathSeams::DeleteFileIfExists(strPreferencesPath);
	(void)DeleteDirectoryTree(strConfigDirectory);
}

TEST_SUITE_END();
