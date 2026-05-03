#include "../third_party/doctest/doctest.h"

#include "PreferenceUiSeams.h"

#if __has_include("PreferenceIniMap.h")
#include "PreferenceIniMap.h"
#define EMULE_TESTS_HAS_PREFERENCE_INI_MAP 1
#else
#define EMULE_TESTS_HAS_PREFERENCE_INI_MAP 0
#endif

#include <climits>
#include <vector>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Preference UI seam validates WebServer allowed-IP lists")
{
	std::vector<uint32_t> addresses;
	CString invalidToken;

	CHECK(PreferenceUiSeams::TryParseAllowedRemoteIpList(CString(_T("127.0.0.1; 192.168.1.50")), addresses, invalidToken));
	REQUIRE(addresses.size() == 2);
	CHECK(PreferenceUiSeams::FormatAllowedRemoteIpList(addresses) == CString(_T("127.0.0.1;192.168.1.50")));

	CHECK(PreferenceUiSeams::TryParseAllowedRemoteIpList(CString(_T(" ;10.0.0.5;;")), addresses, invalidToken));
	REQUIRE(addresses.size() == 1);
	CHECK(PreferenceUiSeams::FormatAllowedRemoteIpList(addresses) == CString(_T("10.0.0.5")));

	CHECK_FALSE(PreferenceUiSeams::TryParseAllowedRemoteIpList(CString(_T("192.168.1.999")), addresses, invalidToken));
	CHECK(invalidToken == CString(_T("192.168.1.999")));

	CHECK_FALSE(PreferenceUiSeams::TryParseAllowedRemoteIpList(CString(_T("0.0.0.0")), addresses, invalidToken));
	CHECK(invalidToken == CString(_T("0.0.0.0")));
}

TEST_CASE("Preference UI seam normalizes exposed hidden-option modes")
{
	CHECK(PreferenceUiSeams::NormalizeCrashDumpMode(0) == 0);
	CHECK(PreferenceUiSeams::NormalizeCrashDumpMode(1) == 1);
	CHECK(PreferenceUiSeams::NormalizeCrashDumpMode(2) == 2);
	CHECK(PreferenceUiSeams::NormalizeCrashDumpMode(9) == 0);

	CHECK(PreferenceUiSeams::NormalizePreviewSmallBlocks(0) == 0);
	CHECK(PreferenceUiSeams::NormalizePreviewSmallBlocks(1) == 1);
	CHECK(PreferenceUiSeams::NormalizePreviewSmallBlocks(2) == 2);
	CHECK(PreferenceUiSeams::NormalizePreviewSmallBlocks(-1) == 0);

	CHECK(PreferenceUiSeams::NormalizeLogFileFormat(0) == 0);
	CHECK(PreferenceUiSeams::NormalizeLogFileFormat(1) == 1);
	CHECK(PreferenceUiSeams::NormalizeLogFileFormat(7) == 0);

	CHECK(PreferenceUiSeams::NormalizePerfLogFileFormat(0) == 0);
	CHECK(PreferenceUiSeams::NormalizePerfLogFileFormat(1) == 1);
	CHECK(PreferenceUiSeams::NormalizePerfLogFileFormat(3) == 0);
}

TEST_CASE("Preference UI seam bounds diagnostic numeric options")
{
	CHECK(PreferenceUiSeams::kDefaultLogFileSizeBytes == 16u * 1024u * 1024u);
	CHECK(PreferenceUiSeams::kDefaultLogBufferKiB == 256u);
	CHECK(PreferenceUiSeams::IsLogFileSizeKiBAllowed(0));
	CHECK(PreferenceUiSeams::IsLogFileSizeKiBAllowed(PreferenceUiSeams::kMaxLogFileSizeKiB));
	CHECK_FALSE(PreferenceUiSeams::IsLogFileSizeKiBAllowed(PreferenceUiSeams::kMaxLogFileSizeKiB + 1));
	CHECK(PreferenceUiSeams::NormalizeLogFileSizeBytes(-1) == PreferenceUiSeams::kDefaultLogFileSizeBytes);
	CHECK(PreferenceUiSeams::NormalizeLogFileSizeBytes(static_cast<int>(PreferenceUiSeams::LogFileSizeKiBToBytes(128))) == PreferenceUiSeams::LogFileSizeKiBToBytes(128));
	CHECK(PreferenceUiSeams::NormalizeLogFileSizeBytes(INT_MAX) == PreferenceUiSeams::kDefaultLogFileSizeBytes);

	CHECK(PreferenceUiSeams::IsLogBufferKiBAllowed(PreferenceUiSeams::kMinLogBufferKiB));
	CHECK(PreferenceUiSeams::IsLogBufferKiBAllowed(PreferenceUiSeams::kMaxLogBufferKiB));
	CHECK_FALSE(PreferenceUiSeams::IsLogBufferKiBAllowed(PreferenceUiSeams::kMinLogBufferKiB - 1));
	CHECK(PreferenceUiSeams::NormalizeLogBufferKiB(-1) == PreferenceUiSeams::kDefaultLogBufferKiB);
	CHECK(PreferenceUiSeams::NormalizeLogBufferKiB(static_cast<int>(PreferenceUiSeams::kMinLogBufferKiB - 1)) == PreferenceUiSeams::kDefaultLogBufferKiB);
	CHECK(PreferenceUiSeams::NormalizeLogBufferKiB(256) == 256);

	CHECK(PreferenceUiSeams::NormalizePositiveBounded(0, 50, PreferenceUiSeams::kMaxMessageSessions) == 50);
	CHECK(PreferenceUiSeams::NormalizePositiveBounded(100, 50, PreferenceUiSeams::kMaxMessageSessions) == 100);
	CHECK(PreferenceUiSeams::NormalizePositiveBounded(10001, 50, PreferenceUiSeams::kMaxMessageSessions) == 50);

	CHECK(PreferenceUiSeams::NormalizePerfLogIntervalMinutes(1) == 1);
	CHECK(PreferenceUiSeams::NormalizePerfLogIntervalMinutes(PreferenceUiSeams::kMaxPerfLogIntervalMinutes) == PreferenceUiSeams::kMaxPerfLogIntervalMinutes);
	CHECK(PreferenceUiSeams::NormalizePerfLogIntervalMinutes(0) == 5);
	CHECK(PreferenceUiSeams::NormalizePerfLogIntervalMinutes(PreferenceUiSeams::kMaxPerfLogIntervalMinutes + 1) == 5);
}

#if EMULE_TESTS_HAS_PREFERENCE_INI_MAP
TEST_CASE("Preference INI map uses dedicated BB-added sections without legacy BB key names")
{
	CHECK(CString(PreferenceIniMap::Sections::FileCompletion) == CString(_T("FileCompletion")));
	CHECK(CString(PreferenceIniMap::Sections::Proxy) == CString(_T("Proxy")));
	CHECK(CString(PreferenceIniMap::Sections::Statistics) == CString(_T("Statistics")));
	CHECK(CString(PreferenceIniMap::Sections::UploadPolicy) == CString(_T("UploadPolicy")));
	CHECK(CString(PreferenceIniMap::Sections::UPnP) == CString(_T("UPnP")));
	CHECK(CString(PreferenceIniMap::Sections::WebServer) == CString(_T("WebServer")));
	CHECK(CString(PreferenceIniMap::Sections::eMule) == CString(_T("eMule")));

	CHECK(CString(PreferenceIniMap::FileCompletionKeys::RunCommandOnFileCompletion) == CString(_T("RunCommandOnFileCompletion")));
	CHECK(CString(PreferenceIniMap::FileCompletionKeys::Program) == CString(_T("FileCompletionProgram")));
	CHECK(CString(PreferenceIniMap::FileCompletionKeys::Arguments) == CString(_T("FileCompletionArguments")));

	CHECK(CString(PreferenceIniMap::GeoLocationKeys::LookupEnabled) == CString(_T("GeoLocationLookupEnabled")));
	CHECK(CString(PreferenceIniMap::GeoLocationKeys::UpdatePeriodDays) == CString(_T("GeoLocationUpdatePeriodDays")));
	CHECK(CString(PreferenceIniMap::GeoLocationKeys::LastUpdateTime) == CString(_T("GeoLocationLastUpdateTime")));
	CHECK(CString(PreferenceIniMap::GeoLocationKeys::UpdateUrl) == CString(_T("GeoLocationUpdateUrl")));

	CHECK(CString(PreferenceIniMap::IPFilterUpdateKeys::Enabled) == CString(_T("IPFilterUpdateEnabled")));
	CHECK(CString(PreferenceIniMap::IPFilterUpdateKeys::PeriodDays) == CString(_T("IPFilterUpdatePeriodDays")));
	CHECK(CString(PreferenceIniMap::IPFilterUpdateKeys::LastUpdateTime) == CString(_T("IPFilterLastUpdateTime")));
	CHECK(CString(PreferenceIniMap::IPFilterUpdateKeys::Url) == CString(_T("IPFilterUpdateUrl")));

	CHECK(CString(PreferenceIniMap::UploadPolicyKeys::MaxUploadClientsAllowed) == CString(_T("MaxUploadClientsAllowed")));
	CHECK(CString(PreferenceIniMap::UploadPolicyKeys::SlowUploadThresholdFactor) == CString(_T("SlowUploadThresholdFactor")));
	CHECK(CString(PreferenceIniMap::UploadPolicyKeys::ZeroUploadRateGraceSeconds) == CString(_T("ZeroUploadRateGraceSeconds")));
	CHECK(CString(PreferenceIniMap::UploadPolicyKeys::LowRatioScoreBonus) == CString(_T("LowRatioScoreBonus")));
	CHECK(CString(PreferenceIniMap::UploadPolicyKeys::SessionTransferLimitMode) == CString(_T("SessionTransferLimitMode")));
	CHECK(CString(PreferenceIniMap::UploadPolicyKeys::SessionTransferLimitValue) == CString(_T("SessionTransferLimitValue")));
	CHECK(CString(PreferenceIniMap::UploadPolicyKeys::SessionTimeLimitSeconds) == CString(_T("SessionTimeLimitSeconds")));

	CHECK_FALSE(CString(PreferenceIniMap::UploadPolicyKeys::MaxUploadClientsAllowed).Left(2) == CString(_T("BB")));
	CHECK_FALSE(CString(PreferenceIniMap::UploadPolicyKeys::SessionTransferLimitMode).Left(2) == CString(_T("BB")));
}
#endif

TEST_SUITE_END;
