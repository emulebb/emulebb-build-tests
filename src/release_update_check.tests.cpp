#include "../third_party/doctest/doctest.h"

#include "PartFileHashLaunchSeams.h"
#include "ReleaseUpdateCheckSeams.h"
#include "VersionCheckLaunchSeams.h"

using PartFileHashLaunchSeams::IsHashWorkerBusyStatus;
using ReleaseUpdateCheckSeams::BuildRequiredAssetName;
using ReleaseUpdateCheckSeams::CompareReleaseVersions;
using ReleaseUpdateCheckSeams::EReleaseEvaluationStatus;
using ReleaseUpdateCheckSeams::EvaluateLatestReleaseJson;
using ReleaseUpdateCheckSeams::SModReleaseVersion;
using ReleaseUpdateCheckSeams::TryParseReleaseTag;
using VersionCheckLaunchSeams::ClearQueued;
using VersionCheckLaunchSeams::IsQueued;
using VersionCheckLaunchSeams::PostCompletion;
using VersionCheckLaunchSeams::TryMarkQueued;

namespace
{
	std::string BuildReleaseJson(const char *pszTagName, const char *pszAssetName, bool bDraft = false, bool bPrerelease = false)
	{
		return std::string("{\"tag_name\":\"") + pszTagName
			+ "\",\"html_url\":\"https://github.com/eMulebb/eMule/releases/tag/" + pszTagName
			+ "\",\"draft\":" + (bDraft ? "true" : "false")
			+ ",\"prerelease\":" + (bPrerelease ? "true" : "false")
			+ ",\"assets\":[{\"name\":\"" + pszAssetName + "\"}]}";
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("eMule BB release tags use strict semver identity")
{
	SModReleaseVersion parsed = {};

	CHECK(TryParseReleaseTag("emule-bb-v1.1.1", parsed));
	CHECK_EQ(parsed.uMajor, 1u);
	CHECK_EQ(parsed.uMinor, 1u);
	CHECK_EQ(parsed.uPatch, 1u);

	CHECK_FALSE(TryParseReleaseTag("v0.72a-bb.1", parsed));
	CHECK_FALSE(TryParseReleaseTag("bb-v1.1.1", parsed));
	CHECK_FALSE(TryParseReleaseTag("emule-bb-v1.1", parsed));
	CHECK_FALSE(TryParseReleaseTag("emule-bb-v1.1.1-beta", parsed));
	CHECK_FALSE(TryParseReleaseTag("emule-bb-v42949672960.0.0", parsed));
}

TEST_CASE("eMule BB release version comparison orders major minor and patch")
{
	CHECK_EQ(CompareReleaseVersions({1u, 0u, 0u}, {1u, 0u, 0u}), 0);
	CHECK_GT(CompareReleaseVersions({1u, 0u, 1u}, {1u, 0u, 0u}), 0);
	CHECK_GT(CompareReleaseVersions({1u, 1u, 0u}, {1u, 0u, 9u}), 0);
	CHECK_GT(CompareReleaseVersions({2u, 0u, 0u}, {1u, 99u, 99u}), 0);
	CHECK_LT(CompareReleaseVersions({1u, 0u, 0u}, {1u, 0u, 1u}), 0);
}

TEST_CASE("eMule BB release evaluation requires current-platform ZIP asset")
{
	const SModReleaseVersion local = {1u, 1u, 1u};
	const std::string strX64Asset = BuildRequiredAssetName({1u, 1u, 2u}, "x64");

	const auto newer = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.2", strX64Asset.c_str()), local, "x64");
	CHECK_EQ(newer.eStatus, EReleaseEvaluationStatus::Newer);
	CHECK_EQ(newer.strRequiredAssetName, "eMule-broadband-1.1.2-x64.zip");

	const auto missingAsset = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.2", "eMule-broadband-1.1.2-arm64.zip"), local, "x64");
	CHECK_EQ(missingAsset.eStatus, EReleaseEvaluationStatus::MissingAsset);

	const auto notNewer = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.1", "eMule-broadband-1.1.1-x64.zip"), local, "x64");
	CHECK_EQ(notNewer.eStatus, EReleaseEvaluationStatus::NotNewer);
}

TEST_CASE("eMule BB release evaluation ignores malformed and prerelease payloads")
{
	const SModReleaseVersion local = {1u, 1u, 1u};

	const auto malformedTag = EvaluateLatestReleaseJson(BuildReleaseJson("v0.72a-bb.1", "eMule-broadband-1.1.2-x64.zip"), local, "x64");
	CHECK_EQ(malformedTag.eStatus, EReleaseEvaluationStatus::IgnoredRelease);

	const auto overflowedTag = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v42949672960.0.0", "eMule-broadband-42949672960.0.0-x64.zip"), local, "x64");
	CHECK_EQ(overflowedTag.eStatus, EReleaseEvaluationStatus::IgnoredRelease);

	const auto prerelease = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.2", "eMule-broadband-1.1.2-x64.zip", false, true), local, "x64");
	CHECK_EQ(prerelease.eStatus, EReleaseEvaluationStatus::IgnoredRelease);

	const auto parseFailed = EvaluateLatestReleaseJson("{not-json", local, "x64");
	CHECK_EQ(parseFailed.eStatus, EReleaseEvaluationStatus::ParseFailed);
}

TEST_SUITE_END;

TEST_SUITE_BEGIN("part_file_hash_launch");

TEST_CASE("part file hash launch guard blocks active hash and completion statuses")
{
	constexpr int kReady = 0;
	constexpr int kWaitingForHash = 2;
	constexpr int kHashing = 3;
	constexpr int kCompleting = 8;
	constexpr int kComplete = 9;

	CHECK_FALSE(IsHashWorkerBusyStatus(kReady, kWaitingForHash, kHashing, kCompleting));
	CHECK(IsHashWorkerBusyStatus(kWaitingForHash, kWaitingForHash, kHashing, kCompleting));
	CHECK(IsHashWorkerBusyStatus(kHashing, kWaitingForHash, kHashing, kCompleting));
	CHECK(IsHashWorkerBusyStatus(kCompleting, kWaitingForHash, kHashing, kCompleting));
	CHECK_FALSE(IsHashWorkerBusyStatus(kComplete, kWaitingForHash, kHashing, kCompleting));
}

TEST_SUITE_END;

TEST_SUITE_BEGIN("version_check_launch");

TEST_CASE("version check launch gate allows only one in-flight worker")
{
	volatile LONG lQueued = 0;

	CHECK_FALSE(IsQueued(lQueued));
	CHECK(TryMarkQueued(lQueued));
	CHECK(IsQueued(lQueued));
	CHECK_FALSE(TryMarkQueued(lQueued));

	ClearQueued(lQueued);
	CHECK_FALSE(IsQueued(lQueued));
	CHECK(TryMarkQueued(lQueued));
}

TEST_CASE("version check completion post failure releases launch gate")
{
	volatile LONG lQueued = 0;
	REQUIRE(TryMarkQueued(lQueued));

	const auto result = PostCompletion(NULL, WM_APP + 1, 0, &lQueued);

	CHECK_FALSE(result.bDelivered);
	CHECK_FALSE(IsQueued(lQueued));
}

TEST_SUITE_END;
