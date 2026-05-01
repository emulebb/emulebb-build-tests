#include "../third_party/doctest/doctest.h"

#include "ReleaseUpdateCheckSeams.h"

using ReleaseUpdateCheckSeams::BuildRequiredAssetName;
using ReleaseUpdateCheckSeams::CompareReleaseVersions;
using ReleaseUpdateCheckSeams::EReleaseEvaluationStatus;
using ReleaseUpdateCheckSeams::EvaluateLatestReleaseJson;
using ReleaseUpdateCheckSeams::SModReleaseVersion;
using ReleaseUpdateCheckSeams::TryParseReleaseTag;

namespace
{
	std::string BuildReleaseJson(const char *pszTagName, const char *pszAssetName, bool bDraft = false, bool bPrerelease = false)
	{
		return std::string("{\"tag_name\":\"") + pszTagName
			+ "\",\"html_url\":\"https://github.com/itlezy/eMule/releases/tag/" + pszTagName
			+ "\",\"draft\":" + (bDraft ? "true" : "false")
			+ ",\"prerelease\":" + (bPrerelease ? "true" : "false")
			+ ",\"assets\":[{\"name\":\"" + pszAssetName + "\"}]}";
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("eMule BB release tags use strict semver identity")
{
	SModReleaseVersion parsed = {};

	CHECK(TryParseReleaseTag("emule-bb-v1.1.0", parsed));
	CHECK_EQ(parsed.uMajor, 1u);
	CHECK_EQ(parsed.uMinor, 1u);
	CHECK_EQ(parsed.uPatch, 0u);

	CHECK_FALSE(TryParseReleaseTag("v0.72a-bb.1", parsed));
	CHECK_FALSE(TryParseReleaseTag("bb-v1.1.0", parsed));
	CHECK_FALSE(TryParseReleaseTag("emule-bb-v1.1", parsed));
	CHECK_FALSE(TryParseReleaseTag("emule-bb-v1.1.0-beta", parsed));
	CHECK_FALSE(TryParseReleaseTag("emule-bb-v42949672960.0.0", parsed));
}

TEST_CASE("eMule BB release version comparison orders major minor and patch")
{
	CHECK_EQ(CompareReleaseVersions({1u, 1u, 0u}, {1u, 1u, 0u}), 0);
	CHECK_GT(CompareReleaseVersions({1u, 1u, 1u}, {1u, 1u, 0u}), 0);
	CHECK_GT(CompareReleaseVersions({1u, 2u, 0u}, {1u, 1u, 9u}), 0);
	CHECK_GT(CompareReleaseVersions({2u, 0u, 0u}, {1u, 99u, 99u}), 0);
	CHECK_LT(CompareReleaseVersions({1u, 1u, 0u}, {1u, 1u, 1u}), 0);
}

TEST_CASE("eMule BB release evaluation requires current-platform ZIP asset")
{
	const SModReleaseVersion local = {1u, 1u, 0u};
	const std::string strX64Asset = BuildRequiredAssetName({1u, 1u, 1u}, "x64");

	const auto newer = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.1", strX64Asset.c_str()), local, "x64");
	CHECK_EQ(newer.eStatus, EReleaseEvaluationStatus::Newer);
	CHECK_EQ(newer.strRequiredAssetName, "eMule-BB-1.1.1-x64.zip");

	const auto missingAsset = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.1", "eMule-BB-1.1.1-arm64.zip"), local, "x64");
	CHECK_EQ(missingAsset.eStatus, EReleaseEvaluationStatus::MissingAsset);

	const auto notNewer = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.0", "eMule-BB-1.1.0-x64.zip"), local, "x64");
	CHECK_EQ(notNewer.eStatus, EReleaseEvaluationStatus::NotNewer);
}

TEST_CASE("eMule BB release evaluation ignores malformed and prerelease payloads")
{
	const SModReleaseVersion local = {1u, 1u, 0u};

	const auto malformedTag = EvaluateLatestReleaseJson(BuildReleaseJson("v0.72a-bb.1", "eMule-BB-1.1.1-x64.zip"), local, "x64");
	CHECK_EQ(malformedTag.eStatus, EReleaseEvaluationStatus::IgnoredRelease);

	const auto overflowedTag = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v42949672960.0.0", "eMule-BB-42949672960.0.0-x64.zip"), local, "x64");
	CHECK_EQ(overflowedTag.eStatus, EReleaseEvaluationStatus::IgnoredRelease);

	const auto prerelease = EvaluateLatestReleaseJson(BuildReleaseJson("emule-bb-v1.1.1", "eMule-BB-1.1.1-x64.zip", false, true), local, "x64");
	CHECK_EQ(prerelease.eStatus, EReleaseEvaluationStatus::IgnoredRelease);

	const auto parseFailed = EvaluateLatestReleaseJson("{not-json", local, "x64");
	CHECK_EQ(parseFailed.eStatus, EReleaseEvaluationStatus::ParseFailed);
}

TEST_SUITE_END;
