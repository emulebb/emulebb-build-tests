#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "UploadQueueSeams.h"

#if EMULEBB_TESTS_HAS_UPLOAD_SCORE_SEAMS
#include "UploadScoreSeams.h"
#endif

#if EMULEBB_TESTS_HAS_PART_FILE_PERSISTENCE_SEAMS
#include "PartFilePersistenceSeams.h"
#endif

namespace
{
#if EMULEBB_TESTS_HAS_PART_FILE_PERSISTENCE_SEAMS
	void WriteTextFileLongPath(const std::wstring &path, const char *pszText)
	{
		const BYTE *pBegin = reinterpret_cast<const BYTE *>(pszText);
		const BYTE *pEnd = pBegin + std::strlen(pszText);
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(path, std::vector<BYTE>(pBegin, pEnd)));
	}

	std::string ReadTextFileLongPath(const std::wstring &path)
	{
		std::vector<BYTE> bytes;
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(path, bytes));
		return std::string(bytes.begin(), bytes.end());
	}
#endif
}

TEST_SUITE_BEGIN("community-core-divergence");

TEST_CASE("Main-only upload score seam restores FEAT-023 low-ratio ordering")
{
	CHECK(EMULEBB_TESTS_HAS_UPLOAD_SCORE_SEAMS != 0);
#if EMULEBB_TESTS_HAS_UPLOAD_SCORE_SEAMS
	UploadScoreSeams::UploadScoreInputs inputs = {};
	inputs.uBaseValueMs = 100000u;
	inputs.fCreditRatio = 1.0f;
	inputs.iFilePrioNumber = 7;
	inputs.bUseCreditSystem = false;
	inputs.bApplyPriority = false;
	inputs.bApplyLowRatioBonus = true;
	inputs.uLowRatioBonus = 50u;
	inputs.bApplyLowIdDivisor = true;
	inputs.uLowIdDivisor = 2u;
	inputs.bApplyOldClientPenalty = true;

	const UploadScoreSeams::UploadScoreBreakdown breakdown = UploadScoreSeams::BuildUploadScoreBreakdown(inputs);
	CHECK_EQ(breakdown.uBaseScore, 50u);
	CHECK_EQ(breakdown.uEffectiveScore, 37u);
	CHECK(UploadScoreSeams::FormatUploadScoreCompact(
		breakdown,
		_T("Low ratio"),
		_T("LowID"),
		_T("Cooldown"),
		_T("Friend"),
		_T("-")) == CString(_T("37 (Low ratio +50, LowID /2)")));
#endif
}

TEST_CASE("Main-only upload queue score helpers expose FEAT-023 consumer semantics")
{
	CHECK(EMULEBB_TESTS_HAS_UPLOAD_SCORE_SEAMS != 0);
#if EMULEBB_TESTS_HAS_UPLOAD_SCORE_SEAMS
	CHECK(PreferHigherUploadQueueScore(11u, 10u));
	CHECK_FALSE(PreferHigherUploadQueueScore(10u, 10u));

	std::uint32_t uMaxScore = 3u;
	UpdateUploadQueueMaxScore(uMaxScore, 9u);
	CHECK_EQ(uMaxScore, 9u);
	CHECK_EQ(AddHigherUploadQueueScoreToRank(4u, 12u, 11u), 5u);
	CHECK(RejectSoftQueueCandidateByCombinedScore(false, true, false, 40.0f, 50.0f));
#endif
}

TEST_CASE("Main-only part-file persistence seam replaces overlong metadata temp files")
{
	CHECK(EMULEBB_TESTS_HAS_PART_FILE_PERSISTENCE_SEAMS != 0);
#if EMULEBB_TESTS_HAS_PART_FILE_PERSISTENCE_SEAMS
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x50445247u));

	const std::wstring rawDestinationPath = fixture.MakeDirectoryChildPath(L"003 odd-[queue].part.met");
	const std::wstring rawSourcePath = fixture.MakeDirectoryChildPath(L"003 odd-[queue].part.met.tmp");
	const std::wstring preparedDestinationPath = LongPathTestSupport::PreparePathForLongPath(rawDestinationPath);
	const std::wstring preparedSourcePath = LongPathTestSupport::PreparePathForLongPath(rawSourcePath);

	WriteTextFileLongPath(rawDestinationPath, "before");
	WriteTextFileLongPath(rawSourcePath, "after");

	DWORD dwLastError = ERROR_GEN_FAILURE;
	CHECK(PartFilePersistenceSeams::TryReplaceFileAtomically(preparedSourcePath.c_str(), preparedDestinationPath.c_str(), &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_SUCCESS));
	CHECK_EQ(ReadTextFileLongPath(rawDestinationPath), std::string("after"));
	CHECK_FALSE(PartFilePersistenceSeams::PathExists(preparedSourcePath.c_str()));
#endif
}

TEST_SUITE_END;
