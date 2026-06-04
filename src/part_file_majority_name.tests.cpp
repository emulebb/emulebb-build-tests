#include "doctest.h"

#include "PartFileMajorityNameSeams.h"

#include <vector>

using PartFileMajorityNameSeams::HasRequiredAgreement;
using PartFileMajorityNameSeams::SelectMajorityName;
using PartFileMajorityNameSeams::TryPrepareMajoritySourceFilename;

TEST_SUITE_BEGIN("part_file_majority_name");

TEST_CASE("empty source names do not select a majority filename")
{
	const auto selection = SelectMajorityName(std::vector<CString>(), 0, 51);

	CHECK_FALSE(selection.HasCandidate);
	CHECK(selection.CandidateVotes == 0);
	CHECK(selection.TotalVotes == 0);
	CHECK(selection.Name.IsEmpty());
}

TEST_CASE("single source name is enough when minimum votes is zero")
{
	const auto selection = SelectMajorityName(std::vector<CString>{_T("File.iso")}, 0, 51);

	CHECK(selection.HasCandidate);
	CHECK(selection.Name == _T("File.iso"));
	CHECK(selection.CandidateVotes == 1);
	CHECK(selection.TotalVotes == 1);
}

TEST_CASE("minimum votes can require more than one agreeing source")
{
	const auto selection = SelectMajorityName(std::vector<CString>{_T("File.iso")}, 2, 51);

	CHECK_FALSE(selection.HasCandidate);
	CHECK(selection.CandidateVotes == 1);
	CHECK(selection.TotalVotes == 1);
}

TEST_CASE("ties do not select a majority filename")
{
	const auto selection = SelectMajorityName(std::vector<CString>{_T("A.iso"), _T("B.iso")}, 0, 50);

	CHECK_FALSE(selection.HasCandidate);
	CHECK(selection.CandidateVotes == 1);
	CHECK(selection.TotalVotes == 2);
}

TEST_CASE("threshold controls required agreement percent")
{
	const auto rejected = SelectMajorityName(std::vector<CString>{_T("A.iso"), _T("B.iso"), _T("B.iso"), _T("C.iso")}, 0, 51);
	const auto accepted = SelectMajorityName(std::vector<CString>{_T("A.iso"), _T("B.iso"), _T("B.iso"), _T("C.iso")}, 0, 50);

	CHECK_FALSE(rejected.HasCandidate);
	CHECK(accepted.HasCandidate);
	CHECK(accepted.Name == _T("B.iso"));
	CHECK(accepted.CandidateVotes == 2);
	CHECK(accepted.TotalVotes == 4);
}

TEST_CASE("blank names are ignored and matching is case-insensitive")
{
	const auto selection = SelectMajorityName(std::vector<CString>{_T(" File.iso "), _T(""), _T("file.ISO"), _T("Other.iso")}, 0, 51);

	CHECK(selection.HasCandidate);
	CHECK(selection.Name == _T("File.iso"));
	CHECK(selection.CandidateVotes == 2);
	CHECK(selection.TotalVotes == 3);
}

TEST_CASE("codec quality and source tokens vote as one majority filename group")
{
	const auto selection = SelectMajorityName(std::vector<CString>{
		_T("Operator Movie DivX 1080p WEBRip.avi"),
		_T("Operator.Movie.XviD.DVDRip.avi"),
		_T("Other Movie XviD.avi"),
	}, 0, 51);

	CHECK(selection.HasCandidate);
	CHECK(selection.CandidateVotes == 2);
	CHECK(selection.TotalVotes == 3);
	CHECK(selection.CanonicalName == _T("operator movie | ext:avi"));
	CHECK_FALSE(selection.Name.IsEmpty());
	CHECK(selection.Name.Find(_T("Operator")) >= 0);
}

TEST_CASE("source names without usable title tokens are ignored")
{
	const auto selection = SelectMajorityName(std::vector<CString>{_T("1080p.x264.avi"), _T("download"), _T("download.iso"), _T(".avi")}, 0, 51);

	CHECK_FALSE(selection.HasCandidate);
	CHECK(selection.CandidateVotes == 0);
	CHECK(selection.TotalVotes == 0);
}

TEST_CASE("source filename preparation repairs mojibake before majority voting")
{
	CString prepared;

	CHECK(TryPrepareMajoritySourceFilename(CString(L"sample-a\u00CC\u0080,.pdf"), prepared));
	CHECK(prepared == CString(L"sample-\u00E0.pdf"));

	const auto selection = SelectMajorityName(std::vector<CString>{
		prepared,
		CString(L"sample-\u00E0.pdf"),
		_T("other.pdf"),
	}, 0, 51);

	CHECK(selection.HasCandidate);
	CHECK(selection.Name == CString(L"sample-\u00E0.pdf"));
	CHECK(selection.CandidateVotes == 2);
	CHECK(selection.TotalVotes == 3);
}

TEST_CASE("required percent is normalized before agreement checks")
{
	CHECK(HasRequiredAgreement(1, 1, 0));
	CHECK_FALSE(HasRequiredAgreement(99, 100, 101));

	const auto selection = SelectMajorityName(std::vector<CString>{_T("File.iso")}, 0, 101);

	CHECK(selection.HasCandidate);
	CHECK(selection.RequiredPercent == 100);
}

TEST_SUITE_END();
