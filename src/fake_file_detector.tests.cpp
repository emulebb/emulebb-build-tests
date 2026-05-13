#include "../third_party/doctest/doctest.h"

#include "FakeFileDetectorSeams.h"
#include "FileTypeClassifierSeams.h"
#include "RegexMatchSeams.h"

TEST_SUITE_BEGIN("fake_file_detector");

TEST_CASE("file-type classifier detects common headers and extension mismatches")
{
	BYTE zipHeader[FileTypeClassifierSeams::kHeaderCheckSize] = { 0x50, 0x4B, 0x03, 0x04 };
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(zipHeader, sizeof zipHeader, _T("movie.mp4")) == ARCHIVE_ZIP);
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("movie.mp4")) == VIDEO_MP4);
	CHECK(FileTypeClassifierSeams::IsExtensionTypeOf(ARCHIVE_ZIP, _T("MP4")) == -1);

	BYTE mp4Header[FileTypeClassifierSeams::kHeaderCheckSize] = {};
	mp4Header[4] = 0x66;
	mp4Header[5] = 0x74;
	mp4Header[6] = 0x79;
	mp4Header[7] = 0x70;
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(mp4Header, sizeof mp4Header, _T("movie.mp4")) == VIDEO_MP4);
	CHECK(FileTypeClassifierSeams::IsExtensionTypeOf(VIDEO_MP4, _T("MP4")) == 1);
}

TEST_CASE("fake-file analyzer combines names bad signals and header mismatch")
{
	FakeFileDetectorSeams::RuleSet rules;
	rules.tokens.push_back(L"password");
	rules.regexes.push_back(L"\\.mp4\\.exe$");

	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"release.mp4", L"release password.mp4", L"release.mp4.exe" };
	evidence.claimedType = L"Video";
	evidence.extensionType = VIDEO_MP4;
	evidence.headerType = ARCHIVE_ZIP;
	evidence.headerAvailable = true;
	evidence.multipleAich = true;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 100);
	CHECK(report.severity == FakeFileDetectorSeams::Severity::Critical);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") != report.reasons.end());
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "bad_signal_name") != report.reasons.end());
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "header_extension_mismatch") != report.reasons.end());
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_aich") != report.reasons.end());
}

TEST_CASE("fake-file analyzer reports pending header without mismatch penalty")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"movie.mp4" };
	evidence.extensionType = VIDEO_MP4;
	evidence.headerPending = true;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(report.severity == FakeFileDetectorSeams::Severity::None);
	CHECK(report.pendingHeaderCheck);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "pending_header_check") != report.reasons.end());
}

TEST_CASE("fake-file analyzer score follows current bad-signal rules")
{
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"release password.mp4" };
	evidence.extensionType = VIDEO_MP4;

	FakeFileDetectorSeams::RuleSet rules;
	rules.tokens.push_back(L"password");
	CHECK(FakeFileDetectorSeams::Analyze(evidence, rules).score == 25);

	rules.tokens.clear();
	CHECK(FakeFileDetectorSeams::Analyze(evidence, rules).score == 0);
}

TEST_CASE("file-type header probe keeps iso pending until offset signature is available")
{
	const FileTypeClassifierSeams::HeaderProbeSummary pendingIso = FileTypeClassifierSeams::SummarizeHeaderProbe(
		FILETYPE_UNKNOWN,
		IMAGE_ISO,
		true,
		false);
	CHECK(pendingIso.status == FileTypeClassifierSeams::HeaderProbeStatus::Pending);
	CHECK(pendingIso.type == FILETYPE_UNKNOWN);

	const FileTypeClassifierSeams::HeaderProbeSummary checkedVideo = FileTypeClassifierSeams::SummarizeHeaderProbe(
		FILETYPE_UNKNOWN,
		VIDEO_MP4,
		true,
		false);
	CHECK(checkedVideo.status == FileTypeClassifierSeams::HeaderProbeStatus::CheckedUnknown);

	const FileTypeClassifierSeams::HeaderProbeSummary detectedZip = FileTypeClassifierSeams::SummarizeHeaderProbe(
		ARCHIVE_ZIP,
		VIDEO_MP4,
		true,
		false);
	CHECK(detectedZip.status == FileTypeClassifierSeams::HeaderProbeStatus::Detected);
	CHECK(detectedZip.type == ARCHIVE_ZIP);
}

TEST_CASE("regex helper preserves category full-match and fake-file search modes")
{
	const std::wstring pattern = L"release";
	CHECK(RegexMatchSeams::Match(std::wstring(L"release"), pattern, RegexMatchSeams::MatchMode::Full));
	CHECK_FALSE(RegexMatchSeams::Match(std::wstring(L"release.mp4"), pattern, RegexMatchSeams::MatchMode::Full));
	CHECK(RegexMatchSeams::Match(std::wstring(L"release.mp4"), pattern, RegexMatchSeams::MatchMode::Search));
	CHECK(RegexMatchSeams::Match(
		std::wstring(L"Release.MP4.EXE"),
		std::wstring(L"\\.mp4\\.exe$"),
		RegexMatchSeams::MatchMode::Search,
		std::regex_constants::icase | std::regex_constants::ECMAScript));
	CHECK_FALSE(RegexMatchSeams::IsValidPattern(std::wstring(L"(")));
}

TEST_CASE("fake-file token matching uses separator boundaries")
{
	CHECK(FakeFileDetectorSeams::ContainsToken(L"movie password protected", L"password"));
	CHECK(FakeFileDetectorSeams::ContainsToken(L"movie-password-protected", L"password"));
	CHECK_FALSE(FakeFileDetectorSeams::ContainsToken(L"movie passworded", L"password"));
}

TEST_SUITE_END();
