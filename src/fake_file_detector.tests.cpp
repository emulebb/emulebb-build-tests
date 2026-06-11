#include "../third_party/doctest/doctest.h"

#include "FakeFileDetectorSeams.h"
#include "FileTypeClassifierSeams.h"
#include "RegexMatchSeams.h"

#include <cstring>

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

TEST_CASE("file-type classifier detects ebook archive and audio extensions")
{
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("book.epub")) == DOCUMENT_EPUB);
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("book.mobi")) == DOCUMENT_MOBI);
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("comic.cbr")) == ARCHIVE_RAR);
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("archive.gz")) == ARCHIVE_GZ);
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("track.flac")) == AUDIO_FLAC);
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("track.wav")) == AUDIO_WAV);
	CHECK(FileTypeClassifierSeams::GetFileTypeFromExtension(_T("track.aac")) == AUDIO_AAC);
}

TEST_CASE("file-type classifier detects ebook archive and audio headers")
{
	BYTE gzHeader[] = { 0x1F, 0x8B, 0x08 };
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(gzHeader, sizeof gzHeader, _T("archive.gz")) == ARCHIVE_GZ);

	BYTE flacHeader[] = { 0x66, 0x4C, 0x61, 0x43 };
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(flacHeader, sizeof flacHeader, _T("track.flac")) == AUDIO_FLAC);

	BYTE wavHeader[FileTypeClassifierSeams::kHeaderCheckSize] = { 0x52, 0x49, 0x46, 0x46 };
	wavHeader[8] = 0x57;
	wavHeader[9] = 0x41;
	wavHeader[10] = 0x56;
	wavHeader[11] = 0x45;
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(wavHeader, sizeof wavHeader, _T("track.wav")) == AUDIO_WAV);

	BYTE aacHeader[FileTypeClassifierSeams::kHeaderCheckSize] = { 0xFF, 0xF1 };
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(aacHeader, sizeof aacHeader, _T("track.aac")) == AUDIO_AAC);

	BYTE shortMobiHeader[FileTypeClassifierSeams::kHeaderCheckSize] = {};
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(shortMobiHeader, sizeof shortMobiHeader, _T("book.mobi")) == FILETYPE_UNKNOWN);

	BYTE mobiHeader[FileTypeClassifierSeams::kDeepHeaderCheckSize] = {};
	const BYTE mobiId[] = { 0x42, 0x4F, 0x4F, 0x4B, 0x4D, 0x4F, 0x42, 0x49 };
	memcpy(mobiHeader + 60, mobiId, sizeof mobiId);
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(mobiHeader, sizeof mobiHeader, _T("book.mobi")) == DOCUMENT_MOBI);

	BYTE epubHeader[FileTypeClassifierSeams::kDeepHeaderCheckSize] = { 0x50, 0x4B, 0x03, 0x04 };
	const BYTE epubName[] = { 0x6D, 0x69, 0x6D, 0x65, 0x74, 0x79, 0x70, 0x65 };
	const BYTE epubMime[] = { 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x65, 0x70, 0x75, 0x62, 0x2B, 0x7A, 0x69, 0x70 };
	epubHeader[26] = sizeof epubName;
	memcpy(epubHeader + 30, epubName, sizeof epubName);
	memcpy(epubHeader + 30 + sizeof epubName, epubMime, sizeof epubMime);
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(epubHeader, sizeof epubHeader, _T("book.epub")) == DOCUMENT_EPUB);

	BYTE mzHeader[] = { 0x4D, 0x5A };
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(mzHeader, sizeof mzHeader, _T("comic.cbr")) == FILETYPE_EXECUTABLE);
	CHECK(FileTypeClassifierSeams::DetectFileTypeFromHeader(mzHeader, sizeof mzHeader, _T("archive.rar")) == FILETYPE_UNKNOWN);

	BYTE isoHeader[FileTypeClassifierSeams::kIsoHeaderCheckSize] = { 0x01, 0x43, 0x44, 0x30, 0x30, 0x31 };
	CHECK(FileTypeClassifierSeams::DetectIsoTypeFromOffsetHeader(isoHeader, sizeof isoHeader) == IMAGE_ISO);
}

TEST_CASE("fake-file analyzer accepts real epub headers")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"book.epub" };
	evidence.extensionType = DOCUMENT_EPUB;
	evidence.headerType = DOCUMENT_EPUB;
	evidence.headerAvailable = true;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(report.severity == FakeFileDetectorSeams::Severity::None);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "header_extension_mismatch") == report.reasons.end());
}

TEST_CASE("fake-file analyzer flags generic zip renamed as epub")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"book.epub" };
	evidence.extensionType = DOCUMENT_EPUB;
	evidence.headerType = ARCHIVE_ZIP;
	evidence.headerAvailable = true;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 45);
	CHECK(report.severity == FakeFileDetectorSeams::Severity::Medium);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "header_extension_mismatch") != report.reasons.end());
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

TEST_CASE("fake-file analyzer ignores release metadata around matching title tokens")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"The Longest Movie DivX 1080p WEBRip.avi",
		L"ITA.The.Longest.Movie.XviD.DVDRip-GROUP.avi",
		L"[GROUP] The Longest Movie 2020 2160p BluRay x265 10bit DDP 5.1 AAC.avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.canonicalNames.size() == 1);
	CHECK(report.canonicalNames[0] == L"the longest movie");
	CHECK(report.nameDivergenceGroups.empty());
	CHECK(std::find(report.ignoredNameTokens.begin(), report.ignoredNameTokens.end(), L"divx") != report.ignoredNameTokens.end());
	CHECK(std::find(report.ignoredNameTokens.begin(), report.ignoredNameTokens.end(), L"1080p") != report.ignoredNameTokens.end());
	CHECK(std::find(report.ignoredNameTokens.begin(), report.ignoredNameTokens.end(), L"ita") != report.ignoredNameTokens.end());
	CHECK(std::find(report.ignoredNameTokens.begin(), report.ignoredNameTokens.end(), L"group") != report.ignoredNameTokens.end());
	CHECK(std::find(report.ignoredNameTokens.begin(), report.ignoredNameTokens.end(), L"2020") != report.ignoredNameTokens.end());
	CHECK(std::find(report.ignoredNameTokens.begin(), report.ignoredNameTokens.end(), L"5.1") != report.ignoredNameTokens.end());
}

TEST_CASE("fake-file analyzer treats extension-only title matches as soft evidence")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"The Longest Movie.avi",
		L"The.Longest.Movie.mkv",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.canonicalNames.size() == 1);
	CHECK(report.canonicalNames[0] == L"the longest movie");
	CHECK(report.observedExtensions.size() == 2);
	CHECK(std::find(report.observedExtensions.begin(), report.observedExtensions.end(), L"avi") != report.observedExtensions.end());
	CHECK(std::find(report.observedExtensions.begin(), report.observedExtensions.end(), L"mkv") != report.observedExtensions.end());
}

TEST_CASE("fake-file analyzer still flags meaningful title divergence")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"The Longest Movie DivX 1080p.avi",
		L"Sports Madness 2000 XviD 1080p.avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 15);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") != report.reasons.end());
	CHECK(report.nameDivergenceGroups.size() == 2);
	CHECK(std::find(report.nameDivergenceGroups.begin(), report.nameDivergenceGroups.end(), L"the longest movie") != report.nameDivergenceGroups.end());
	CHECK(std::find(report.nameDivergenceGroups.begin(), report.nameDivergenceGroups.end(), L"sports madness 2000") != report.nameDivergenceGroups.end());
}

TEST_CASE("fake-file analyzer merges names that differ only by a stray year token")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"[GROUP-ITA] Sample Title (Alpha Beta - 2023).avi",
		L"Sample.Title.Alpha.Beta.2023.HDTV.ITA.AC3.XviD-Relgroup.avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.nameDivergenceGroups.empty());
}

TEST_CASE("fake-file analyzer merges a terse title that is a subset of a descriptive one")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"[uploader] Sample Title 2016 Alpha Beta DVDRip XviD - by uploader note.avi",
		L"Sample Title of Alpha Beta with Gamma Delta and Epsilon Zeta - 2016.avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.nameDivergenceGroups.empty());
}

TEST_CASE("fake-file analyzer merges the same title tokens in a different order")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"Alpha Beta - Sample Title.avi",
		L"Sample Title - Alpha Beta(Divx).avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.nameDivergenceGroups.empty());
}

TEST_CASE("fake-file analyzer merges names carrying hash suffixes and episode markers")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"Sample Show Alpha 05 Creator (Extra Subtitle).mp4",
		L"Creator - Sample Show Alpha - 01x05 - Creator.mp4",
		L"Sample Show Alpha - Creator-9ff9f11c-abef-4dcf-bd56-6fef7fefa95a.mp4",
	};
	evidence.extensionType = VIDEO_MP4;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.nameDivergenceGroups.empty());
}

TEST_CASE("fake-file analyzer merges a shared title core that differs in cast or crew words")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"2009 - Sample Movie - 2009 - genreword with Actorone Actortwo Actorthree - divx ita.avi",
		L"Sample Movie 2009 by Directorname (Actorone Actortwo Actorthree) DivX Ita.avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.nameDivergenceGroups.empty());
}

TEST_CASE("fake-file analyzer merges the same core across multilingual connector words")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"Sample Title de Alpha Beta con Gamma.avi",   // Spanish connectors
		L"Sample Title von Alpha Beta mit Gamma.avi",  // German connectors
		L"Sample Title de Alpha Beta com Gamma.avi",   // Portuguese connectors
		L"Sample Title di Alpha Beta e Gamma.avi",     // Italian connectors
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.nameDivergenceGroups.empty());
}

TEST_CASE("fake-file analyzer ignores generic download fallback names")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"The Longest Movie.avi",
		L"download.avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.canonicalNames.size() == 1);
	CHECK(report.canonicalNames[0] == L"the longest movie");
	CHECK(report.nameDivergenceGroups.empty());
}

TEST_CASE("fake-file analyzer ignores metadata-only names without suppressing title evidence")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = {
		L"The Longest Movie.avi",
		L"1080p x264 WEB-DL.avi",
	};
	evidence.extensionType = VIDEO_AVI;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") == report.reasons.end());
	CHECK(report.canonicalNames.size() == 1);
	CHECK(report.canonicalNames[0] == L"the longest movie");
}

TEST_CASE("fake-file analyzer flags implausible video length metadata")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"Feature Film.avi" };
	evidence.extensionType = VIDEO_AVI;
	evidence.fileSizeBytes = 700ull * 1024ull * 1024ull;
	evidence.mediaLengthAvailable = true;
	evidence.mediaLengthSeconds = 30;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 10);
	CHECK(report.severity == FakeFileDetectorSeams::Severity::Low);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "implausible_media_length") != report.reasons.end());
}

TEST_CASE("fake-file analyzer flags implausible audio bitrate metadata")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"Album Track.mp3" };
	evidence.extensionType = AUDIO_MPEG;
	evidence.fileSizeBytes = 4ull * 1024ull * 1024ull;
	evidence.mediaBitrateAvailable = true;
	evidence.mediaBitrateKbps = 8;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 10);
	CHECK(report.severity == FakeFileDetectorSeams::Severity::Low);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "implausible_media_bitrate") != report.reasons.end());
}

TEST_CASE("fake-file analyzer accepts plausible media metadata")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"Feature Film.mp4" };
	evidence.extensionType = VIDEO_MP4;
	evidence.fileSizeBytes = 700ull * 1024ull * 1024ull;
	evidence.mediaLengthAvailable = true;
	evidence.mediaLengthSeconds = 5400;
	evidence.mediaBitrateAvailable = true;
	evidence.mediaBitrateKbps = 1500;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 0);
	CHECK(report.severity == FakeFileDetectorSeams::Severity::None);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "implausible_media_length") == report.reasons.end());
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "implausible_media_bitrate") == report.reasons.end());
}

TEST_CASE("fake-file analyzer flags filename that omits its own embedded media tags")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"random_upload_2024.mp3" };
	evidence.extensionType = AUDIO_MPEG;
	evidence.mediaArtist = L"Wolfgang Mozart";
	evidence.mediaTitle = L"Symphony No 5";

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "name_media_tag_mismatch") != report.reasons.end());
}

TEST_CASE("fake-file analyzer accepts filename that reflects an embedded media tag")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"Wolfgang Mozart - Symphony No 5.mp3" };
	evidence.extensionType = AUDIO_MPEG;
	evidence.mediaArtist = L"Wolfgang Mozart";
	evidence.mediaTitle = L"Symphony No 5";

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "name_media_tag_mismatch") == report.reasons.end());
}

TEST_CASE("fake-file analyzer ignores short embedded media tags as too noisy")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"random_upload_2024.mp3" };
	evidence.extensionType = AUDIO_MPEG;
	evidence.mediaTitle = L"Yo"; // shorter than the 4-char meaningful-tag threshold

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "name_media_tag_mismatch") == report.reasons.end());
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

TEST_CASE("fake-file analyzer composes cached header evidence with current signals")
{
	FakeFileDetectorSeams::RuleSet rules;
	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"release.mp4", L"release alternate.mp4" };
	evidence.extensionType = VIDEO_MP4;
	evidence.headerType = ARCHIVE_ZIP;
	evidence.headerAvailable = true;
	evidence.spamRating = 30;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules);
	CHECK(report.score == 95);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "multiple_names") != report.reasons.end());
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "header_extension_mismatch") != report.reasons.end());
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "archive_masquerade") != report.reasons.end());
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "spam_score") != report.reasons.end());
}

TEST_CASE("file-type header probe keeps iso pending until offset signature is available")
{
	CHECK(FileTypeClassifierSeams::GetHeaderRangeEnd(FileTypeClassifierSeams::kIsoHeaderOffset)
		== FileTypeClassifierSeams::kIsoHeaderOffset + FileTypeClassifierSeams::kHeaderCheckSize - 1);

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

TEST_CASE("fake-file analyzer accepts precompiled regex rules")
{
	FakeFileDetectorSeams::RuleSet rules;
	rules.regexes.push_back(L"\\.mp4\\.exe$");
	std::vector<std::wregex> compiledRules;
	compiledRules.push_back(std::wregex(rules.regexes[0], std::regex_constants::icase | std::regex_constants::ECMAScript));

	FakeFileDetectorSeams::Evidence evidence;
	evidence.names = { L"Release.MP4.EXE" };
	evidence.extensionType = FILETYPE_EXECUTABLE;

	const FakeFileDetectorSeams::Report report = FakeFileDetectorSeams::Analyze(evidence, rules, &compiledRules);
	CHECK(report.score == 25);
	CHECK(std::find(report.reasons.begin(), report.reasons.end(), "bad_signal_name") != report.reasons.end());
}

TEST_CASE("fake-file token matching uses separator boundaries")
{
	CHECK(FakeFileDetectorSeams::ContainsToken(L"movie password protected", L"password"));
	CHECK(FakeFileDetectorSeams::ContainsToken(L"movie-password-protected", L"password"));
	CHECK_FALSE(FakeFileDetectorSeams::ContainsToken(L"movie passworded", L"password"));
}

TEST_SUITE_END();
