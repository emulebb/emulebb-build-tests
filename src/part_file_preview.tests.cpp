#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "PartFilePreviewSeams.h"

#include <vector>

TEST_SUITE_BEGIN("parity");

TEST_CASE("Part-file preview seam extracts VLC from a long configured player path without truncation")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x565343u));

	const std::wstring playerPath = fixture.MakeDirectoryChildPath(L"vlc.exe");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(3073u, 0x564C43u);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(playerPath, payload));

	CString strLongPath(playerPath.c_str());
	std::vector<BYTE> roundTrip;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(playerPath, roundTrip));

	CHECK(strLongPath.GetLength() > MAX_PATH);
	CHECK(PartFilePreviewSeams::ExtractConfiguredVideoPlayerBaseName(strLongPath) == CString(_T("vlc")));
	CHECK(roundTrip == payload);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(playerPath));
}

TEST_CASE("Part-file preview seam handles slash variants and extensionless commands")
{
	CHECK(PartFilePreviewSeams::ExtractConfiguredVideoPlayerBaseName(CString(_T("C:/apps/VideoLAN/VLC.EXE"))) == CString(_T("VLC")));
	CHECK(PartFilePreviewSeams::ExtractConfiguredVideoPlayerBaseName(CString(_T("vlc"))) == CString(_T("vlc")));
	CHECK(PartFilePreviewSeams::ExtractConfiguredVideoPlayerBaseName(CString(_T("C:\\tools\\player.with.dots\\mpv.com"))) == CString(_T("mpv")));
	CHECK(PartFilePreviewSeams::ExtractConfiguredVideoPlayerBaseName(CString(_T("\"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe\""))) == CString(_T("vlc")));
}

TEST_CASE("Part-file preview seam recognizes configured VLC preview players")
{
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("vlc"))));
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("vlc.exe"))));
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("C:/apps/VideoLAN/VLC.EXE"))));
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("\"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe\""))));

	CHECK_FALSE(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T(""))));
	CHECK_FALSE(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("mpv.exe"))));
	CHECK_FALSE(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("vlc-helper.exe"))));
}

TEST_CASE("Part-file preview seam validates external FFmpeg thumbnail helpers")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x46464Du));

	const std::wstring ffmpegPath = fixture.MakeDirectoryChildPath(L"ffmpeg.exe");
	const std::wstring missingPath = fixture.MakeDirectoryChildPath(L"missing-ffmpeg.exe");
	const std::wstring scriptPath = fixture.MakeDirectoryChildPath(L"ffmpeg.cmd");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(1024u, 0x46464Du);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(ffmpegPath, payload));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(scriptPath, payload));

	CHECK(PartFilePreviewSeams::IsValidConfiguredFfmpegPath(CString(ffmpegPath.c_str())));
	CHECK_FALSE(PartFilePreviewSeams::IsValidConfiguredFfmpegPath(CString(missingPath.c_str())));
	CHECK_FALSE(PartFilePreviewSeams::IsValidConfiguredFfmpegPath(CString(scriptPath.c_str())));
	CHECK_FALSE(PartFilePreviewSeams::IsValidConfiguredFfmpegPath(CString()));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(ffmpegPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(scriptPath));
}

TEST_CASE("Part-file preview seam unlocks partial videos after a capped percentage threshold")
{
	const std::uint64_t oneMegabyte = 1024ull * 1024ull;
	const std::uint64_t twoGigabytes = 2ull * 1024ull * 1024ull * 1024ull;
	const std::uint64_t hundredGigabytes = 100ull * 1024ull * 1024ull * 1024ull;

	CHECK(PartFilePreviewSeams::GetPartialVideoPreviewRequiredCompletedBytes(100ull * 1024ull * 1024ull) == oneMegabyte);
	CHECK(PartFilePreviewSeams::GetPartialVideoPreviewRequiredCompletedBytes(twoGigabytes) == 10737419ull);
	CHECK(PartFilePreviewSeams::GetPartialVideoPreviewRequiredCompletedBytes(hundredGigabytes) == 64ull * oneMegabyte);

	CHECK_FALSE(PartFilePreviewSeams::HasEnoughCompletedDataForPartialVideoPreview(0, 64ull * oneMegabyte));
	CHECK_FALSE(PartFilePreviewSeams::HasEnoughCompletedDataForPartialVideoPreview(twoGigabytes, 10737418ull));
	CHECK(PartFilePreviewSeams::HasEnoughCompletedDataForPartialVideoPreview(twoGigabytes, 10737419ull));
}

TEST_CASE("Part-file preview seam throttles thumbnail retries and refreshes on progress")
{
	const std::uint64_t oneMegabyte = 1024ull * 1024ull;
	const std::uint64_t hundredMegabytes = 100ull * oneMegabyte;
	const std::uint64_t tenGigabytes = 10ull * 1024ull * oneMegabyte;

	CHECK(PartFilePreviewSeams::kVideoThumbnailDisplayMaxWidth == 480);
	CHECK(PartFilePreviewSeams::kVideoThumbnailDefaultIntervalSeconds == 0u);
	CHECK(PartFilePreviewSeams::kVideoThumbnailMinIntervalSeconds == 30u);
	CHECK(PartFilePreviewSeams::kVideoThumbnailRecommendedIntervalSeconds == 90u);
	CHECK(PartFilePreviewSeams::kVideoThumbnailMaxIntervalSeconds == 900u);
	CHECK(PartFilePreviewSeams::NormalizeVideoThumbnailIntervalSeconds(0u) == 0u);
	CHECK(PartFilePreviewSeams::NormalizeVideoThumbnailIntervalSeconds(1u) == 30u);
	CHECK(PartFilePreviewSeams::NormalizeVideoThumbnailIntervalSeconds(29u) == 30u);
	CHECK(PartFilePreviewSeams::NormalizeVideoThumbnailIntervalSeconds(30u) == 30u);
	CHECK(PartFilePreviewSeams::NormalizeVideoThumbnailIntervalSeconds(90u) == 90u);
	CHECK(PartFilePreviewSeams::NormalizeVideoThumbnailIntervalSeconds(901u) == 900u);
	CHECK_FALSE(PartFilePreviewSeams::IsVideoThumbnailIntervalEnabled(0u));
	CHECK(PartFilePreviewSeams::IsVideoThumbnailIntervalEnabled(1u));
	CHECK(PartFilePreviewSeams::IsVideoThumbnailIntervalEnabled(90u));
	CHECK(PartFilePreviewSeams::kVideoThumbnailRefreshDeltaPermille == 50ull);
	CHECK(PartFilePreviewSeams::kVideoThumbnailRefreshMaxDeltaBytes == 128ull * oneMegabyte);
	CHECK(PartFilePreviewSeams::kFfmpegThumbnailTimeoutMs == 30000u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailRefreshRequiredCompletedDelta(hundredMegabytes) == 5ull * oneMegabyte);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailRefreshRequiredCompletedDelta(tenGigabytes) == 128ull * oneMegabyte);

	CHECK(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(5000ull, 0ull, 90000ull));
	CHECK_FALSE(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(5000ull, 1000ull, 90000ull));
	CHECK_FALSE(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(90999ull, 1000ull, 90000ull));
	CHECK(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(91000ull, 1000ull, 90000ull));
	CHECK(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(1000ull, 91000ull, 90000ull));

	CHECK(PartFilePreviewSeams::ShouldForceVideoThumbnailAttempt(true, false));
	CHECK_FALSE(PartFilePreviewSeams::ShouldForceVideoThumbnailAttempt(false, false));
	CHECK_FALSE(PartFilePreviewSeams::ShouldForceVideoThumbnailAttempt(true, true));
	CHECK(PartFilePreviewSeams::kVideoThumbnailWorkerThreadPriority == THREAD_PRIORITY_LOWEST);
	CHECK(PartFilePreviewSeams::ShouldStartVideoThumbnailWorker(false, true, false));
	CHECK_FALSE(PartFilePreviewSeams::ShouldStartVideoThumbnailWorker(true, true, false));
	CHECK_FALSE(PartFilePreviewSeams::ShouldStartVideoThumbnailWorker(false, false, false));
	CHECK_FALSE(PartFilePreviewSeams::ShouldStartVideoThumbnailWorker(false, true, true));

	CHECK_FALSE(PartFilePreviewSeams::ShouldRefreshVideoThumbnail(40ull * oneMegabyte, 40ull * oneMegabyte, hundredMegabytes));
	CHECK_FALSE(PartFilePreviewSeams::ShouldRefreshVideoThumbnail(45ull * oneMegabyte, 40ull * oneMegabyte, hundredMegabytes));
	CHECK_FALSE(PartFilePreviewSeams::ShouldRefreshVideoThumbnail(40ull * oneMegabyte, 44ull * oneMegabyte, hundredMegabytes));
	CHECK(PartFilePreviewSeams::ShouldRefreshVideoThumbnail(40ull * oneMegabyte, 45ull * oneMegabyte, hundredMegabytes));
	CHECK(PartFilePreviewSeams::ShouldRefreshVideoThumbnail(99ull * oneMegabyte, hundredMegabytes, hundredMegabytes));
}

TEST_CASE("Part-file preview seam moves thumbnail capture deeper as progress increases")
{
	const std::uint64_t fileSize = 1000ull;

	CHECK_FALSE(PartFilePreviewSeams::HasReachedCompletedPermille(fileSize, 49ull, 50ull));
	CHECK(PartFilePreviewSeams::HasReachedCompletedPermille(fileSize, 50ull, 50ull));
	CHECK(PartFilePreviewSeams::GetVideoThumbnailCaptureStartSecond(0ull, 1000ull) == 15u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailCaptureStartSecond(fileSize, 49ull) == 15u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailCaptureStartSecond(fileSize, 50ull) == 30u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailCaptureStartSecond(fileSize, 100ull) == 60u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailCaptureStartSecond(fileSize, 250ull) == 90u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailCaptureStartSecond(fileSize, 500ull) == 120u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailCaptureStartSecond(fileSize, 950ull) == 180u);
}

TEST_CASE("Part-file preview seam builds quoted FFmpeg thumbnail command lines")
{
	const CString command = PartFilePreviewSeams::BuildFfmpegThumbnailCommandLine(
		CString(_T("C:\\Program Files\\FFmpeg\\bin\\ffmpeg.exe")),
		CString(_T("C:\\Temp Files\\sample preview.mkv")),
		CString(_T("C:\\Temp Files\\thumb_sample.png")),
		60u);

	CHECK(command.Find(_T("\"C:\\Program Files\\FFmpeg\\bin\\ffmpeg.exe\"")) >= 0);
	CHECK(command.Find(_T("-hide_banner")) >= 0);
	CHECK(command.Find(_T("-loglevel error")) >= 0);
	CHECK(command.Find(_T("-y")) >= 0);
	CHECK(command.Find(_T("-ss 60")) >= 0);
	CHECK(command.Find(_T("-fflags +genpts+discardcorrupt")) >= 0);
	CHECK(command.Find(_T("-err_detect ignore_err")) >= 0);
	CHECK(command.Find(_T("-analyzeduration 5M -probesize 5M")) >= 0);
	CHECK(command.Find(_T("\"C:\\Temp Files\\sample preview.mkv\"")) >= 0);
	CHECK(command.Find(_T("-an -frames:v 1")) >= 0);
	CHECK(command.Find(_T("\"scale=480:-2:force_original_aspect_ratio=decrease\"")) >= 0);
	CHECK(command.Find(_T("\"C:\\Temp Files\\thumb_sample.png\"")) >= 0);
}

TEST_SUITE_END;
