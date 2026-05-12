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

TEST_CASE("Part-file preview seam recognizes only configured VLC players for thumbnail generation")
{
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("vlc"))));
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("vlc.exe"))));
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("C:/apps/VideoLAN/VLC.EXE"))));
	CHECK(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("\"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe\""))));

	CHECK_FALSE(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T(""))));
	CHECK_FALSE(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("mpv.exe"))));
	CHECK_FALSE(PartFilePreviewSeams::IsConfiguredVlcPreviewPlayer(CString(_T("vlc-helper.exe"))));
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
	CHECK(PartFilePreviewSeams::kVideoThumbnailScanIntervalMs == 90000ull);
	CHECK(PartFilePreviewSeams::kVideoThumbnailRetryIntervalMs == 90000ull);
	CHECK(PartFilePreviewSeams::kVideoThumbnailRefreshIntervalMs == PartFilePreviewSeams::kVideoThumbnailRetryIntervalMs);
	CHECK(PartFilePreviewSeams::kVideoThumbnailRefreshDeltaPermille == 50ull);
	CHECK(PartFilePreviewSeams::kVideoThumbnailRefreshMaxDeltaBytes == 128ull * oneMegabyte);
	CHECK(PartFilePreviewSeams::kVlcThumbnailTimeoutMs == 30000u);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailRefreshRequiredCompletedDelta(hundredMegabytes) == 5ull * oneMegabyte);
	CHECK(PartFilePreviewSeams::GetVideoThumbnailRefreshRequiredCompletedDelta(tenGigabytes) == 128ull * oneMegabyte);

	CHECK(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(5000ull, 0ull));
	CHECK_FALSE(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(5000ull, 1000ull));
	CHECK_FALSE(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(90999ull, 1000ull));
	CHECK(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(91000ull, 1000ull));
	CHECK(PartFilePreviewSeams::IsVideoThumbnailAttemptDue(1000ull, 91000ull));

	CHECK(PartFilePreviewSeams::ShouldForceVideoThumbnailAttempt(true, false));
	CHECK_FALSE(PartFilePreviewSeams::ShouldForceVideoThumbnailAttempt(false, false));
	CHECK_FALSE(PartFilePreviewSeams::ShouldForceVideoThumbnailAttempt(true, true));

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

TEST_CASE("Part-file preview seam builds quoted VLC thumbnail command lines")
{
	const CString command = PartFilePreviewSeams::BuildVlcThumbnailCommandLine(
		CString(_T("C:\\Program Files\\VideoLAN\\VLC\\vlc.exe")),
		CString(_T("C:\\Temp Files\\sample preview.mkv")),
		CString(_T("C:\\Temp Files\\")),
		CString(_T("emulebb_thumb_abc")),
		60u);

	CHECK(command.Find(_T("\"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe\"")) >= 0);
	CHECK(command.Find(_T("--intf dummy")) >= 0);
	CHECK(command.Find(_T("--no-interact")) >= 0);
	CHECK(command.Find(_T("--no-crashdump")) >= 0);
	CHECK(command.Find(_T("--vout=dummy")) >= 0);
	CHECK(command.Find(_T("--no-embedded-video")) >= 0);
	CHECK(command.Find(_T("--no-video-deco")) >= 0);
	CHECK(command.Find(_T("--no-qt-error-dialogs")) >= 0);
	CHECK(command.Find(_T("--video-filter=scene")) >= 0);
	CHECK(command.Find(_T("--start-time=60 --stop-time=61")) >= 0);
	CHECK(command.Find(_T("\"--scene-prefix=emulebb_thumb_abc\"")) >= 0);
	CHECK(command.Find(_T("\"--scene-path=C:\\Temp Files\\")) >= 0);
	CHECK(command.Find(_T("\"C:\\Temp Files\\sample preview.mkv\"")) >= 0);
	CHECK(command.Find(_T("vlc://quit")) >= 0);
}

TEST_SUITE_END;
