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

TEST_CASE("Part-file preview seam builds quoted VLC thumbnail command lines")
{
	const CString command = PartFilePreviewSeams::BuildVlcThumbnailCommandLine(
		CString(_T("C:\\Program Files\\VideoLAN\\VLC\\vlc.exe")),
		CString(_T("C:\\Temp Files\\sample preview.mkv")),
		CString(_T("C:\\Temp Files\\")),
		CString(_T("emulebb_thumb_abc")));

	CHECK(command.Find(_T("\"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe\"")) >= 0);
	CHECK(command.Find(_T("--intf dummy")) >= 0);
	CHECK(command.Find(_T("--video-filter=scene")) >= 0);
	CHECK(command.Find(_T("\"--scene-prefix=emulebb_thumb_abc\"")) >= 0);
	CHECK(command.Find(_T("\"--scene-path=C:\\Temp Files\\")) >= 0);
	CHECK(command.Find(_T("\"C:\\Temp Files\\sample preview.mkv\"")) >= 0);
	CHECK(command.Find(_T("vlc://quit")) >= 0);
}

TEST_SUITE_END;
