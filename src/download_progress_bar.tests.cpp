#include "../third_party/doctest/doctest.h"

#include "DownloadProgressBarSeams.h"

TEST_SUITE_BEGIN("download_progress_bar");

TEST_CASE("Download progress-bar drawing requires a positive target extent")
{
	CHECK(DownloadProgressBarSeams::HasDrawableExtent(1, 1));
	CHECK(DownloadProgressBarSeams::HasDrawableExtent(120, 8));

	CHECK_FALSE(DownloadProgressBarSeams::HasDrawableExtent(0, 8));
	CHECK_FALSE(DownloadProgressBarSeams::HasDrawableExtent(120, 0));
	CHECK_FALSE(DownloadProgressBarSeams::HasDrawableExtent(-1, 8));
	CHECK_FALSE(DownloadProgressBarSeams::HasDrawableExtent(120, -1));
}

TEST_CASE("Download progress-bar drawing isolates DC state only for flat bars")
{
	CHECK(DownloadProgressBarSeams::ShouldIsolateFlatBarDcState(true));
	CHECK_FALSE(DownloadProgressBarSeams::ShouldIsolateFlatBarDcState(false));
}

TEST_CASE("Download progress-bar status bitmap cache follows normalized desktop refresh values")
{
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(500u) == 500u);
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(1000u) == 1000u);
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(2000u) == 2000u);
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(5000u) == 5000u);
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(10000u) == 10000u);
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(0u) == 2000u);
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(750u) == 2000u);
	CHECK(DownloadProgressBarSeams::GetStatusBitmapCacheDelayMs(60000u) == 2000u);
}

TEST_SUITE_END();
