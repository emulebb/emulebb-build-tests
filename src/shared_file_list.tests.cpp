#include "../third_party/doctest/doctest.h"
#include "../include/LongPathTestSupport.h"
#include "SharedFileListSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Shared file list accepts files from shared directories")
{
	CHECK(SharedFileListSeams::CanAddSharedFile(false, true, false));
}

TEST_CASE("Shared file list accepts explicitly single-shared files outside shared directories")
{
	CHECK(SharedFileListSeams::CanAddSharedFile(false, false, true));
}

TEST_CASE("Shared file list accepts part files outside shared directories")
{
	CHECK(SharedFileListSeams::CanAddSharedFile(true, false, false));
}

#ifdef EMULE_TESTS_HAS_SHARED_FILE_LIST_PATH_SEAMS
TEST_CASE("Shared file list matches explicit shared files across prefixed and DOS 8.3 spellings")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 301u, 0x515151u));

	const CString strLongPath(fixture.FilePath().c_str());
	const CString strPrefixedPath(LongPathTestSupport::PreparePathForLongPath(fixture.FilePath()).c_str());
	CHECK(SharedFileListSeams::MatchesExplicitSharedFilePath(strLongPath, strPrefixedPath));

	std::wstring shortAlias;
	if (!LongPathTestSupport::TryGetShortPathAlias(fixture.FilePath(), shortAlias))
		return;

	CHECK(SharedFileListSeams::MatchesExplicitSharedFilePath(strLongPath, CString(shortAlias.c_str())));
}

TEST_CASE("Shared file list contains child files across canonicalized directory spellings")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 302u, 0x616161u));

	const CString strDirectory(PathHelpers::EnsureTrailingSeparator(CString(fixture.DirectoryPath().c_str())));
	const CString strFilePath(fixture.FilePath().c_str());
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strDirectory, strFilePath));

	std::wstring shortAlias;
	if (!LongPathTestSupport::TryGetShortPathAlias(fixture.DirectoryPath(), shortAlias))
		return;

	const CString strShortDirectory(PathHelpers::EnsureTrailingSeparator(CString(shortAlias.c_str())));
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strShortDirectory, strFilePath));
}
#endif

TEST_CASE("Shared file list rejects complete files that are neither directory-shared nor explicitly shared")
{
	CHECK_FALSE(SharedFileListSeams::CanAddSharedFile(false, false, false));
}

TEST_CASE("Shared file auto-reload schedules only when the stable snapshot allows it")
{
	const SharedFileListSeams::AutoReloadScheduleState state = {
		true,
		false,
		false,
		true,
		false,
		true
	};

	CHECK(SharedFileListSeams::ShouldScheduleAutoReload(state));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ false, false, false, true, false, true }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, true, false, true, false, true }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, true, true, false, true }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, false, false, true, true }));
}

TEST_CASE("Shared file auto-reload accepts fallback polling as a valid dirty-work trigger")
{
	CHECK(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, false, true, true, false }));
	CHECK_FALSE(SharedFileListSeams::ShouldScheduleAutoReload({ true, false, false, true, false, false }));
}

TEST_CASE("Shared file import yield only applies to active full-part imports")
{
	CHECK(SharedFileListSeams::ShouldYieldAfterImportProgress(true, true, true));
	CHECK_FALSE(SharedFileListSeams::ShouldYieldAfterImportProgress(false, true, true));
	CHECK_FALSE(SharedFileListSeams::ShouldYieldAfterImportProgress(true, false, true));
	CHECK_FALSE(SharedFileListSeams::ShouldYieldAfterImportProgress(true, true, false));
	CHECK(SharedFileListSeams::kImportPartProgressYieldMs == 100);
}
