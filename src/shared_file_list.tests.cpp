#include "../third_party/doctest/doctest.h"
#include "../include/LongPathTestSupport.h"
#if defined(__has_include)
#if __has_include("SharedDirectoryOps.h")
#include "SharedDirectoryOps.h"
#define EMULE_TESTS_HAS_SHARED_DIRECTORY_OPS 1
#endif
#if __has_include("SharedFileIntakePolicy.h")
#include "SharedFileIntakePolicy.h"
#define EMULE_TESTS_HAS_SHARED_FILE_INTAKE_POLICY 1
#endif
#if __has_include("SharedFilesWndSeams.h")
#include "SharedFilesWndSeams.h"
#define EMULE_TESTS_HAS_SHARED_FILES_WND_SEAMS 1
#endif
#endif
#include "SharedFileListSeams.h"

TEST_SUITE_BEGIN("parity");

#ifdef EMULE_TESTS_HAS_SHARED_DIRECTORY_OPS
bool EqualPaths(const CString &rstrDir1, const CString &rstrDir2)
{
	return PathHelpers::ArePathsEquivalent(rstrDir1, rstrDir2);
}
#endif

namespace
{
#ifdef EMULE_TESTS_HAS_SHARED_DIRECTORY_OPS
int CountEquivalentPaths(const CStringList &rList, const CString &rstrPath)
{
	int nMatches = 0;
	for (POSITION pos = rList.GetHeadPosition(); pos != NULL;) {
		if (EqualPaths(rList.GetNext(pos), rstrPath))
			++nMatches;
	}
	return nMatches;
}

int CountPaths(const CStringList &rList)
{
	int nCount = 0;
	for (POSITION pos = rList.GetHeadPosition(); pos != NULL;)
		(void)rList.GetNext(pos), ++nCount;
	return nCount;
}
#endif
}

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

#ifdef EMULE_TESTS_HAS_SHARED_FILES_WND_SEAMS
TEST_CASE("Shared files splitter range scales with dialog width instead of capping at the legacy maximum")
{
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(50, 900), SharedFilesWndSeams::kMinTreeWidth);
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(999, 900), SharedFilesWndSeams::GetSplitterRangeMax(900));
	CHECK(SharedFilesWndSeams::GetSplitterRangeMax(900) > 350);
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(500, 900), 500);
}

TEST_CASE("Shared files splitter keeps a usable right pane in narrow windows")
{
	CHECK_EQ(SharedFilesWndSeams::GetSplitterRangeMax(180), SharedFilesWndSeams::kMinTreeWidth);
	CHECK_EQ(SharedFilesWndSeams::ClampSplitterPosition(999, 180), SharedFilesWndSeams::kMinTreeWidth);
}
#endif

#ifdef EMULE_TESTS_HAS_SHARED_DIRECTORY_OPS
TEST_CASE("Shared directory recursion dedupes non-recursive junction aliases by filesystem identity")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10001u));

	const std::wstring targetPath = fixture.MakeDirectoryChildPath(L"real-target");
	const std::wstring aliasPath = fixture.MakeDirectoryChildPath(L"alias-target");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(targetPath));
	if (!LongPathTestSupport::CreateDirectoryJunction(aliasPath, targetPath))
		return;

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(targetPath.c_str()), false, [](const CString &) { return true; }));
	CHECK_FALSE(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(aliasPath.c_str()), false, [](const CString &) { return true; }));
	CHECK_EQ(CountPaths(sharedDirectories), 1);
	CHECK(CountEquivalentPaths(sharedDirectories, CString(targetPath.c_str())) + CountEquivalentPaths(sharedDirectories, CString(aliasPath.c_str())) == 1);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(aliasPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(targetPath));
}

TEST_CASE("Shared directory recursion keeps only one child path when a junction aliases the same target")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10002u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring targetPath = fixture.MakeDirectoryChildPath(L"real-child");
	const std::wstring aliasPath = fixture.MakeDirectoryChildPath(L"alias-child");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(targetPath));
	if (!LongPathTestSupport::CreateDirectoryJunction(aliasPath, targetPath))
		return;

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(rootPath.c_str()), true, [](const CString &) { return true; }));
	CHECK_EQ(CountPaths(sharedDirectories), 2);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(rootPath.c_str())), 1);
	CHECK(CountEquivalentPaths(sharedDirectories, CString(targetPath.c_str())) + CountEquivalentPaths(sharedDirectories, CString(aliasPath.c_str())) == 1);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(aliasPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(targetPath));
}

TEST_CASE("Shared directory recursion stops junction loops by filesystem identity")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10003u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring childPath = fixture.MakeDirectoryChildPath(L"loop-child");
	const std::wstring loopPath = childPath + L"\\back-to-root";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(childPath));
	if (!LongPathTestSupport::CreateDirectoryJunction(loopPath, rootPath))
		return;

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(rootPath.c_str()), true, [](const CString &) { return true; }));
	CHECK_EQ(CountPaths(sharedDirectories), 2);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(rootPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(childPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(loopPath.c_str())), 0);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(loopPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(childPath));
}

#if defined(EMULE_TESTS_HAS_SHARED_DIRECTORY_OPS) && defined(EMULE_TESTS_HAS_SHARED_FILE_INTAKE_POLICY)
TEST_CASE("Shared directory recursion skips built-in and configured ignored directory names")
{
	SharedFileIntakePolicy::ScopedUserRuleOverride restoreRules;
	SharedFileIntakePolicy::ClearUserRules();

	SharedFileIntakePolicy::IgnoreRule rule = {};
	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("skip-me"), rule));
	std::vector<SharedFileIntakePolicy::IgnoreRule> userRules;
	userRules.push_back(rule);
	SharedFileIntakePolicy::ReplaceUserRules(userRules);

	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0xA10004u));

	const std::wstring rootPath = fixture.DirectoryPath();
	const std::wstring keepPath = fixture.MakeDirectoryChildPath(L"keep-me");
	const std::wstring vcsPath = fixture.MakeDirectoryChildPath(L".git");
	const std::wstring configuredPath = fixture.MakeDirectoryChildPath(L"skip-me");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(keepPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(vcsPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(configuredPath));

	CStringList sharedDirectories;
	CHECK(SharedDirectoryOps::AddSharedDirectory(sharedDirectories, CString(rootPath.c_str()), true, [](const CString &) { return true; }));
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(rootPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(keepPath.c_str())), 1);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(vcsPath.c_str())), 0);
	CHECK_EQ(CountEquivalentPaths(sharedDirectories, CString(configuredPath.c_str())), 0);
	CHECK(CountPaths(sharedDirectories) >= 2);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(configuredPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(vcsPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(keepPath));
}
#endif
#endif

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

TEST_CASE("Shared file list preserves exact trailing dot and trailing space names across canonical path spellings")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x717273u));

	const std::wstring directoryPath = fixture.DirectoryPath() + L"\\shared-dir. ";
	const std::wstring filePath = directoryPath + L"\\shared-file ";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(directoryPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(filePath, LongPathTestSupport::BuildDeterministicPayload(211u, 0x818283u)));

	const CString strDirectory(PathHelpers::EnsureTrailingSeparator(CString(directoryPath.c_str())));
	const CString strFilePath(CString(filePath.c_str()));
	const CString strPrefixedDirectory(PathHelpers::EnsureTrailingSeparator(CString(LongPathTestSupport::PreparePathForLongPath(directoryPath).c_str())));
	const CString strPrefixedFile(CString(LongPathTestSupport::PreparePathForLongPath(filePath).c_str()));

	CHECK(SharedFileListSeams::ContainsSharedChildPath(strDirectory, strFilePath));
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strPrefixedDirectory, strFilePath));
	CHECK(SharedFileListSeams::ContainsSharedChildPath(strDirectory, strPrefixedFile));
	CHECK(SharedFileListSeams::MatchesExplicitSharedFilePath(strFilePath, strPrefixedFile));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(filePath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(directoryPath));
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
