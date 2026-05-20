#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "PartFilePersistenceSeams.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace
{
	class ScopedTempDir
	{
	public:
		ScopedTempDir()
		{
			WCHAR szTempPath[MAX_PATH] = { 0 };
			REQUIRE(::GetTempPathW(_countof(szTempPath), szTempPath) != 0);

			WCHAR szTempFile[MAX_PATH] = { 0 };
			REQUIRE(::GetTempFileNameW(szTempPath, L"pmt", 0, szTempFile) != 0);

			m_root = std::filesystem::path(szTempFile);
			std::error_code ec;
			std::filesystem::remove(m_root, ec);
			std::filesystem::create_directories(m_root, ec);
			REQUIRE_FALSE(ec);
		}

		~ScopedTempDir()
		{
			std::error_code ec;
			std::filesystem::remove_all(m_root, ec);
		}

		const std::filesystem::path &Root() const
		{
			return m_root;
		}

	private:
		std::filesystem::path m_root;
	};

	void WriteTextFile(const std::filesystem::path &rPath, const char *pszText)
	{
		std::ofstream file(rPath, std::ios::binary | std::ios::trunc);
		REQUIRE(file.good());
		file << pszText;
		REQUIRE(file.good());
	}

	std::string ReadTextFile(const std::filesystem::path &rPath)
	{
		std::ifstream file(rPath, std::ios::binary);
		REQUIRE(file.good());
		return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	}

	BOOL WINAPI AlwaysFailMoveFileEx(LPCTSTR, LPCTSTR, DWORD)
	{
		::SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}

	BOOL WINAPI AlwaysFailCopyFile(LPCTSTR, LPCTSTR, BOOL)
	{
		::SetLastError(ERROR_DISK_FULL);
		return FALSE;
	}

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
}

TEST_SUITE_BEGIN("parity");

#if defined(EMULE_TEST_HAVE_PART_FILE_PERSISTENCE_SEAMS)
TEST_CASE("Part-file persistence seams expose the fixed disk-space minimums")
{
	CHECK_EQ(PartFilePersistenceSeams::NormalizeDownloadFreeSpaceFloor(0u), PartFilePersistenceSeams::kMinDownloadFreeBytes);
	CHECK_EQ(PartFilePersistenceSeams::NormalizeDownloadFreeSpaceFloor(PartFilePersistenceSeams::kMinDownloadFreeBytes - 1u), PartFilePersistenceSeams::kMinDownloadFreeBytes);
	CHECK_EQ(PartFilePersistenceSeams::NormalizeDownloadFreeSpaceFloor(PartFilePersistenceSeams::kMinDownloadFreeBytes + 1u), PartFilePersistenceSeams::kMinDownloadFreeBytes + 1u);
	CHECK_EQ(PartFilePersistenceSeams::NormalizeDownloadFreeSpaceFloor(PartFilePersistenceSeams::kMaxDownloadFreeBytes + PartFilePersistenceSeams::kDiskSpaceFloorUnitBytes), PartFilePersistenceSeams::kMaxDownloadFreeBytes);
	CHECK_EQ(PartFilePersistenceSeams::NormalizeDownloadFreeSpaceFloorGiB(0u), PartFilePersistenceSeams::kMinDiskSpaceFloorGiB);
	CHECK_EQ(PartFilePersistenceSeams::NormalizeDownloadFreeSpaceFloorGiB(PartFilePersistenceSeams::kMaxDiskSpaceFloorGiB + 1u), PartFilePersistenceSeams::kMaxDiskSpaceFloorGiB);
	CHECK_EQ(PartFilePersistenceSeams::ConvertDownloadFreeSpaceFloorBytesToDisplayGiB(0u), PartFilePersistenceSeams::kMinDiskSpaceFloorGiB);
	CHECK_EQ(PartFilePersistenceSeams::ConvertDownloadFreeSpaceFloorBytesToDisplayGiB(PartFilePersistenceSeams::kMaxDownloadFreeBytes), PartFilePersistenceSeams::kMaxDiskSpaceFloorGiB);
	CHECK_EQ(PartFilePersistenceSeams::kMinPartMetWriteFreeBytes, PartFilePersistenceSeams::kMinDownloadFreeBytes);
}

TEST_CASE("Part-file persistence seam caps and aggregates insufficient resume headroom")
{
	CHECK_EQ(PartFilePersistenceSeams::GetInsufficientResumeHeadroomBytes(0u), 0u);
	CHECK_EQ(PartFilePersistenceSeams::GetInsufficientResumeHeadroomBytes(PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes / 2u),
		PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes / 2u);
	CHECK_EQ(PartFilePersistenceSeams::GetInsufficientResumeHeadroomBytes(PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes + 1u),
		PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes);
	CHECK_EQ(PartFilePersistenceSeams::AddInsufficientResumeHeadroomBytes(
		PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes, PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes),
		PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes * 2u);
}

TEST_CASE("Part-file persistence seam only resumes insufficient files after the full hysteresis budget is available")
{
	const uint64_t nMinimumFreeBytes = PartFilePersistenceSeams::kMinDownloadFreeBytes;
	const uint64_t nResumeHeadroomBytes = PartFilePersistenceSeams::AddInsufficientResumeHeadroomBytes(
		PartFilePersistenceSeams::GetInsufficientResumeHeadroomBytes(PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes / 4u),
		PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes + 123u);

	CHECK_EQ(PartFilePersistenceSeams::GetInsufficientResumeThresholdBytes(nMinimumFreeBytes, nResumeHeadroomBytes),
		nMinimumFreeBytes + nResumeHeadroomBytes);
	CHECK_FALSE(PartFilePersistenceSeams::CanResumeInsufficientFileWithFreeSpace(
		nMinimumFreeBytes + nResumeHeadroomBytes - 1u, nMinimumFreeBytes, nResumeHeadroomBytes));
	CHECK(PartFilePersistenceSeams::CanResumeInsufficientFileWithFreeSpace(
		nMinimumFreeBytes + nResumeHeadroomBytes, nMinimumFreeBytes, nResumeHeadroomBytes));
}

TEST_CASE("Part-file persistence seam does not reuse stale metadata write decisions")
{
	PartFilePersistenceSeams::PartMetWriteGuardState state = { false, false };

	CHECK_FALSE(PartFilePersistenceSeams::ShouldReusePartMetWriteCache(false, false));
	CHECK_FALSE(PartFilePersistenceSeams::ShouldReusePartMetWriteCache(false, true));

	PartFilePersistenceSeams::StorePartMetWriteGuardState(&state, true);
	CHECK(state.HasCachedResult);
	CHECK(state.CanWrite);
	CHECK_FALSE(PartFilePersistenceSeams::ShouldReusePartMetWriteCache(state.HasCachedResult, false));
	CHECK_FALSE(PartFilePersistenceSeams::ShouldReusePartMetWriteCache(state.HasCachedResult, true));

	PartFilePersistenceSeams::InvalidatePartMetWriteGuardState(&state);
	CHECK_FALSE(state.HasCachedResult);
	CHECK_FALSE(state.CanWrite);

	PartFilePersistenceSeams::StorePartMetWriteGuardState(NULL, true);
	PartFilePersistenceSeams::InvalidatePartMetWriteGuardState(NULL);

	state = { true, true };
	const PartFilePersistenceSeams::PartMetWriteGuardDecision decision =
		PartFilePersistenceSeams::ResolvePartMetWriteGuard(
			state.HasCachedResult,
			state.CanWrite,
			false,
			PartFilePersistenceSeams::kMinPartMetWriteFreeBytes - 1u);

	CHECK_FALSE(decision.UseCachedResult);
	CHECK_FALSE(decision.CanWrite);
}

TEST_CASE("Part-file persistence seam exposes path existence without treating blank paths as files")
{
	ScopedTempDir tempDir;
	const std::filesystem::path existingPath = tempDir.Root() / L"download.part.met";
	WriteTextFile(existingPath, "present");

	CHECK_FALSE(PartFilePersistenceSeams::PathExists(NULL));
	CHECK_FALSE(PartFilePersistenceSeams::PathExists(_T("")));
	CHECK(PartFilePersistenceSeams::PathExists(existingPath.c_str()));
}

TEST_CASE("Part-file persistence seam exposes overlong .part.met existence on real unicode temp paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x504D4554u));

	const std::wstring rawPartMetPath = fixture.MakeDirectoryChildPath(L"001 odd-[state].part.met");
	const std::wstring preparedPartMetPath = LongPathTestSupport::PreparePathForLongPath(rawPartMetPath);
	WriteTextFileLongPath(rawPartMetPath, "present");

	CHECK(PartFilePersistenceSeams::PathExists(preparedPartMetPath.c_str()));
	CHECK_EQ(ReadTextFileLongPath(rawPartMetPath), std::string("present"));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(rawPartMetPath));
}

#if defined(EMULE_TEST_HAVE_PART_FILE_DELETE_PLAN_SEAMS)
TEST_CASE("Part-file persistence seam models metadata cleanup companion paths")
{
	const PartFilePersistenceSeams::PartFilePathString partMetPath(_T("C:\\Temp\\001.part.met"));

	CHECK(PartFilePersistenceSeams::BuildPartFileDeletePath(partMetPath, PartFilePersistenceSeams::PartFileDeletePathRole::Metadata)
		== PartFilePersistenceSeams::PartFilePathString(_T("C:\\Temp\\001.part.met")));
	CHECK(PartFilePersistenceSeams::BuildPartFileDeletePath(partMetPath, PartFilePersistenceSeams::PartFileDeletePathRole::Data)
		== PartFilePersistenceSeams::PartFilePathString(_T("C:\\Temp\\001.part")));
	CHECK(PartFilePersistenceSeams::BuildPartFileDeletePath(partMetPath, PartFilePersistenceSeams::PartFileDeletePathRole::Backup)
		== PartFilePersistenceSeams::PartFilePathString(_T("C:\\Temp\\001.part.met.bak")));
	CHECK(PartFilePersistenceSeams::BuildPartFileDeletePath(partMetPath, PartFilePersistenceSeams::PartFileDeletePathRole::Temporary)
		== PartFilePersistenceSeams::PartFilePathString(_T("C:\\Temp\\001.part.met.backup")));

	CHECK_EQ(PartFilePersistenceSeams::GetPartFileDeletePathCount(false), 3u);
	CHECK(PartFilePersistenceSeams::IsPartFileDeletePathActive(PartFilePersistenceSeams::PartFileDeletePathRole::Metadata, false));
	CHECK_FALSE(PartFilePersistenceSeams::IsPartFileDeletePathActive(PartFilePersistenceSeams::PartFileDeletePathRole::Data, false));
	CHECK(PartFilePersistenceSeams::IsPartFileDeletePathActive(PartFilePersistenceSeams::PartFileDeletePathRole::Backup, false));
	CHECK(PartFilePersistenceSeams::IsPartFileDeletePathActive(PartFilePersistenceSeams::PartFileDeletePathRole::Temporary, false));
}

TEST_CASE("Part-file persistence seam models full part-file delete paths on real temp storage")
{
	ScopedTempDir tempDir;
	const std::filesystem::path partMetFile = tempDir.Root() / L"002 odd-[delete].part.met";
	const PartFilePersistenceSeams::PartFilePathString partMetPath(partMetFile.c_str());
	const PartFilePersistenceSeams::PartFileDeletePathRole roles[] = {
		PartFilePersistenceSeams::PartFileDeletePathRole::Metadata,
		PartFilePersistenceSeams::PartFileDeletePathRole::Data,
		PartFilePersistenceSeams::PartFileDeletePathRole::Backup,
		PartFilePersistenceSeams::PartFileDeletePathRole::Temporary
	};

	CHECK_EQ(PartFilePersistenceSeams::GetPartFileDeletePathCount(true), 4u);
	for (const PartFilePersistenceSeams::PartFileDeletePathRole role : roles) {
		const std::filesystem::path plannedPath(PartFilePersistenceSeams::BuildPartFileDeletePath(partMetPath, role));
		WriteTextFile(plannedPath, "delete-me");
		CHECK(std::filesystem::exists(plannedPath));
	}

	for (const PartFilePersistenceSeams::PartFileDeletePathRole role : roles) {
		REQUIRE(PartFilePersistenceSeams::IsPartFileDeletePathActive(role, true));
		std::error_code ec;
		std::filesystem::remove(std::filesystem::path(PartFilePersistenceSeams::BuildPartFileDeletePath(partMetPath, role)), ec);
		REQUIRE_FALSE(ec);
	}

	for (const PartFilePersistenceSeams::PartFileDeletePathRole role : roles)
		CHECK_FALSE(std::filesystem::exists(std::filesystem::path(PartFilePersistenceSeams::BuildPartFileDeletePath(partMetPath, role))));
}
#endif

TEST_CASE("Part-file persistence seam keeps the non-shutdown flush path intact")
{
	CHECK(PartFilePersistenceSeams::ShouldFlushPartFileOnDestroy(false, false, false));
	CHECK(PartFilePersistenceSeams::ShouldFlushPartFileOnDestroy(true, true, true));
}

TEST_CASE("Part-file persistence helper rejects invalid atomic replace parameters")
{
	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(PartFilePersistenceSeams::TryReplaceFileAtomically(_T(""), _T("dst"), &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_PARAMETER));

	CHECK_FALSE(PartFilePersistenceSeams::TryReplaceFileAtomically(NULL, _T("dst"), &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_PARAMETER));

	CHECK_FALSE(PartFilePersistenceSeams::TryReplaceFileAtomically(_T("src"), _T(""), &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_PARAMETER));
}

TEST_CASE("Part-file persistence helper rejects invalid backup replacement parameters")
{
	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(PartFilePersistenceSeams::TryCopyFileToTempAndReplace(NULL, _T("dst"), _T("tmp"), false, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_PARAMETER));

	CHECK_FALSE(PartFilePersistenceSeams::TryCopyFileToTempAndReplace(_T("src"), _T("dst"), _T(""), false, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_PARAMETER));
}

TEST_CASE("Part-file persistence helper atomically replaces destination content")
{
	ScopedTempDir tempDir;
	const std::filesystem::path destinationPath = tempDir.Root() / L"download.part.met";
	const std::filesystem::path sourcePath = tempDir.Root() / L"download.part.met.tmp";

	WriteTextFile(destinationPath, "before");
	WriteTextFile(sourcePath, "after");

	DWORD dwLastError = ERROR_GEN_FAILURE;
	CHECK(PartFilePersistenceSeams::TryReplaceFileAtomically(sourcePath.c_str(), destinationPath.c_str(), &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_SUCCESS));
	CHECK_EQ(ReadTextFile(destinationPath), std::string("after"));
	CHECK_FALSE(std::filesystem::exists(sourcePath));
}

TEST_CASE("Part-file persistence helper atomically replaces overlong .part.met temp files on real temp storage")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x50415254u));

	const std::wstring rawPartPath = fixture.MakeDirectoryChildPath(L"001 odd-[chunk].part");
	const std::wstring rawDestinationPath = fixture.MakeDirectoryChildPath(L"001 odd-[chunk].part.met");
	const std::wstring rawSourcePath = fixture.MakeDirectoryChildPath(L"001 odd-[chunk].part.met.tmp");
	const std::wstring preparedDestinationPath = LongPathTestSupport::PreparePathForLongPath(rawDestinationPath);
	const std::wstring preparedSourcePath = LongPathTestSupport::PreparePathForLongPath(rawSourcePath);

	WriteTextFileLongPath(rawPartPath, "part-bytes");
	WriteTextFileLongPath(rawDestinationPath, "before");
	WriteTextFileLongPath(rawSourcePath, "after");

	DWORD dwLastError = ERROR_GEN_FAILURE;
	CHECK(PartFilePersistenceSeams::TryReplaceFileAtomically(preparedSourcePath.c_str(), preparedDestinationPath.c_str(), &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_SUCCESS));
	CHECK_EQ(ReadTextFileLongPath(rawDestinationPath), std::string("after"));
	CHECK_FALSE(PartFilePersistenceSeams::PathExists(preparedSourcePath.c_str()));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(rawPartPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(rawDestinationPath));
}

TEST_CASE("Part-file persistence helper creates backups through a temp file replace path")
{
	ScopedTempDir tempDir;
	const std::filesystem::path sourcePath = tempDir.Root() / L"download.part.met";
	const std::filesystem::path backupPath = tempDir.Root() / L"download.part.met.bak";
	const std::filesystem::path backupTmpPath = tempDir.Root() / L"download.part.met.bak.tmp";

	WriteTextFile(sourcePath, "current");
	WriteTextFile(backupPath, "previous");

	DWORD dwLastError = ERROR_GEN_FAILURE;
	CHECK(PartFilePersistenceSeams::TryCopyFileToTempAndReplace(sourcePath.c_str(), backupPath.c_str(), backupTmpPath.c_str(), false, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_SUCCESS));
	CHECK_EQ(ReadTextFile(backupPath), std::string("current"));
	CHECK_FALSE(std::filesystem::exists(backupTmpPath));
}

TEST_CASE("Part-file persistence helper stages .part.met backups on overlong unicode temp paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x42414B75u));

	const std::wstring rawPartPath = fixture.MakeDirectoryChildPath(L"002 odd-[chunk].part");
	const std::wstring rawSourcePath = fixture.MakeDirectoryChildPath(L"002 odd-[chunk].part.met");
	const std::wstring rawBackupPath = fixture.MakeDirectoryChildPath(L"002 odd-[chunk].part.met.bak");
	const std::wstring rawBackupTmpPath = fixture.MakeDirectoryChildPath(L"002 odd-[chunk].part.met.bak.tmp");
	const std::wstring preparedSourcePath = LongPathTestSupport::PreparePathForLongPath(rawSourcePath);
	const std::wstring preparedBackupPath = LongPathTestSupport::PreparePathForLongPath(rawBackupPath);
	const std::wstring preparedBackupTmpPath = LongPathTestSupport::PreparePathForLongPath(rawBackupTmpPath);

	WriteTextFileLongPath(rawPartPath, "part-bytes");
	WriteTextFileLongPath(rawSourcePath, "current");
	WriteTextFileLongPath(rawBackupPath, "previous");
	WriteTextFileLongPath(rawBackupTmpPath, "stale-temp");

	DWORD dwLastError = ERROR_GEN_FAILURE;
	CHECK(PartFilePersistenceSeams::TryCopyFileToTempAndReplace(preparedSourcePath.c_str(), preparedBackupPath.c_str(), preparedBackupTmpPath.c_str(), false, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_SUCCESS));
	CHECK_EQ(ReadTextFileLongPath(rawBackupPath), std::string("current"));
	CHECK_FALSE(PartFilePersistenceSeams::PathExists(preparedBackupTmpPath.c_str()));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(rawPartPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(rawSourcePath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(rawBackupPath));
}

TEST_CASE("Part-file persistence helper clears stale backup temp files before restaging")
{
	ScopedTempDir tempDir;
	const std::filesystem::path sourcePath = tempDir.Root() / L"download.part.met";
	const std::filesystem::path backupPath = tempDir.Root() / L"download.part.met.bak";
	const std::filesystem::path backupTmpPath = tempDir.Root() / L"download.part.met.bak.tmp";

	WriteTextFile(sourcePath, "current");
	WriteTextFile(backupPath, "previous");
	WriteTextFile(backupTmpPath, "stale-temp");

	DWORD dwLastError = ERROR_GEN_FAILURE;
	CHECK(PartFilePersistenceSeams::TryCopyFileToTempAndReplace(sourcePath.c_str(), backupPath.c_str(), backupTmpPath.c_str(), false, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_SUCCESS));
	CHECK_EQ(ReadTextFile(backupPath), std::string("current"));
	CHECK_FALSE(std::filesystem::exists(backupTmpPath));
}

TEST_CASE("Part-file persistence helper respects dont-override when a backup already exists")
{
	ScopedTempDir tempDir;
	const std::filesystem::path sourcePath = tempDir.Root() / L"download.part.met";
	const std::filesystem::path backupPath = tempDir.Root() / L"download.part.met.bak";
	const std::filesystem::path backupTmpPath = tempDir.Root() / L"download.part.met.bak.tmp";

	WriteTextFile(sourcePath, "current");
	WriteTextFile(backupPath, "existing-backup");

	DWORD dwLastError = ERROR_GEN_FAILURE;
	CHECK_FALSE(PartFilePersistenceSeams::TryCopyFileToTempAndReplace(sourcePath.c_str(), backupPath.c_str(), backupTmpPath.c_str(), true, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_FILE_EXISTS));
	CHECK_EQ(ReadTextFile(backupPath), std::string("existing-backup"));
	CHECK_FALSE(std::filesystem::exists(backupTmpPath));
}

TEST_CASE("Part-file persistence helper preserves the previous backup when staging the copy fails")
{
	ScopedTempDir tempDir;
	const std::filesystem::path sourcePath = tempDir.Root() / L"download.part.met";
	const std::filesystem::path backupPath = tempDir.Root() / L"download.part.met.bak";
	const std::filesystem::path backupTmpPath = tempDir.Root() / L"download.part.met.bak.tmp";

	WriteTextFile(sourcePath, "current");
	WriteTextFile(backupPath, "previous");
	WriteTextFile(backupTmpPath, "stale-temp");

	PartFilePersistenceSeams::FileSystemOps ops = PartFilePersistenceSeams::GetDefaultFileSystemOps();
	ops.CopyFile = &AlwaysFailCopyFile;

	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(PartFilePersistenceSeams::TryCopyFileToTempAndReplaceWithOps(sourcePath.c_str(), backupPath.c_str(), backupTmpPath.c_str(), false, &dwLastError, ops));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_DISK_FULL));
	CHECK_EQ(ReadTextFile(backupPath), std::string("previous"));
	CHECK_FALSE(std::filesystem::exists(backupTmpPath));
}
#endif

TEST_SUITE_END;

TEST_SUITE_BEGIN("divergence");

#if defined(EMULE_TEST_HAVE_PART_FILE_PERSISTENCE_SEAMS)
TEST_CASE("Part-file persistence seam blocks metadata writes when the free-space floor is not met")
{
	CHECK_FALSE(PartFilePersistenceSeams::CanWritePartMetWithFreeSpace(0u));
	CHECK_FALSE(PartFilePersistenceSeams::CanWritePartMetWithFreeSpace(PartFilePersistenceSeams::kMinPartMetWriteFreeBytes - 1u));
	CHECK(PartFilePersistenceSeams::CanWritePartMetWithFreeSpace(PartFilePersistenceSeams::kMinPartMetWriteFreeBytes));
	CHECK(PartFilePersistenceSeams::CanWritePartMetWithFreeSpace(PartFilePersistenceSeams::kMinPartMetWriteFreeBytes + 1u));
}

TEST_CASE("Part-file persistence seam invalidation forces a fresh low-space decision")
{
	PartFilePersistenceSeams::PartMetWriteGuardState state = { false, false };

	const PartFilePersistenceSeams::PartMetWriteGuardDecision initialDecision = PartFilePersistenceSeams::ResolvePartMetWriteGuard(state.HasCachedResult, state.CanWrite, false, PartFilePersistenceSeams::kMinPartMetWriteFreeBytes + 1u);
	CHECK_FALSE(initialDecision.UseCachedResult);
	CHECK(initialDecision.CanWrite);

	PartFilePersistenceSeams::StorePartMetWriteGuardState(&state, initialDecision.CanWrite);
	const PartFilePersistenceSeams::PartMetWriteGuardDecision cachedDecision = PartFilePersistenceSeams::ResolvePartMetWriteGuard(state.HasCachedResult, state.CanWrite, false, 0u);
	CHECK_FALSE(cachedDecision.UseCachedResult);
	CHECK_FALSE(cachedDecision.CanWrite);

	PartFilePersistenceSeams::InvalidatePartMetWriteGuardState(&state);
	const PartFilePersistenceSeams::PartMetWriteGuardDecision refreshedDecision = PartFilePersistenceSeams::ResolvePartMetWriteGuard(state.HasCachedResult, state.CanWrite, false, 0u);
	CHECK_FALSE(refreshedDecision.UseCachedResult);
	CHECK_FALSE(refreshedDecision.CanWrite);
}

TEST_CASE("Part-file persistence seam force-refresh ignores stale cached write permission")
{
	PartFilePersistenceSeams::PartMetWriteGuardState state = { true, true };

	const PartFilePersistenceSeams::PartMetWriteGuardDecision refreshedDecision = PartFilePersistenceSeams::ResolvePartMetWriteGuard(state.HasCachedResult, state.CanWrite, true, 0u);
	CHECK_FALSE(refreshedDecision.UseCachedResult);
	CHECK_FALSE(refreshedDecision.CanWrite);
	CHECK_FALSE(PartFilePersistenceSeams::ShouldReusePartMetWriteCache(state.HasCachedResult, true));
}

TEST_CASE("Part-file persistence seam skips destructor flushes only during shutdown after the write thread is gone")
{
	CHECK_FALSE(PartFilePersistenceSeams::ShouldFlushPartFileOnDestroy(true, false, false));
	CHECK_FALSE(PartFilePersistenceSeams::ShouldFlushPartFileOnDestroy(true, true, false));
}

TEST_CASE("Part-file persistence helper preserves destination content when the atomic replace fails")
{
	ScopedTempDir tempDir;
	const std::filesystem::path destinationPath = tempDir.Root() / L"download.part.met";
	const std::filesystem::path sourcePath = tempDir.Root() / L"download.part.met.tmp";

	WriteTextFile(destinationPath, "before");
	WriteTextFile(sourcePath, "after");

	PartFilePersistenceSeams::FileSystemOps ops = PartFilePersistenceSeams::GetDefaultFileSystemOps();
	ops.MoveFileEx = &AlwaysFailMoveFileEx;

	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(PartFilePersistenceSeams::TryReplaceFileAtomicallyWithOps(sourcePath.c_str(), destinationPath.c_str(), &dwLastError, ops));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_ACCESS_DENIED));
	CHECK_EQ(ReadTextFile(destinationPath), std::string("before"));
	CHECK(std::filesystem::exists(sourcePath));
}

TEST_CASE("Part-file persistence helper preserves the previous backup when temp replace fails")
{
	ScopedTempDir tempDir;
	const std::filesystem::path sourcePath = tempDir.Root() / L"download.part.met";
	const std::filesystem::path backupPath = tempDir.Root() / L"download.part.met.bak";
	const std::filesystem::path backupTmpPath = tempDir.Root() / L"download.part.met.bak.tmp";

	WriteTextFile(sourcePath, "current");
	WriteTextFile(backupPath, "previous");

	PartFilePersistenceSeams::FileSystemOps ops = PartFilePersistenceSeams::GetDefaultFileSystemOps();
	ops.MoveFileEx = &AlwaysFailMoveFileEx;

	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(PartFilePersistenceSeams::TryCopyFileToTempAndReplaceWithOps(sourcePath.c_str(), backupPath.c_str(), backupTmpPath.c_str(), false, &dwLastError, ops));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_ACCESS_DENIED));
	CHECK_EQ(ReadTextFile(backupPath), std::string("previous"));
	CHECK_FALSE(std::filesystem::exists(backupTmpPath));
}
#endif

TEST_SUITE_END;
