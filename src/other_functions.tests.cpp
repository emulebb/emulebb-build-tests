#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "LongPathSeams.h"
#include "OtherFunctionsSeams.h"
#include "PathHelpers.h"
#include "SharedFileIntakePolicy.h"
#include "ShellUiHelpers.h"

#include <algorithm>
#include <objbase.h>
#include <windows.h>

TEST_SUITE_BEGIN("parity");

namespace
{
CString RepeatPathFragment(LPCTSTR pszFragment, const int nCount)
{
	CString strRepeated;
	for (int i = 0; i < nCount; ++i)
		strRepeated += pszFragment;
	return strRepeated;
}

struct SpecialNameCase
{
	const wchar_t *pszDirectoryName;
	const wchar_t *pszFileName;
	bool bRequiresExactNamespace;
};

std::vector<SpecialNameCase> GetSpecialNameCases()
{
	return {
		{ L".leading-dot-dir", L".leading-dot-file", false },
		{ L"trailing-dot-dir.", L"trailing-dot-file.", true },
		{ L" leading-space-dir", L" leading-space-file", true },
		{ L"trailing-space-dir ", L"trailing-space-file ", true },
		{ L"space-only-dir ", L" ", true },
		{ L"reserved-device-dir", L"NUL.txt", true },
		{ L"\u00A0leading-nbsp-dir", L"\u00A0leading-nbsp-file", false },
		{ L"trailing-nbsp-dir\u00A0", L"trailing-nbsp-file\u00A0", false },
		{ L"\u2003leading-emspace-dir", L"\u2003leading-emspace-file", false },
		{ L"trailing-emspace-dir\u2003", L"trailing-emspace-file\u2003", false }
	};
}

bool IsRealThumbsDbStorage(const CString &rstrFilePath, const CString &rstrFileName)
{
	if (rstrFileName.CompareNoCase(_T("thumbs.db")) != 0)
		return false;

	IStorage *pStorage = NULL;
	if (::StgOpenStorage(rstrFilePath, NULL, STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0, &pStorage) != S_OK)
		return false;

	IEnumSTATSTG *pEnumSTATSTG = NULL;
	const HRESULT hrEnum = pStorage->EnumElements(0, NULL, 0, &pEnumSTATSTG);
	if (FAILED(hrEnum)) {
		pStorage->Release();
		return false;
	}

	STATSTG statstg = {};
	const HRESULT hrNext = pEnumSTATSTG->Next(1, &statstg, 0);
	if (statstg.pwcsName != NULL)
		::CoTaskMemFree(statstg.pwcsName);
	pEnumSTATSTG->Release();
	pStorage->Release();
	return hrNext == S_OK;
}
}

TEST_CASE("Other-functions seam strips Win32 long-path prefixes before shell parsing")
{
	CHECK(PathHelpers::HasExtendedLengthPrefix(CString(_T("\\\\?\\C:\\deep\\leaf.bin"))));
	CHECK(PathHelpers::HasExtendedLengthPrefix(CString(_T("\\\\?\\UNC\\server\\share\\leaf.bin"))));
	CHECK_FALSE(PathHelpers::HasExtendedLengthPrefix(CString(_T("C:\\short\\leaf.bin"))));
	CHECK(PathHelpers::StripExtendedLengthPrefix(CString(_T("\\\\?\\C:\\deep\\leaf.bin"))) == CString(_T("C:\\deep\\leaf.bin")));
	CHECK(PathHelpers::StripExtendedLengthPrefix(CString(_T("\\\\?\\UNC\\server\\share\\leaf.bin"))) == CString(_T("\\\\server\\share\\leaf.bin")));
	CHECK(PathHelpers::StripExtendedLengthPrefix(CString(_T("C:\\short\\leaf.bin"))) == CString(_T("C:\\short\\leaf.bin")));
}

TEST_CASE("Path-helper seam normalizes trailing separators across drive UNC and long paths")
{
	CHECK(PathHelpers::EnsureTrailingSeparator(CString(_T("C:\\temp"))) == CString(_T("C:\\temp\\")));
	CHECK(PathHelpers::EnsureTrailingSeparator(CString(_T("C:\\"))) == CString(_T("C:\\")));
	CHECK(PathHelpers::EnsureTrailingSeparator(CString(_T("\\\\server\\share"))) == CString(_T("\\\\server\\share\\")));
	CHECK(PathHelpers::EnsureTrailingSeparator(CString(_T("\\\\?\\C:\\deep\\path"))) == CString(_T("\\\\?\\C:\\deep\\path\\")));

	CHECK(PathHelpers::TrimTrailingSeparator(CString(_T("C:\\temp\\"))) == CString(_T("C:\\temp")));
	CHECK(PathHelpers::TrimTrailingSeparator(CString(_T("C:\\"))) == CString(_T("C:\\")));
	CHECK(PathHelpers::TrimTrailingSeparator(CString(_T("\\\\server\\share\\"))) == CString(_T("\\\\server\\share\\")));
	CHECK(PathHelpers::TrimTrailingSeparator(CString(_T("\\\\server\\share\\folder\\"))) == CString(_T("\\\\server\\share\\folder")));
	CHECK(PathHelpers::TrimTrailingSeparator(CString(_T("\\\\?\\UNC\\server\\share\\dir\\"))) == CString(_T("\\\\?\\UNC\\server\\share\\dir")));

	CHECK(PathHelpers::TrimTrailingSeparatorForLeaf(CString(_T("C:\\"))) == CString(_T("C:")));
	CHECK(PathHelpers::TrimTrailingSeparatorForLeaf(CString(_T("\\\\server\\share\\"))) == CString(_T("\\\\server\\share")));
	CHECK(PathHelpers::TrimTrailingSeparatorForLeaf(CString(_T("\\\\server\\share\\folder\\"))) == CString(_T("\\\\server\\share\\folder")));
}

TEST_CASE("Shell/UI seam preserves folder roots when preparing shell selection paths")
{
	CHECK(ShellUiHelpers::PrepareFolderSelectionPathForShell(CString(_T("C:\\"))) == CString(_T("C:\\")));
	CHECK(ShellUiHelpers::PrepareFolderSelectionPathForShell(CString(_T("\\\\server\\share\\"))) == CString(_T("\\\\server\\share\\")));
	CHECK(ShellUiHelpers::PrepareFolderSelectionPathForShell(CString(_T("\\\\?\\C:\\deep\\folder\\"))) == CString(_T("C:\\deep\\folder")));
	CHECK(ShellUiHelpers::PrepareFolderSelectionPathForShell(CString(_T("\\\\?\\UNC\\server\\share\\folder\\"))) == CString(_T("\\\\server\\share\\folder")));
	CHECK(ShellUiHelpers::PrepareFolderSelectionPathForShell(CString(_T("C:\\deep\\folder. \\"))).IsEmpty());
	CHECK(ShellUiHelpers::PrepareFolderSelectionPathForShell(CString(_T("\\\\?\\C:\\deep\\folder. \\"))).IsEmpty());
}

TEST_CASE("Other-functions seam routes deep unicode deletes through the direct long-path path when recycle-bin delete is disabled")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 4097u, 0x0B2201u));

	int nRecycleDeleteCalls = 0;
	int nDirectDeleteCalls = 0;
	const std::wstring filePath = fixture.FilePath();

	const bool bDeleted = OtherFunctionsSeams::ExecuteShellDelete(
		filePath.c_str(),
		false,
		NULL,
		[](LPCTSTR pszPath) { return LongPathSeams::PathExists(pszPath) != FALSE; },
		[&](LPCTSTR, HWND) {
			++nRecycleDeleteCalls;
			return false;
		},
		[&](LPCTSTR pszPath) {
			++nDirectDeleteCalls;
			return LongPathSeams::DeleteFile(pszPath) != FALSE;
		});

	CHECK(bDeleted);
	CHECK_EQ(nRecycleDeleteCalls, 0);
	CHECK_EQ(nDirectDeleteCalls, 1);
	CHECK_FALSE(LongPathSeams::PathExists(filePath.c_str()));
}

TEST_CASE("Other-functions seam routes deep unicode deletes through the recycle-bin path when recycle-bin delete is enabled")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 2049u, 0x0B2202u));

	int nRecycleDeleteCalls = 0;
	int nDirectDeleteCalls = 0;
	const std::wstring filePath = fixture.FilePath();

	const bool bDeleted = OtherFunctionsSeams::ExecuteShellDelete(
		filePath.c_str(),
		true,
		reinterpret_cast<HWND>(static_cast<INT_PTR>(0x1234)),
		[](LPCTSTR pszPath) { return LongPathSeams::PathExists(pszPath) != FALSE; },
		[&](LPCTSTR pszPath, HWND hOwnerWindow) {
			++nRecycleDeleteCalls;
			CHECK(CString(pszPath) == CString(filePath.c_str()));
			CHECK(hOwnerWindow == reinterpret_cast<HWND>(static_cast<INT_PTR>(0x1234)));
			return true;
		},
		[&](LPCTSTR) {
			++nDirectDeleteCalls;
			return false;
		});

	CHECK(bDeleted);
	CHECK_EQ(nRecycleDeleteCalls, 1);
	CHECK_EQ(nDirectDeleteCalls, 0);
	CHECK(LongPathSeams::PathExists(filePath.c_str()));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(filePath));
}

TEST_CASE("Path-helper seam grows module-path buffers past MAX_PATH")
{
	const CString strExpected = CString(_T("C:\\module-root\\")) + RepeatPathFragment(_T("segment\\"), 80) + CString(_T("emule.exe"));

	const CString strActual = PathHelpers::GetModuleFilePath(
		reinterpret_cast<HMODULE>(static_cast<INT_PTR>(0x7777)),
		[&](HMODULE hModule, LPTSTR pszBuffer, DWORD cchBuffer) -> DWORD {
			CHECK(hModule == reinterpret_cast<HMODULE>(static_cast<INT_PTR>(0x7777)));
			if (cchBuffer == 0)
				return 0;

			const DWORD cchRequired = static_cast<DWORD>(strExpected.GetLength());
			if (cchBuffer <= cchRequired) {
				const DWORD cchToCopy = cchBuffer - 1;
				for (DWORD i = 0; i < cchToCopy; ++i)
					pszBuffer[i] = strExpected[i];
				pszBuffer[cchToCopy] = _T('\0');
				return cchBuffer;
			}

			for (DWORD i = 0; i < cchRequired; ++i)
				pszBuffer[i] = strExpected[i];
			pszBuffer[cchRequired] = _T('\0');
			return cchRequired;
		});

	CHECK(strActual == strExpected);
	CHECK(strActual.GetLength() > MAX_PATH);
}

TEST_CASE("Path-helper seam joins MediaInfo DLL candidates without MAX_PATH truncation")
{
	const CString strBase = CString(_T("C:\\Program Files\\")) + RepeatPathFragment(_T("MediaInfo\\segment\\"), 40) + CString(_T("bin"));
	const CString strJoined = PathHelpers::AppendPathComponent(strBase, _T("MEDIAINFO.DLL"));

	CHECK(strJoined == strBase + CString(_T("\\MEDIAINFO.DLL")));
	CHECK(strJoined.GetLength() > MAX_PATH);
}

TEST_CASE("Path-helper seam canonicalizes overlong paths lexically")
{
	const CString strPrefix = CString(_T("C:\\skins\\")) + RepeatPathFragment(_T("segment\\"), 60);
	const CString strInput = strPrefix + CString(_T(".\\theme\\..\\icons\\logo.gif"));
	const CString strExpected = strPrefix + CString(_T("icons\\logo.gif"));

	CHECK(PathHelpers::CanonicalizePath(strInput) == strExpected);
	CHECK(strInput.GetLength() > MAX_PATH);
}

TEST_CASE("Path-helper seam expands DOS 8.3 aliases to canonical long names for existing files")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 513u, 0x0C0FFEEu));

	std::wstring shortAlias;
	if (!LongPathTestSupport::TryGetShortPathAlias(fixture.FilePath(), shortAlias))
		return;

	CString strCanonicalPath;
	DWORD dwCanonicalizeError = ERROR_SUCCESS;
	REQUIRE(PathHelpers::TryCanonicalizeExistingPath(CString(shortAlias.c_str()), strCanonicalPath, &dwCanonicalizeError));
	CHECK(strCanonicalPath == CString(fixture.FilePath().c_str()));
}

TEST_CASE("Path-helper seam treats prefixed, dotted, and DOS 8.3 aliases as the same existing path")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 777u, 0x0D00D00u));

	const CString strLongPath(fixture.FilePath().c_str());
	const CString strPrefixedPath(LongPathTestSupport::PreparePathForLongPath(fixture.FilePath()).c_str());
	const CString strDottedPath((fixture.DirectoryPath() + L"\\.\\payload_" + LongPathTestSupport::MakeSpecialSegment() + L".bin").c_str());

	CHECK(PathHelpers::ArePathsEquivalent(strLongPath, strPrefixedPath));
	CHECK(PathHelpers::ArePathsEquivalent(strLongPath, strDottedPath));

	std::wstring shortAlias;
	if (!LongPathTestSupport::TryGetShortPathAlias(fixture.FilePath(), shortAlias))
		return;

	CHECK(PathHelpers::ArePathsEquivalent(strLongPath, CString(shortAlias.c_str())));
}

TEST_CASE("Path-helper seam treats descendant checks as equivalent across canonical path spellings")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x0F2200Fu));

	const CString strLongDirectory(PathHelpers::EnsureTrailingSeparator(CString(fixture.DirectoryPath().c_str())));
	const CString strLongFile(CString(fixture.FilePath().c_str()));
	const CString strPrefixedDirectory(PathHelpers::EnsureTrailingSeparator(CString(LongPathTestSupport::PreparePathForLongPath(fixture.DirectoryPath()).c_str())));
	const CString strPrefixedFile(CString(LongPathTestSupport::PreparePathForLongPath(fixture.FilePath()).c_str()));

	CHECK(PathHelpers::IsPathWithinDirectory(strLongDirectory, strLongFile));
	CHECK(PathHelpers::IsPathWithinDirectory(strLongDirectory, strPrefixedFile));
	CHECK(PathHelpers::IsPathWithinDirectory(strPrefixedDirectory, strLongFile));

	std::wstring shortAlias;
	if (LongPathTestSupport::TryGetShortPathAlias(fixture.DirectoryPath(), shortAlias)) {
		const CString strShortDirectory(PathHelpers::EnsureTrailingSeparator(CString(shortAlias.c_str())));
		CHECK(PathHelpers::IsPathWithinDirectory(strShortDirectory, strLongFile));
	}

	const CString strEscapingCandidate((fixture.DirectoryPath() + L"\\..\\outside.bin").c_str());
	CHECK_FALSE(PathHelpers::IsPathWithinDirectory(strLongDirectory, strEscapingCandidate));
}

TEST_CASE("Path-helper seam queries single overlong filesystem entries without MAX_PATH-specific branches")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 222u, 0x0F3300Fu));

	WIN32_FIND_DATA findData = {};
	DWORD dwFindError = ERROR_SUCCESS;
	REQUIRE(PathHelpers::TryGetPathEntryData(CString(fixture.FilePath().c_str()), findData, &dwFindError));
	CHECK(dwFindError == ERROR_SUCCESS);
	CHECK((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
	CHECK(CString(findData.cFileName) == CString((L"payload_" + LongPathTestSupport::MakeSpecialSegment() + L".bin").c_str()));

	const ULONGLONG ullFoundFileSize = (static_cast<ULONGLONG>(findData.nFileSizeHigh) << 32) | findData.nFileSizeLow;
	CHECK_EQ(ullFoundFileSize, static_cast<ULONGLONG>(fixture.Payload().size()));
}

TEST_CASE("Path-helper seam preserves exact leading and trailing dot and whitespace names for files and folders")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x0F5500Fu));

	unsigned int uSeed = 0x71710000u;
	for (const SpecialNameCase &nameCase : GetSpecialNameCases()) {
		const std::wstring directoryPath = fixture.DirectoryPath() + L"\\" + nameCase.pszDirectoryName;
		const std::wstring filePath = directoryPath + L"\\" + nameCase.pszFileName;
		const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(193u + (uSeed & 0x3Fu), uSeed++);

		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(directoryPath));
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(filePath, payload));

		CString strCanonicalDirectory;
		DWORD dwCanonicalDirectoryError = ERROR_SUCCESS;
		REQUIRE(PathHelpers::TryCanonicalizeExistingPath(CString(directoryPath.c_str()), strCanonicalDirectory, &dwCanonicalDirectoryError));
		CHECK(strCanonicalDirectory == CString(directoryPath.c_str()));

		CString strCanonicalFile;
		DWORD dwCanonicalFileError = ERROR_SUCCESS;
		REQUIRE(PathHelpers::TryCanonicalizeExistingPath(CString(filePath.c_str()), strCanonicalFile, &dwCanonicalFileError));
		CHECK(strCanonicalFile == CString(filePath.c_str()));
		CHECK(PathHelpers::RequiresExtendedLengthPathForExactName(strCanonicalFile) == nameCase.bRequiresExactNamespace);
		CHECK(PathHelpers::ArePathsEquivalent(strCanonicalFile, CString(LongPathTestSupport::PreparePathForLongPath(filePath).c_str())));
		CHECK(PathHelpers::IsPathWithinDirectory(PathHelpers::EnsureTrailingSeparator(strCanonicalDirectory), strCanonicalFile));

		WIN32_FIND_DATA findData = {};
		DWORD dwFindError = ERROR_SUCCESS;
		REQUIRE(PathHelpers::TryGetPathEntryData(strCanonicalFile, findData, &dwFindError));
		CHECK(CString(findData.cFileName) == CString(nameCase.pszFileName));

		bool bFoundDirectory = false;
		REQUIRE(PathHelpers::ForEachDirectoryEntry(CString(fixture.DirectoryPath().c_str()), [&](const WIN32_FIND_DATA &entry) -> bool {
			bFoundDirectory = bFoundDirectory || CString(entry.cFileName) == CString(nameCase.pszDirectoryName);
			return true;
		}));
		CHECK(bFoundDirectory);

		bool bFoundFile = false;
		REQUIRE(PathHelpers::ForEachDirectoryEntry(strCanonicalDirectory, [&](const WIN32_FIND_DATA &entry) -> bool {
			bFoundFile = bFoundFile || CString(entry.cFileName) == CString(nameCase.pszFileName);
			return true;
		}));
		CHECK(bFoundFile);

		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(filePath));
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(directoryPath));
	}
}

TEST_CASE("Path-helper seam enumerates wildcard matches under overlong directories")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 333u, 0x0F4400Fu));

	const std::wstring secondFilePath = fixture.MakeDirectoryChildPath(L"second_payload.bin");
	const std::wstring ignoredFilePath = fixture.MakeDirectoryChildPath(L"ignored.txt");
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(secondFilePath, LongPathTestSupport::BuildDeterministicPayload(64u, 0x0ABCDEF0u)));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(ignoredFilePath, LongPathTestSupport::BuildDeterministicPayload(16u, 0x01020304u)));

	bool bFoundFixturePayload = false;
	bool bFoundSecondPayload = false;
	bool bFoundIgnored = false;
	DWORD dwFindError = ERROR_SUCCESS;
	REQUIRE(PathHelpers::ForEachMatchingEntry(CString((fixture.DirectoryPath() + L"\\*.bin").c_str()),
		[&](const WIN32_FIND_DATA &findData) -> bool {
		const CString strFileName(findData.cFileName);
		bFoundFixturePayload = bFoundFixturePayload || strFileName == CString((L"payload_" + LongPathTestSupport::MakeSpecialSegment() + L".bin").c_str());
		bFoundSecondPayload = bFoundSecondPayload || strFileName == _T("second_payload.bin");
		bFoundIgnored = bFoundIgnored || strFileName == _T("ignored.txt");
		return true;
	}, &dwFindError));
	CHECK(dwFindError == ERROR_SUCCESS);
	CHECK(bFoundFixturePayload);
	CHECK(bFoundSecondPayload);
	CHECK_FALSE(bFoundIgnored);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(secondFilePath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(ignoredFilePath));
}

TEST_CASE("Path-helper seam enumerates wildcard matches inside short exact-name and reserved-name directories")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 0u, 0x0F4410Fu));

	const std::wstring exactDirectory = fixture.DirectoryPath() + L"\\ leading-space-dir";
	const std::wstring exactFile = exactDirectory + L"\\alpha.bin";
	const std::wstring exactIgnored = exactDirectory + L"\\beta.txt";
	const std::wstring reservedDirectory = fixture.DirectoryPath() + L"\\reserved-device-dir";
	const std::wstring reservedFile = reservedDirectory + L"\\NUL.bin";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(exactDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(exactFile, LongPathTestSupport::BuildDeterministicPayload(48u, 0x4411u)));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(exactIgnored, LongPathTestSupport::BuildDeterministicPayload(24u, 0x4412u)));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(reservedDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(reservedFile, LongPathTestSupport::BuildDeterministicPayload(52u, 0x4413u)));

	bool bFoundExact = false;
	bool bFoundIgnored = false;
	REQUIRE(PathHelpers::ForEachMatchingEntry(CString((exactDirectory + L"\\*.bin").c_str()), [&](const WIN32_FIND_DATA &findData) -> bool {
		const CString strFileName(findData.cFileName);
		bFoundExact = bFoundExact || strFileName == _T("alpha.bin");
		bFoundIgnored = bFoundIgnored || strFileName == _T("beta.txt");
		return true;
	}));
	CHECK(bFoundExact);
	CHECK_FALSE(bFoundIgnored);

	bool bFoundReserved = false;
	REQUIRE(PathHelpers::ForEachMatchingEntry(CString((reservedDirectory + L"\\*.bin").c_str()), [&](const WIN32_FIND_DATA &findData) -> bool {
		bFoundReserved = bFoundReserved || CString(findData.cFileName) == _T("NUL.bin");
		return true;
	}));
	CHECK(bFoundReserved);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(exactFile));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(exactIgnored));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(reservedFile));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(exactDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(reservedDirectory));
}

TEST_CASE("Path-helper seam enumerates child entries whose full paths exceed MAX_PATH even when the parent directory does not")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 0u, 0x0E11E11u));
	REQUIRE(fixture.DirectoryPath().size() < MAX_PATH);

	std::wstring longDirectoryLeaf = L"childdir_";
	while (fixture.DirectoryPath().size() + 1u + longDirectoryLeaf.size() <= MAX_PATH + 8u && longDirectoryLeaf.size() < 220u) {
		longDirectoryLeaf += L"segment_";
		longDirectoryLeaf += LongPathTestSupport::MakeSpecialSegment();
	}
	const std::wstring longDirectoryPath = fixture.DirectoryPath() + L"\\" + longDirectoryLeaf;
	REQUIRE(longDirectoryPath.size() > MAX_PATH);
	REQUIRE(::CreateDirectoryW(LongPathTestSupport::PrepareDirectoryCreatePathForLongPath(longDirectoryPath).c_str(), NULL) != FALSE);

	std::wstring longFileLeaf = L"payload_";
	while (fixture.DirectoryPath().size() + 1u + longFileLeaf.size() + 4u <= MAX_PATH + 12u && longFileLeaf.size() < 220u) {
		longFileLeaf += L"segment_";
		longFileLeaf += LongPathTestSupport::MakeSpecialSegment();
	}
	longFileLeaf += L".bin";
	const std::wstring longFilePath = fixture.DirectoryPath() + L"\\" + longFileLeaf;
	REQUIRE(longFilePath.size() > MAX_PATH);
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(321u, 0x12345678u);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(longFilePath, payload));

	std::vector<std::wstring> names;
	DWORD dwEnumerateError = ERROR_SUCCESS;
	REQUIRE(PathHelpers::ForEachDirectoryEntry(CString(fixture.DirectoryPath().c_str()), [&](const WIN32_FIND_DATA &findData) -> bool {
		names.push_back(findData.cFileName);
		return true;
	}, &dwEnumerateError));
	CHECK(dwEnumerateError == ERROR_SUCCESS);
	CHECK(std::find(names.begin(), names.end(), longDirectoryLeaf) != names.end());
	CHECK(std::find(names.begin(), names.end(), longFileLeaf) != names.end());

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(longFilePath));
	REQUIRE(::RemoveDirectoryW(LongPathTestSupport::PreparePathForLongPath(longDirectoryPath).c_str()) != FALSE);
}

TEST_CASE("Path-helper seam formats MiniMule resource URLs from overlong module paths")
{
	const CString strModulePath = CString(_T("C:\\Program Files\\eMule\\")) + RepeatPathFragment(_T("segment\\"), 70) + CString(_T("emule.exe"));
	const CString strResourceUrl = PathHelpers::BuildModuleResourceBaseUrl(
		reinterpret_cast<HMODULE>(static_cast<INT_PTR>(0x2222)),
		[&](HMODULE hModule, LPTSTR pszBuffer, DWORD cchBuffer) -> DWORD {
			CHECK(hModule == reinterpret_cast<HMODULE>(static_cast<INT_PTR>(0x2222)));
			if (cchBuffer == 0)
				return 0;

			const DWORD cchRequired = static_cast<DWORD>(strModulePath.GetLength());
			if (cchBuffer <= cchRequired) {
				const DWORD cchToCopy = cchBuffer - 1;
				for (DWORD i = 0; i < cchToCopy; ++i)
					pszBuffer[i] = strModulePath[i];
				pszBuffer[cchToCopy] = _T('\0');
				return cchBuffer;
			}

			for (DWORD i = 0; i < cchRequired; ++i)
				pszBuffer[i] = strModulePath[i];
			pszBuffer[cchRequired] = _T('\0');
			return cchRequired;
		});

	CHECK(strResourceUrl == CString(_T("res://")) + strModulePath);
	CHECK(strResourceUrl.GetLength() > MAX_PATH);
}

TEST_CASE("Shell/UI seam ignores Windows shortcuts by extension")
{
	CHECK(ShellUiHelpers::ShouldIgnoreShortcutFileName(_T("sample.lnk")));
	CHECK(ShellUiHelpers::ShouldIgnoreShortcutFileName(_T("SAMPLE.LNK")));
	CHECK_FALSE(ShellUiHelpers::ShouldIgnoreShortcutFileName(_T("sample.txt")));
}

TEST_CASE("Shared-file intake policy ignores built-in junk names and preserves nearby names")
{
	SharedFileIntakePolicy::ScopedUserRuleOverride restoreRules;
	SharedFileIntakePolicy::ClearUserRules();

	const CString strIconCrName(_T("Icon\r"));
	const CString strIconCrTxtName(_T("Icon\r.txt"));

	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("desktop.ini")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("Desktop.ini")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("ehthumbs.db")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".DS_Store")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".localized")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".directory")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(strIconCrName));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.lnk")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.part")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.crdownload")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.download")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.tmp")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.temp")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample~")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("~$draft.docx")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("._resource")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".nfsA1B2C3")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".sb-cache")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".syncthing.index-v0")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("~lock.report.odt#")));

	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T("desktop.ini.bak")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".localized.bak")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.part.txt")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T("sample.tmpx")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T(".syncthing")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T("~lock.report.odt")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T("Icon")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(strIconCrTxtName));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreCandidate(_T("C:\\share\\thumbs.db"), _T("thumbs.db"), [](const CString &, const CString &) { return false; }));
}

TEST_CASE("Shared-file intake policy parses additive shareignore rules and applies them to files and directories")
{
	SharedFileIntakePolicy::ScopedUserRuleOverride restoreRules;
	SharedFileIntakePolicy::ClearUserRules();

	SharedFileIntakePolicy::IgnoreRule rule = {};
	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("exact.name"), rule));
	CHECK_EQ(rule.eMatchKind, SharedFileIntakePolicy::RuleMatchExact);
	CHECK(rule.strPattern == CString(_T("exact.name")));

	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("prefix*"), rule));
	CHECK_EQ(rule.eMatchKind, SharedFileIntakePolicy::RuleMatchPrefix);
	CHECK(rule.strPattern == CString(_T("prefix")));

	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("*suffix"), rule));
	CHECK_EQ(rule.eMatchKind, SharedFileIntakePolicy::RuleMatchSuffix);
	CHECK(rule.strPattern == CString(_T("suffix")));

	CHECK_FALSE(SharedFileIntakePolicy::TryParseUserRule(_T(""), rule));
	CHECK_FALSE(SharedFileIntakePolicy::TryParseUserRule(_T("*"), rule));
	CHECK_FALSE(SharedFileIntakePolicy::TryParseUserRule(_T("prefix*suffix"), rule));
	CHECK_FALSE(SharedFileIntakePolicy::TryParseUserRule(_T("*middle*"), rule));

	std::vector<SharedFileIntakePolicy::IgnoreRule> userRules;
	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("skip-exact"), rule));
	userRules.push_back(rule);
	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("skip-prefix*"), rule));
	userRules.push_back(rule);
	REQUIRE(SharedFileIntakePolicy::TryParseUserRule(_T("*skip-suffix"), rule));
	userRules.push_back(rule);
	SharedFileIntakePolicy::ReplaceUserRules(userRules);

	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("skip-exact")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("skip-prefix-file.bin")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreByName(_T("archive.skip-suffix")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T("keep-prefix-file.bin")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreByName(_T("archive.skip-suffix.txt")));

	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T("skip-exact")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T("skip-prefix-folder")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T("folder.skip-suffix")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T("legit-folder")));
}

TEST_CASE("Shared-file intake policy ignores configured junk directories without hiding nearby legitimate folders")
{
	SharedFileIntakePolicy::ScopedUserRuleOverride restoreRules;
	SharedFileIntakePolicy::ClearUserRules();

	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".git")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".svn")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".hg")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T("CVS")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".fseventsd")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".spotlight-v100")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".temporaryitems")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".trashes")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".syncthing.private")));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T("._metadata")));

	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".github")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T(".spotlight-v100-backup")));
	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreDirectoryByName(_T("CVSROOT")));
}

TEST_CASE("Shared-file intake policy ignores real thumbs databases but not arbitrary files with the same name")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 0u, 0xA10080u));

	const std::wstring plainDir = fixture.MakeDirectoryChildPath(L"plain");
	const std::wstring storageDir = fixture.MakeDirectoryChildPath(L"storage");
	const std::wstring plainThumbsPath = plainDir + L"\\thumbs.db";
	const std::wstring storageThumbsPath = storageDir + L"\\thumbs.db";
	struct CleanupPaths
	{
		std::wstring plainThumbsPath;
		std::wstring storageThumbsPath;
		std::wstring storageDir;
		std::wstring plainDir;

		~CleanupPaths()
		{
			if (!plainThumbsPath.empty())
				(void)LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(plainThumbsPath);
			if (!storageThumbsPath.empty())
				(void)LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(storageThumbsPath);
			if (!storageDir.empty())
				(void)LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(storageDir);
			if (!plainDir.empty())
				(void)LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(plainDir);
		}
	} cleanup = { plainThumbsPath, storageThumbsPath, storageDir, plainDir };

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(plainDir));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(storageDir));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(
		plainThumbsPath,
		LongPathTestSupport::BuildDeterministicPayload(16u, 0x0BADF00Du)));

	IStorage *pStorage = NULL;
	REQUIRE(SUCCEEDED(::StgCreateDocfile(
		LongPathTestSupport::PreparePathForLongPath(storageThumbsPath).c_str(),
		STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE,
		0,
		&pStorage)));
	IStream *pStream = NULL;
	REQUIRE(SUCCEEDED(pStorage->CreateStream(L"Catalog", STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &pStream)));
	const char payload = 'x';
	ULONG cbWritten = 0;
	REQUIRE(SUCCEEDED(pStream->Write(&payload, sizeof(payload), &cbWritten)));
	CHECK_EQ(cbWritten, static_cast<ULONG>(sizeof(payload)));
	pStream->Release();
	pStorage->Commit(STGC_DEFAULT);
	pStorage->Release();

	CHECK_FALSE(SharedFileIntakePolicy::ShouldIgnoreCandidate(CString(plainThumbsPath.c_str()), _T("thumbs.db"), IsRealThumbsDbStorage));
	CHECK(SharedFileIntakePolicy::ShouldIgnoreCandidate(CString(storageThumbsPath.c_str()), _T("thumbs.db"), IsRealThumbsDbStorage));
}

TEST_CASE("Shell/UI seam limits shell display-name enrichment to shell-friendly paths")
{
	CHECK(ShellUiHelpers::CanUseShellDisplayName(_T("C:\\short\\folder")));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(_T("\\\\?\\C:\\deep\\folder")));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(CString(_T("C:\\")) + RepeatPathFragment(_T("segment\\"), 80)));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(_T("C:\\short\\ leading-space")));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(_T("C:\\short\\folder ")));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(_T("C:\\short\\folder.")));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(_T("C:\\short\\NUL.txt")));
}

TEST_CASE("Shell/UI seam builds stable extension and directory icon queries")
{
	const ShellUiHelpers::ShellIconDescriptor fileQuery = ShellUiHelpers::DescribeShellIcon(_T("C:\\deep\\folder\\movie.mkv"));
	CHECK(fileQuery.strCacheKey == CString(_T("mkv")));
	CHECK(fileQuery.strQueryPath == CString(_T("file.mkv")));
	CHECK_EQ(fileQuery.dwFileAttributes, static_cast<DWORD>(FILE_ATTRIBUTE_NORMAL));

	const ShellUiHelpers::ShellIconDescriptor folderQuery = ShellUiHelpers::DescribeShellIcon(_T("C:\\deep\\folder\\"));
	CHECK(folderQuery.strCacheKey == CString(_T("\\")));
	CHECK(folderQuery.strQueryPath == CString(_T("folder\\")));
	CHECK_EQ(folderQuery.dwFileAttributes, static_cast<DWORD>(FILE_ATTRIBUTE_DIRECTORY));
}

TEST_CASE("Shell/UI seam splits initial picker selections and restores trailing folder separators")
{
	const CString strInput = CString(_T("C:\\skins\\")) + RepeatPathFragment(_T("segment\\"), 50) + CString(_T("theme.ini"));
	const ShellUiHelpers::DialogInitialSelection selection = ShellUiHelpers::SplitDialogInitialSelection(strInput);

	CHECK(selection.strInitialFolder == PathHelpers::GetDirectoryPath(strInput));
	CHECK(selection.strFileName == CString(_T("theme.ini")));
	CHECK(ShellUiHelpers::FinalizeFolderSelection(selection.strInitialFolder).Right(1) == CString(_T("\\")));
}

TEST_CASE("Shell/UI seam resolves skin resources after environment expansion without MAX_PATH truncation")
{
	const CString strSkinProfile = CString(_T("C:\\profiles\\")) + RepeatPathFragment(_T("segment\\"), 45) + CString(_T("skin.ini"));
	const CString strResolved = ShellUiHelpers::ResolveSkinResourcePath(
		strSkinProfile,
		_T("%SKINROOT%\\icons\\toolbar.bmp"),
		[](const CString &rstrInput) -> CString {
			CHECK(rstrInput == CString(_T("%SKINROOT%\\icons\\toolbar.bmp")));
			return CString(_T("relative-root\\icons\\toolbar.bmp"));
		});

	CHECK(strResolved == PathHelpers::AppendPathComponent(PathHelpers::GetDirectoryPath(strSkinProfile), _T("relative-root\\icons\\toolbar.bmp")));
	CHECK(strResolved.GetLength() > MAX_PATH);
}

TEST_CASE("Shell/UI seam grows profile-string buffers past MAX_PATH")
{
	const CString strExpected = CString(_T("C:\\skins\\")) + RepeatPathFragment(_T("theme\\"), 70) + CString(_T("toolbar.bmp"));
	const CString strActual = ShellUiHelpers::GetProfileString(
		_T("Skin"),
		_T("Toolbar"),
		NULL,
		_T("C:\\profiles\\skin.ini"),
		[&](const CString &rstrSection, const CString &rstrKey, LPCTSTR, LPTSTR pszBuffer, DWORD cchBuffer, const CString &rstrProfileFile) -> DWORD {
			CHECK(rstrSection == CString(_T("Skin")));
			CHECK(rstrKey == CString(_T("Toolbar")));
			CHECK(rstrProfileFile == CString(_T("C:\\profiles\\skin.ini")));
			if (cchBuffer == 0)
				return 0;

			const DWORD cchRequired = static_cast<DWORD>(strExpected.GetLength());
			if (cchBuffer <= cchRequired) {
				const DWORD cchToCopy = cchBuffer - 1;
				for (DWORD i = 0; i < cchToCopy; ++i)
					pszBuffer[i] = strExpected[i];
				pszBuffer[cchToCopy] = _T('\0');
				return cchBuffer - 1;
			}

			for (DWORD i = 0; i < cchRequired; ++i)
				pszBuffer[i] = strExpected[i];
			pszBuffer[cchRequired] = _T('\0');
			return cchRequired;
		});

	CHECK(strActual == strExpected);
	CHECK(strActual.GetLength() > MAX_PATH);
}

TEST_SUITE_END;
