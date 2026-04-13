#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "LongPathSeams.h"
#include "OtherFunctionsSeams.h"
#include "PathHelpers.h"
#include "ShellUiHelpers.h"

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

TEST_CASE("Shell/UI seam limits shell display-name enrichment to shell-friendly paths")
{
	CHECK(ShellUiHelpers::CanUseShellDisplayName(_T("C:\\short\\folder")));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(_T("\\\\?\\C:\\deep\\folder")));
	CHECK_FALSE(ShellUiHelpers::CanUseShellDisplayName(CString(_T("C:\\")) + RepeatPathFragment(_T("segment\\"), 80)));
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
