#include "../third_party/doctest/doctest.h"

#include "../include/LongPathTestSupport.h"

#include "LongPathSeams.h"

#include <algorithm>
#include <cstdio>
#include <io.h>
#include <string>
#include <vector>
#include <windows.h>

namespace
{
	std::vector<BYTE> ReadBytesFromStream(FILE *pStream)
	{
		std::vector<BYTE> bytes;
		BYTE buffer[4096] = {};
		size_t nRead = 0;
		while ((nRead = fread(buffer, 1, sizeof buffer, pStream)) != 0)
			bytes.insert(bytes.end(), buffer, buffer + nRead);
		return bytes;
	}

	std::vector<BYTE> ReadBytesFromFd(const int fd)
	{
		std::vector<BYTE> bytes;
		BYTE buffer[4096] = {};
		int nRead = 0;
		while ((nRead = _read(fd, buffer, sizeof buffer)) > 0)
			bytes.insert(bytes.end(), buffer, buffer + nRead);
		return bytes;
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
}

TEST_SUITE_BEGIN("divergence");

TEST_CASE("Long-path seam matches the reference prefix policy for overlong and exact-name absolute paths")
{
	std::wstring longDriveAbsolute = L"C:\\";
	longDriveAbsolute.append(static_cast<size_t>(MAX_PATH), L'a');

	std::wstring longUnc = L"\\\\server\\share\\";
	longUnc.append(static_cast<size_t>(MAX_PATH), L'b');

	std::wstring longRelative(static_cast<size_t>(MAX_PATH) + 16u, L'c');
	std::wstring longDriveRelative = L"C:";
	longDriveRelative.append(static_cast<size_t>(MAX_PATH), L'd');
	std::wstring longRootRelative = L"\\";
	longRootRelative.append(static_cast<size_t>(MAX_PATH), L'e');
	std::wstring longDriveForwardSlash = L"C:/";
	longDriveForwardSlash.append(static_cast<size_t>(MAX_PATH), L'f');
	const std::wstring trailingDotPath = L"C:\\Temp\\namespace-only.";
	const std::wstring trailingSpacePath = L"C:\\Temp\\namespace-only ";
	const std::wstring leadingSpacePath = L"C:\\Temp\\ leading-space";
	const std::wstring leadingDotPath = L"C:\\Temp\\.leading-dot";
	const std::wstring trailingNbspPath = L"C:\\Temp\\nbsp-trailing\u00A0";
	const std::wstring reservedDevicePath = L"C:\\Temp\\NUL.txt";

	CHECK(LongPathSeams::PreparePathForLongPath(_T("C:\\Temp\\short.txt")) == LongPathSeams::PathString(_T("C:\\Temp\\short.txt")));
	CHECK(LongPathSeams::PreparePathForLongPath(_T("\\\\server\\share\\short.txt")) == LongPathSeams::PathString(_T("\\\\server\\share\\short.txt")));
	CHECK(LongPathSeams::PreparePathForLongPath(_T("\\\\?\\C:\\already-prefixed.txt")) == LongPathSeams::PathString(_T("\\\\?\\C:\\already-prefixed.txt")));

	CHECK(LongPathSeams::PreparePathForLongPath(longDriveAbsolute.c_str()) == LongPathTestSupport::PreparePathForLongPath(longDriveAbsolute));
	CHECK(LongPathSeams::PreparePathForLongPath(longUnc.c_str()) == LongPathTestSupport::PreparePathForLongPath(longUnc));
	CHECK(LongPathSeams::PreparePathForLongPath(longRelative.c_str()) == LongPathTestSupport::PreparePathForLongPath(longRelative));
	CHECK(LongPathSeams::PreparePathForLongPath(longDriveRelative.c_str()) == LongPathTestSupport::PreparePathForLongPath(longDriveRelative));
	CHECK(LongPathSeams::PreparePathForLongPath(longRootRelative.c_str()) == LongPathTestSupport::PreparePathForLongPath(longRootRelative));
	CHECK(LongPathSeams::PreparePathForLongPath(longDriveForwardSlash.c_str()) == LongPathTestSupport::PreparePathForLongPath(longDriveForwardSlash));
	CHECK(LongPathSeams::PreparePathForLongPath(trailingDotPath.c_str()) == LongPathTestSupport::PreparePathForLongPath(trailingDotPath));
	CHECK(LongPathSeams::PreparePathForLongPath(trailingSpacePath.c_str()) == LongPathTestSupport::PreparePathForLongPath(trailingSpacePath));
	CHECK(LongPathSeams::PreparePathForLongPath(leadingSpacePath.c_str()) == LongPathTestSupport::PreparePathForLongPath(leadingSpacePath));
	CHECK(LongPathSeams::PreparePathForLongPath(leadingDotPath.c_str()) == LongPathTestSupport::PreparePathForLongPath(leadingDotPath));
	CHECK(LongPathSeams::PreparePathForLongPath(trailingNbspPath.c_str()) == LongPathTestSupport::PreparePathForLongPath(trailingNbspPath));
	CHECK(LongPathSeams::PreparePathForLongPath(reservedDevicePath.c_str()) == LongPathTestSupport::PreparePathForLongPath(reservedDevicePath));
}

TEST_CASE("Long-path seam reads deterministic generated payloads from overlong unicode paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 65537u, 0xA17E5u));

	FILE *pStream = LongPathSeams::OpenFileStreamSharedReadLongPath(fixture.FilePath().c_str(), false);
	REQUIRE(pStream != NULL);
	const std::vector<BYTE> bytes = ReadBytesFromStream(pStream);
	fclose(pStream);

	CHECK(bytes == fixture.Payload());
	CHECK(LongPathTestSupport::ComputeFnv1a64(bytes) == fixture.PayloadFnv1a64());
}

TEST_CASE("Long-path seam opens CRT descriptors for overlong unicode paths and preserves golden vectors")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 32791u, 0x51A73u));

	const int fd = LongPathSeams::OpenCrtReadOnlyLongPath(fixture.FilePath().c_str());
	REQUIRE(fd != -1);
	const std::vector<BYTE> bytes = ReadBytesFromFd(fd);
	_close(fd);

	CHECK(bytes == fixture.Payload());
	CHECK(LongPathTestSupport::ComputeFnv1a64(bytes) == fixture.PayloadFnv1a64());
}

TEST_CASE("Long-path seam opens CRT write descriptors for overlong unicode paths and preserves golden vectors")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x44CC11u));

	const std::wstring writtenPath = fixture.MakeSiblingPath(L".fdwrite");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(5003u, 0x314159u);

	const int fd = LongPathSeams::OpenCrtWriteOnlyLongPath(writtenPath.c_str());
	REQUIRE(fd != -1);
	REQUIRE(_write(fd, payload.data(), static_cast<unsigned int>(payload.size())) == static_cast<int>(payload.size()));
	REQUIRE(_close(fd) == 0);

	std::vector<BYTE> bytes;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(writtenPath, bytes));
	CHECK(bytes == payload);
	CHECK(LongPathTestSupport::ComputeFnv1a64(bytes) == LongPathTestSupport::ComputeFnv1a64(payload));
	REQUIRE(LongPathSeams::DeleteFile(writtenPath.c_str()) != FALSE);
}

TEST_CASE("Long-path seam reads and writes whole-file byte buffers on overlong unicode paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x110022u));

	const std::wstring blobPath = fixture.MakeSiblingPath(L".blob");
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(7001u, 0xABC123u);

	REQUIRE(LongPathSeams::WriteAllBytes(blobPath.c_str(), payload));

	std::vector<unsigned char> loadedBytes;
	REQUIRE(LongPathSeams::ReadAllBytes(blobPath.c_str(), loadedBytes));
	std::vector<BYTE> roundTripBytes(loadedBytes.begin(), loadedBytes.end());
	CHECK_EQ(roundTripBytes.size(), payload.size());
	CHECK(std::equal(roundTripBytes.begin(), roundTripBytes.end(), payload.begin()));
	CHECK_EQ(LongPathTestSupport::ComputeFnv1a64(roundTripBytes), LongPathTestSupport::ComputeFnv1a64(payload));

	DWORD dwHigh = 0;
	const DWORD dwLow = LongPathSeams::GetCompressedFileSize(blobPath.c_str(), &dwHigh);
	const DWORD dwCompressedSizeError = ::GetLastError();
	const bool bCompressedSizeOk = (dwLow != INVALID_FILE_SIZE) || (dwCompressedSizeError == NO_ERROR);
	CHECK(bCompressedSizeOk);
	const ULONGLONG nReportedSize = (static_cast<ULONGLONG>(dwHigh) << 32) | dwLow;
	CHECK_EQ(nReportedSize, static_cast<ULONGLONG>(payload.size()));

	REQUIRE(LongPathSeams::DeleteFileIfExists(blobPath.c_str()));
	CHECK_FALSE(LongPathSeams::PathExists(blobPath.c_str()));
}

TEST_CASE("Long-path seam treats missing parent directories as successful delete-no-op cleanup")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x778899u));

	const std::wstring missingPath = fixture.DirectoryPath() + L"\\missing_" + LongPathTestSupport::MakeSpecialSegment() + L"\\child.bin";
	CHECK(LongPathSeams::DeleteFileIfExists(missingPath.c_str()));
}

TEST_CASE("Long-path seam copies moves enumerates and deletes deterministic payloads on overlong unicode paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 8192u + 37u, 0x9F31u));

	const std::wstring copiedPath = fixture.MakeSiblingPath(L".copy");
	const std::wstring renamedPath = fixture.MakeSiblingPath(L".renamed");

	REQUIRE(LongPathSeams::CopyFile(fixture.FilePath().c_str(), copiedPath.c_str(), FALSE) != FALSE);
	REQUIRE(LongPathSeams::MoveFileEx(copiedPath.c_str(), renamedPath.c_str(), MOVEFILE_REPLACE_EXISTING) != FALSE);

	WIN32_FILE_ATTRIBUTE_DATA attributes = {};
	REQUIRE(LongPathSeams::GetFileAttributesEx(renamedPath.c_str(), GetFileExInfoStandard, &attributes) != FALSE);
	const ULONGLONG nFileSize = (static_cast<ULONGLONG>(attributes.nFileSizeHigh) << 32) | attributes.nFileSizeLow;
	CHECK_EQ(nFileSize, static_cast<ULONGLONG>(fixture.Payload().size()));

	std::vector<std::wstring> names;
	WIN32_FIND_DATA findData = {};
	const std::wstring searchPath = fixture.DirectoryPath() + L"\\*";
	HANDLE hFind = LongPathSeams::FindFirstFile(searchPath.c_str(), &findData);
	REQUIRE(hFind != INVALID_HANDLE_VALUE);
	do {
		const wchar_t *pszName = findData.cFileName;
		if (wcscmp(pszName, L".") != 0 && wcscmp(pszName, L"..") != 0)
			names.push_back(pszName);
	} while (::FindNextFile(hFind, &findData) != FALSE);
	REQUIRE(::GetLastError() == ERROR_NO_MORE_FILES);
	REQUIRE(::FindClose(hFind) != FALSE);
	std::sort(names.begin(), names.end());
	CHECK(std::find(names.begin(), names.end(), std::wstring(L"payload_") + LongPathTestSupport::MakeSpecialSegment() + L".bin") != names.end());
	CHECK(std::find(names.begin(), names.end(), std::wstring(L"payload_") + LongPathTestSupport::MakeSpecialSegment() + L".bin.renamed") != names.end());

	std::vector<BYTE> copiedBytes;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(renamedPath, copiedBytes));
	CHECK(copiedBytes == fixture.Payload());
	CHECK(LongPathTestSupport::ComputeFnv1a64(copiedBytes) == fixture.PayloadFnv1a64());

	REQUIRE(LongPathSeams::DeleteFile(renamedPath.c_str()) != FALSE);
	CHECK_FALSE(LongPathSeams::PathExists(renamedPath.c_str()));
}

TEST_CASE("Long-path seam preserves golden vectors across temp-file append move and backup flows")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x445566u));

	const std::wstring tempPath = fixture.MakeSiblingPath(L".tmp");
	const std::wstring finalPath = fixture.MakeSiblingPath(L".final");
	const std::wstring backupPath = fixture.MakeSiblingPath(L".bak");
	const std::vector<BYTE> firstPayload = LongPathTestSupport::BuildDeterministicPayload(6001u, 0x1234ABCDu);
	const std::vector<BYTE> secondPayload = LongPathTestSupport::BuildDeterministicPayload(4097u, 0x55AA7711u);

	FILE *pCreate = LongPathSeams::OpenFileStreamDenyWriteLongPath(tempPath.c_str(), _T("wb"));
	REQUIRE(pCreate != NULL);
	REQUIRE(fwrite(firstPayload.data(), 1, firstPayload.size(), pCreate) == firstPayload.size());
	REQUIRE(fclose(pCreate) == 0);

	FILE *pAppend = LongPathSeams::OpenFileStreamDenyWriteLongPath(tempPath.c_str(), _T("ab"));
	REQUIRE(pAppend != NULL);
	REQUIRE(fwrite(secondPayload.data(), 1, secondPayload.size(), pAppend) == secondPayload.size());
	REQUIRE(fclose(pAppend) == 0);

	REQUIRE(LongPathSeams::MoveFileWithProgress(tempPath.c_str(), finalPath.c_str(), NULL, NULL, MOVEFILE_REPLACE_EXISTING) != FALSE);
	REQUIRE(LongPathSeams::CopyFile(finalPath.c_str(), backupPath.c_str(), FALSE) != FALSE);

	std::vector<BYTE> expected = firstPayload;
	expected.insert(expected.end(), secondPayload.begin(), secondPayload.end());

	std::vector<unsigned char> finalBytesRaw;
	REQUIRE(LongPathSeams::ReadAllBytes(finalPath.c_str(), finalBytesRaw));
	const std::vector<BYTE> finalBytes(finalBytesRaw.begin(), finalBytesRaw.end());
	CHECK(finalBytes == expected);
	CHECK(LongPathTestSupport::ComputeFnv1a64(finalBytes) == LongPathTestSupport::ComputeFnv1a64(expected));

	std::vector<BYTE> backupBytes;
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(backupPath, backupBytes));
	CHECK(backupBytes == expected);
	CHECK(LongPathTestSupport::ComputeFnv1a64(backupBytes) == LongPathTestSupport::ComputeFnv1a64(expected));

	REQUIRE(LongPathSeams::DeleteFileIfExists(finalPath.c_str()));
	REQUIRE(LongPathSeams::DeleteFileIfExists(backupPath.c_str()));
	CHECK_FALSE(LongPathSeams::PathExists(finalPath.c_str()));
	CHECK_FALSE(LongPathSeams::PathExists(backupPath.c_str()));
}

TEST_CASE("Long-path seam handles special-character short paths without changing the golden payload")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 12345u, 0x20260409u));

	FILE *pStream = LongPathSeams::OpenFileStreamSharedReadLongPath(fixture.FilePath().c_str(), false);
	REQUIRE(pStream != NULL);
	const std::vector<BYTE> bytes = ReadBytesFromStream(pStream);
	fclose(pStream);

	CHECK(bytes == fixture.Payload());
	CHECK(LongPathTestSupport::ComputeFnv1a64(bytes) == fixture.PayloadFnv1a64());
}

TEST_CASE("Long-path seam preserves exact dot and whitespace names for files and folders on real filesystem paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x20260413u));

	unsigned int uSeed = 0x31415000u;
	for (const SpecialNameCase &nameCase : GetSpecialNameCases()) {
		const std::wstring directoryPath = fixture.DirectoryPath() + L"\\" + nameCase.pszDirectoryName;
		const std::wstring filePath = directoryPath + L"\\" + nameCase.pszFileName;
		const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(257u + (uSeed & 0x3Fu), uSeed++);

		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(directoryPath));
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(filePath, payload));

		std::vector<std::wstring> rootNames;
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::EnumerateFileNames(fixture.DirectoryPath(), rootNames));
		CHECK(std::find(rootNames.begin(), rootNames.end(), std::wstring(nameCase.pszDirectoryName)) != rootNames.end());

		std::vector<std::wstring> childNames;
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::EnumerateFileNames(directoryPath, childNames));
		CHECK(std::find(childNames.begin(), childNames.end(), std::wstring(nameCase.pszFileName)) != childNames.end());

		std::vector<BYTE> loaded;
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::ReadBytes(filePath, loaded));
		CHECK(loaded == payload);
		CHECK(LongPathTestSupport::RequiresExtendedLengthPathForExactName(filePath) == nameCase.bRequiresExactNamespace);

		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(filePath));
		REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(directoryPath));
	}
}

TEST_CASE("Long-path seam preserves leading-space and reserved-name short paths without relying on path length")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 0u, 0x20260417u));

	const std::wstring leadingSpaceDirectory = fixture.DirectoryPath() + L"\\ leading-space-dir";
	const std::wstring leadingSpaceFile = leadingSpaceDirectory + L"\\ leading-space-file.bin";
	const std::wstring reservedDirectory = fixture.DirectoryPath() + L"\\reserved-device-dir";
	const std::wstring reservedFile = reservedDirectory + L"\\NUL.txt";

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(leadingSpaceDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(leadingSpaceFile, LongPathTestSupport::BuildDeterministicPayload(73u, 0x17A1u)));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(reservedDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(reservedFile, LongPathTestSupport::BuildDeterministicPayload(91u, 0x17B2u)));

	CHECK(LongPathSeams::PreparePathForLongPath(leadingSpaceDirectory.c_str()).rfind(L"\\\\?\\", 0) == 0);
	CHECK(LongPathSeams::PreparePathForLongPath(reservedFile.c_str()).rfind(L"\\\\?\\", 0) == 0);
	CHECK(LongPathSeams::PathExists(leadingSpaceFile.c_str()));
	CHECK(LongPathSeams::PathExists(reservedFile.c_str()));

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(leadingSpaceFile));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(leadingSpaceDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(reservedFile));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(reservedDirectory));
}

TEST_CASE("Long-path seam enumerates wildcard matches inside exact-name and reserved-name directories")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 0u, 0x20260418u));

	const std::wstring exactDirectory = fixture.DirectoryPath() + L"\\ leading-space-dir";
	const std::wstring reservedDirectory = fixture.DirectoryPath() + L"\\reserved-device-dir";
	const std::wstring exactFile = exactDirectory + L"\\alpha.bin";
	const std::wstring exactIgnored = exactDirectory + L"\\beta.txt";
	const std::wstring reservedFile = reservedDirectory + L"\\NUL.bin";
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(exactDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(reservedDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(exactFile, LongPathTestSupport::BuildDeterministicPayload(29u, 0x18A1u)));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(exactIgnored, LongPathTestSupport::BuildDeterministicPayload(31u, 0x18A2u)));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(reservedFile, LongPathTestSupport::BuildDeterministicPayload(37u, 0x18A3u)));

	std::vector<std::wstring> exactNames;
	WIN32_FIND_DATAW findData = {};
	HANDLE hFind = LongPathSeams::FindFirstFile((exactDirectory + L"\\*.bin").c_str(), &findData);
	REQUIRE(hFind != INVALID_HANDLE_VALUE);
	do {
		if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0)
			exactNames.push_back(findData.cFileName);
	} while (::FindNextFileW(hFind, &findData) != FALSE);
	REQUIRE(::GetLastError() == ERROR_NO_MORE_FILES);
	REQUIRE(::FindClose(hFind) != FALSE);

	CHECK(std::find(exactNames.begin(), exactNames.end(), std::wstring(L"alpha.bin")) != exactNames.end());
	CHECK(std::find(exactNames.begin(), exactNames.end(), std::wstring(L"beta.txt")) == exactNames.end());

	std::vector<std::wstring> reservedNames;
	WIN32_FIND_DATAW reservedFindData = {};
	HANDLE hReservedFind = LongPathSeams::FindFirstFile((reservedDirectory + L"\\*.bin").c_str(), &reservedFindData);
	REQUIRE(hReservedFind != INVALID_HANDLE_VALUE);
	do {
		if (wcscmp(reservedFindData.cFileName, L".") != 0 && wcscmp(reservedFindData.cFileName, L"..") != 0)
			reservedNames.push_back(reservedFindData.cFileName);
	} while (::FindNextFileW(hReservedFind, &reservedFindData) != FALSE);
	REQUIRE(::GetLastError() == ERROR_NO_MORE_FILES);
	REQUIRE(::FindClose(hReservedFind) != FALSE);

	CHECK(std::find(reservedNames.begin(), reservedNames.end(), std::wstring(L"NUL.bin")) != reservedNames.end());

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(exactFile));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(exactIgnored));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(reservedFile));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(exactDirectory));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::RemoveDirectoryPath(reservedDirectory));
}

TEST_CASE("Long-path seam rejects tab-prefixed and tab-suffixed names as invalid Win32 filenames")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 0u, 0x20260414u));

	const std::wstring invalidDirectory = fixture.DirectoryPath() + L"\\\tinvalid-dir";
	CHECK_FALSE(LongPathTestSupport::ScopedLongPathFixture::CreateDirectoryPath(invalidDirectory));
	CHECK(::GetLastError() == ERROR_INVALID_NAME);

	const std::wstring invalidFile = fixture.DirectoryPath() + L"\\invalid-file\t";
	const HANDLE hFile = ::CreateFileW(LongPathTestSupport::PreparePathForLongPath(invalidFile).c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	CHECK(hFile == INVALID_HANDLE_VALUE);
	CHECK(::GetLastError() == ERROR_INVALID_NAME);
}

TEST_CASE("Long-path seam supports deny-write FILE streams for create append and reread on overlong unicode paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x55AA11u));

	const std::wstring streamPath = fixture.MakeSiblingPath(L".stream");
	const std::vector<BYTE> firstPayload = LongPathTestSupport::BuildDeterministicPayload(4096u + 19u, 0x13579u);
	const std::vector<BYTE> secondPayload = LongPathTestSupport::BuildDeterministicPayload(1024u + 7u, 0x24680u);

	FILE *pCreate = LongPathSeams::OpenFileStreamDenyWriteLongPath(streamPath.c_str(), _T("wb"));
	REQUIRE(pCreate != NULL);
	REQUIRE(fwrite(firstPayload.data(), 1, firstPayload.size(), pCreate) == firstPayload.size());
	REQUIRE(fclose(pCreate) == 0);

	FILE *pAppend = LongPathSeams::OpenFileStreamDenyWriteLongPath(streamPath.c_str(), _T("ab"));
	REQUIRE(pAppend != NULL);
	REQUIRE(fwrite(secondPayload.data(), 1, secondPayload.size(), pAppend) == secondPayload.size());
	REQUIRE(fclose(pAppend) == 0);

	FILE *pRead = LongPathSeams::OpenFileStreamDenyWriteLongPath(streamPath.c_str(), _T("rb"));
	REQUIRE(pRead != NULL);
	const std::vector<BYTE> combinedBytes = ReadBytesFromStream(pRead);
	fclose(pRead);

	std::vector<BYTE> expected = firstPayload;
	expected.insert(expected.end(), secondPayload.begin(), secondPayload.end());
	CHECK(combinedBytes == expected);
	REQUIRE(LongPathSeams::DeleteFile(streamPath.c_str()) != FALSE);
}

TEST_CASE("Long-path seam creates overlong unicode directories before file operations")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 128u, 0xACEu));

	std::wstring longDir = fixture.DirectoryPath() + L"\\generated_" + LongPathTestSupport::MakeSpecialSegment();
	while (longDir.size() < MAX_PATH + 20u) {
		longDir += L"\\segment_";
		longDir += LongPathTestSupport::MakeSpecialSegment();
	}

	for (size_t i = fixture.DirectoryPath().size() + 1u; i < longDir.size(); ++i) {
		if (longDir[i] != L'\\')
			continue;
		const std::wstring incrementalPath = longDir.substr(0, i);
		const bool bExistsOrCreated = LongPathSeams::PathExists(incrementalPath.c_str()) || LongPathSeams::CreateDirectory(incrementalPath.c_str());
		REQUIRE(bExistsOrCreated);
	}
	const bool bFinalExistsOrCreated = LongPathSeams::PathExists(longDir.c_str()) || LongPathSeams::CreateDirectory(longDir.c_str());
	REQUIRE(bFinalExistsOrCreated);
	CHECK(LongPathSeams::PathExists(longDir.c_str()));

	for (std::wstring current = longDir; current.size() > fixture.DirectoryPath().size(); ) {
		REQUIRE(::RemoveDirectoryW(LongPathTestSupport::PreparePathForLongPath(current).c_str()) != FALSE);
		const size_t nLastSlash = current.find_last_of(L'\\');
		REQUIRE(nLastSlash != std::wstring::npos);
		current.erase(nLastSlash);
	}
}

TEST_CASE("Long-path seam normalizes overlong forward-slash paths for directory and payload round-trips")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(false, 0u, 0xA1B2C3u));

	std::wstring longDir = fixture.DirectoryPath() + L"\\forward_" + LongPathTestSupport::MakeSpecialSegment();
	while (longDir.size() < MAX_PATH + 40u) {
		longDir += L"\\segment_";
		longDir += LongPathTestSupport::MakeSpecialSegment();
	}
	std::wstring forwardSlashDir = longDir;
	std::replace(forwardSlashDir.begin(), forwardSlashDir.end(), L'\\', L'/');
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::EnsureDirectoryTree(fixture.DirectoryPath(), longDir));
	CHECK(LongPathSeams::PathExists(forwardSlashDir.c_str()));

	const std::wstring filePath = longDir + L"\\payload.bin";
	std::wstring forwardSlashFilePath = filePath;
	std::replace(forwardSlashFilePath.begin(), forwardSlashFilePath.end(), L'\\', L'/');
	const std::vector<BYTE> payload = LongPathTestSupport::BuildDeterministicPayload(5432u, 0xCAFEBABEu);
	REQUIRE(LongPathSeams::WriteAllBytes(forwardSlashFilePath.c_str(), payload));

	std::vector<unsigned char> loadedRaw;
	REQUIRE(LongPathSeams::ReadAllBytes(forwardSlashFilePath.c_str(), loadedRaw));
	const std::vector<BYTE> loaded(loadedRaw.begin(), loadedRaw.end());
	CHECK(loaded == payload);
	CHECK(LongPathTestSupport::ComputeFnv1a64(loaded) == LongPathTestSupport::ComputeFnv1a64(payload));

	REQUIRE(LongPathSeams::DeleteFileIfExists(forwardSlashFilePath.c_str()));
	for (std::wstring current = longDir; current.size() > fixture.DirectoryPath().size(); ) {
		REQUIRE(::RemoveDirectoryW(LongPathTestSupport::PreparePathForLongPath(current).c_str()) != FALSE);
		const size_t nLastSlash = current.find_last_of(L'\\');
		REQUIRE(nLastSlash != std::wstring::npos);
		current.erase(nLastSlash);
	}
}

TEST_SUITE_END;
