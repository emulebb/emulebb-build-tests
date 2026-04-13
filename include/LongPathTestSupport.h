#pragma once

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <string>
#include <vector>
#include <windows.h>

namespace LongPathTestSupport
{
constexpr size_t kCreateDirectoryLegacyHeadroom = 12u;

/**
 * @brief Normalizes forward slashes to backslashes before building reference extended-length DOS/UNC paths.
 */
inline std::wstring NormalizeAbsolutePathSeparators(const std::wstring &path)
{
	std::wstring normalized(path);
	std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
	return normalized;
}

/**
 * @brief Returns true when the character is treated as a Win32 path separator.
 */
inline bool IsPathSeparator(const wchar_t ch)
{
	return ch == L'\\' || ch == L'/';
}

/**
 * @brief Returns a mixed Cyrillic and emoji path segment to stress Unicode handling in real-FS tests.
 */
inline std::wstring MakeSpecialSegment()
{
	return std::wstring(L"\x043A\x0438\x0440\x0438\x043B\x043B\x0438\x0446\x0430_") + std::wstring(L"\xD83D") + std::wstring(L"\xDE80");
}

/**
 * @brief Detects whether a wide path already carries an extended-length prefix.
 */
inline bool HasLongPathPrefix(const std::wstring &path)
{
	return path.rfind(L"\\\\?\\", 0) == 0;
}

/**
 * @brief Removes an existing extended-length prefix so tests can inspect the logical DOS/UNC path text.
 */
inline std::wstring StripLongPathPrefix(const std::wstring &path)
{
	const std::wstring normalized = NormalizeAbsolutePathSeparators(path);
	if (normalized.rfind(L"\\\\?\\UNC\\", 0) == 0)
		return std::wstring(L"\\\\") + normalized.substr(8);
	if (normalized.rfind(L"\\\\?\\", 0) == 0)
		return normalized.substr(4);
	return normalized;
}

/**
 * @brief Returns true for fully qualified DOS drive paths such as `C:\dir\file`.
 */
inline bool IsDriveAbsolutePath(const std::wstring &path)
{
	if (path.size() < 3)
		return false;
	const wchar_t chDrive = path[0];
	return ((chDrive >= L'A' && chDrive <= L'Z') || (chDrive >= L'a' && chDrive <= L'z'))
		&& path[1] == L':'
		&& (path[2] == L'\\' || path[2] == L'/');
}

/**
 * @brief Returns true for UNC paths that can be converted to `\\?\UNC\...`.
 */
inline bool IsUncPath(const std::wstring &path)
{
	return path.size() > 2 && path[0] == L'\\' && path[1] == L'\\' && path[2] != L'?' && path[2] != L'.';
}

/**
 * @brief Returns true when any logical path component ends with a space or period and therefore needs namespace semantics.
 */
inline bool RequiresExtendedLengthPathForExactName(const std::wstring &path)
{
	if (path.empty())
		return false;

	const std::wstring logicalPath = StripLongPathPrefix(path);
	size_t iIndex = 0;
	while (iIndex < logicalPath.size()) {
		while (iIndex < logicalPath.size() && IsPathSeparator(logicalPath[iIndex]))
			++iIndex;
		if (iIndex >= logicalPath.size())
			break;

		const size_t iStart = iIndex;
		while (iIndex < logicalPath.size() && !IsPathSeparator(logicalPath[iIndex]))
			++iIndex;

		const std::wstring segment = logicalPath.substr(iStart, iIndex - iStart);
		if (!segment.empty()
			&& segment != L"."
			&& segment != L".."
			&& (segment.back() == L' ' || segment.back() == L'.'))
		{
			return true;
		}
	}

	return false;
}

/**
 * @brief Applies the reference extended-length prefix policy used by the real-FS tests and probes.
 */
inline std::wstring PreparePathForLongPath(const std::wstring &path)
{
	if (path.empty() || HasLongPathPrefix(path))
		return path;
	const std::wstring normalized = NormalizeAbsolutePathSeparators(path);
	const bool bRequiresExactNamePrefix = RequiresExtendedLengthPathForExactName(normalized);
	if (normalized.size() < MAX_PATH && !bRequiresExactNamePrefix)
		return path;
	if (!IsDriveAbsolutePath(normalized) && !IsUncPath(normalized))
		return path;
	if (IsUncPath(normalized))
		return std::wstring(L"\\\\?\\UNC\\") + normalized.substr(2);
	return std::wstring(L"\\\\?\\") + normalized;
}

/**
 * @brief Prepares directory-create paths early enough to dodge the legacy create headroom limit.
 */
inline std::wstring PrepareDirectoryCreatePathForLongPath(const std::wstring &path)
{
	if (path.empty() || HasLongPathPrefix(path))
		return path;
	const std::wstring normalized = NormalizeAbsolutePathSeparators(path);
	const bool bRequiresExactNamePrefix = RequiresExtendedLengthPathForExactName(normalized);
	if (normalized.size() + kCreateDirectoryLegacyHeadroom < MAX_PATH && !bRequiresExactNamePrefix)
		return path;
	if (!IsDriveAbsolutePath(normalized) && !IsUncPath(normalized))
		return path;
	if (IsUncPath(normalized))
		return std::wstring(L"\\\\?\\UNC\\") + normalized.substr(2);
	return std::wstring(L"\\\\?\\") + normalized;
}

/**
 * @brief Returns the preferred real-FS root used for long-path regression scenarios.
 */
inline std::wstring PreferredFixtureRoot()
{
	return std::wstring(L"C:\\tmp\\00_long_paths\\emule-longpath-tests");
}

/**
 * @brief Queries the DOS 8.3 short-name alias for an existing path when the volume exposes one.
 */
inline bool TryGetShortPathAlias(const std::wstring &path, std::wstring &aliasOut)
{
	aliasOut.clear();
	if (path.empty())
		return false;

	const std::wstring preparedPath = PreparePathForLongPath(path);
	DWORD cchRequired = ::GetShortPathNameW(preparedPath.c_str(), NULL, 0);
	if (cchRequired == 0)
		return false;

	std::vector<wchar_t> buffer(static_cast<size_t>(cchRequired), L'\0');
	const DWORD cchWritten = ::GetShortPathNameW(preparedPath.c_str(), buffer.data(), cchRequired);
	if (cchWritten == 0 || cchWritten >= cchRequired)
		return false;

	aliasOut.assign(buffer.data(), cchWritten);
	return !aliasOut.empty() && _wcsicmp(aliasOut.c_str(), path.c_str()) != 0;
}

/**
 * @brief Builds deterministic binary payloads so real-FS tests can assert exact golden vectors.
 */
inline std::vector<BYTE> BuildDeterministicPayload(const size_t nByteCount, const std::uint32_t nSeed)
{
	std::vector<BYTE> payload(nByteCount);
	std::uint32_t state = nSeed ? nSeed : 0xC0FFEE11u;
	for (size_t i = 0; i < nByteCount; ++i) {
		state = state * 1664525u + 1013904223u;
		payload[i] = static_cast<BYTE>((state >> 16) & 0xFFu);
	}
	return payload;
}

/**
 * @brief Computes a stable FNV-1a golden vector over a byte payload.
 */
inline std::uint64_t ComputeFnv1a64(const std::vector<BYTE> &payload)
{
	std::uint64_t value = 1469598103934665603ull;
	for (const BYTE byteValue : payload) {
		value ^= static_cast<std::uint64_t>(byteValue);
		value *= 1099511628211ull;
	}
	return value;
}

/**
 * @brief Owns a temporary Unicode-heavy fixture tree and deterministic payload file for long-path integration tests.
 */
class ScopedLongPathFixture
{
public:
	/**
	 * @brief Creates the temporary directory tree and writes the deterministic payload file.
	 */
	bool Initialize(const bool bMakeLongPath, const size_t nPayloadBytes, const std::uint32_t nSeed)
	{
		m_directories.clear();
		m_payload = BuildDeterministicPayload(nPayloadBytes, nSeed);
		m_dwLastError = ERROR_SUCCESS;

		const std::wstring root = PreferredFixtureRoot();
		if (!EnsureDirectoryTree(std::wstring(L"C:\\"), root)) {
			m_dwLastError = ::GetLastError();
			return false;
		}
		if (!CreateDirectoryIfNeeded(root))
			return false;
		m_directories.push_back(root);

		std::wstring current = root + L"\\" + MakeSpecialSegment();
		if (!CreateDirectoryIfNeeded(current))
			return false;
		m_directories.push_back(current);

		if (bMakeLongPath) {
			while (current.size() < MAX_PATH + 48u) {
				current += L"\\segment_";
				current += MakeSpecialSegment();
				if (!CreateDirectoryIfNeeded(current))
					return false;
				m_directories.push_back(current);
			}
		}

		m_directoryPath = current;
		m_filePath = current + L"\\payload_" + MakeSpecialSegment() + L".bin";
		if (!WriteBytes(m_filePath, m_payload)) {
			m_dwLastError = ::GetLastError();
			return false;
		}
		return true;
	}

	/**
	 * @brief Deletes the fixture file and all directories created by `Initialize`.
	 */
	~ScopedLongPathFixture()
	{
		if (!m_filePath.empty())
			(void)::DeleteFileW(PreparePathForLongPath(m_filePath).c_str());

		for (std::vector<std::wstring>::reverse_iterator it = m_directories.rbegin(); it != m_directories.rend(); ++it)
			(void)::RemoveDirectoryW(PreparePathForLongPath(*it).c_str());
	}

	/**
	 * @brief Returns the full path to the deterministic payload file.
	 */
	const std::wstring &FilePath() const
	{
		return m_filePath;
	}

	/**
	 * @brief Returns the deepest directory path that owns the payload file.
	 */
	const std::wstring &DirectoryPath() const
	{
		return m_directoryPath;
	}

	/**
	 * @brief Builds a sibling file path beside the payload file.
	 */
	std::wstring MakeSiblingPath(const wchar_t *pszSuffix) const
	{
		return m_filePath + (pszSuffix != NULL ? pszSuffix : L"");
	}

	/**
	 * @brief Builds a child path inside the fixture directory.
	 */
	std::wstring MakeDirectoryChildPath(const wchar_t *pszLeafName) const
	{
		return m_directoryPath + L"\\" + (pszLeafName != NULL ? pszLeafName : L"");
	}

	/**
	 * @brief Returns the deterministic payload bytes written by the fixture.
	 */
	const std::vector<BYTE> &Payload() const
	{
		return m_payload;
	}

	/**
	 * @brief Returns the expected FNV-1a golden vector for the fixture payload.
	 */
	std::uint64_t PayloadFnv1a64() const
	{
		return ComputeFnv1a64(m_payload);
	}

	/**
	 * @brief Returns the last Win32 error captured during fixture setup.
	 */
	DWORD LastError() const
	{
		return m_dwLastError;
	}

	/**
	 * @brief Writes raw bytes to disk through the reference long-path preparation helper.
	 */
	static bool WriteBytes(const std::wstring &path, const std::vector<BYTE> &payload)
	{
		HANDLE hFile = ::CreateFileW(PreparePathForLongPath(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return false;

		DWORD dwWritten = 0;
		const bool bOk = payload.empty() || (::WriteFile(hFile, payload.data(), static_cast<DWORD>(payload.size()), &dwWritten, NULL) != FALSE && dwWritten == payload.size());
		const DWORD dwCloseError = (::CloseHandle(hFile) != FALSE) ? ERROR_SUCCESS : ::GetLastError();
		if (!bOk) {
			::SetLastError(::GetLastError());
			return false;
		}
		if (dwCloseError != ERROR_SUCCESS) {
			::SetLastError(dwCloseError);
			return false;
		}
		return true;
	}

	/**
	 * @brief Reads the entire file into memory through the reference long-path preparation helper.
	 */
	static bool ReadBytes(const std::wstring &path, std::vector<BYTE> &payloadOut)
	{
		payloadOut.clear();

		HANDLE hFile = ::CreateFileW(PreparePathForLongPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return false;

		LARGE_INTEGER fileSize = {};
		if (::GetFileSizeEx(hFile, &fileSize) == FALSE || fileSize.QuadPart < 0) {
			const DWORD dwError = ::GetLastError();
			::CloseHandle(hFile);
			::SetLastError(dwError);
			return false;
		}

		payloadOut.resize(static_cast<size_t>(fileSize.QuadPart));
		DWORD dwRead = 0;
		const bool bOk = payloadOut.empty() || (::ReadFile(hFile, payloadOut.data(), static_cast<DWORD>(payloadOut.size()), &dwRead, NULL) != FALSE && dwRead == payloadOut.size());
		const DWORD dwCloseError = (::CloseHandle(hFile) != FALSE) ? ERROR_SUCCESS : ::GetLastError();
		if (!bOk) {
			::SetLastError(::GetLastError());
			return false;
		}
		if (dwCloseError != ERROR_SUCCESS) {
			::SetLastError(dwCloseError);
			return false;
		}
		return true;
	}

	/**
	 * @brief Appends raw bytes to disk through the reference long-path preparation helper.
	 */
	static bool AppendBytes(const std::wstring &path, const std::vector<BYTE> &payload)
	{
		HANDLE hFile = ::CreateFileW(PreparePathForLongPath(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return false;

		LARGE_INTEGER endOfFile = {};
		const bool bSeekOk = (::SetFilePointerEx(hFile, endOfFile, NULL, FILE_END) != FALSE);
		DWORD dwWritten = 0;
		const bool bWriteOk = payload.empty() || (::WriteFile(hFile, payload.data(), static_cast<DWORD>(payload.size()), &dwWritten, NULL) != FALSE && dwWritten == payload.size());
		const DWORD dwWriteError = bWriteOk ? ERROR_SUCCESS : ::GetLastError();
		const DWORD dwCloseError = (::CloseHandle(hFile) != FALSE) ? ERROR_SUCCESS : ::GetLastError();
		if (!bSeekOk) {
			::SetLastError(::GetLastError());
			return false;
		}
		if (!bWriteOk) {
			::SetLastError(dwWriteError);
			return false;
		}
		if (dwCloseError != ERROR_SUCCESS) {
			::SetLastError(dwCloseError);
			return false;
		}
		return true;
	}

	/**
	 * @brief Enumerates directory entries for the fixture root using a long-path-safe search path.
	 */
	static bool EnumerateFileNames(const std::wstring &directoryPath, std::vector<std::wstring> &namesOut)
	{
		namesOut.clear();

		const std::wstring searchPath = directoryPath + L"\\*";
		WIN32_FIND_DATAW findData = {};
		HANDLE hFind = ::FindFirstFileW(PreparePathForLongPath(searchPath).c_str(), &findData);
		if (hFind == INVALID_HANDLE_VALUE)
			return false;

		do {
			const wchar_t *pszName = findData.cFileName;
			if (wcscmp(pszName, L".") != 0 && wcscmp(pszName, L"..") != 0)
				namesOut.push_back(pszName);
		} while (::FindNextFileW(hFind, &findData) != FALSE);

		const DWORD dwLastError = ::GetLastError();
		(void)::FindClose(hFind);
		if (dwLastError != ERROR_NO_MORE_FILES) {
			::SetLastError(dwLastError);
			return false;
		}

		std::sort(namesOut.begin(), namesOut.end());
		return true;
	}

	/**
	 * @brief Creates every path segment under the provided root using the reference directory-create rule.
	 */
	static bool EnsureDirectoryTree(const std::wstring &rootPath, const std::wstring &directoryPath)
	{
		if (directoryPath.size() < rootPath.size() || directoryPath.compare(0, rootPath.size(), rootPath) != 0)
			return false;

		for (size_t i = rootPath.size() + 1u; i < directoryPath.size(); ++i) {
			if (directoryPath[i] != L'\\')
				continue;
			const std::wstring incrementalPath = directoryPath.substr(0, i);
			if (::CreateDirectoryW(PrepareDirectoryCreatePathForLongPath(incrementalPath).c_str(), NULL) == FALSE && ::GetLastError() != ERROR_ALREADY_EXISTS)
				return false;
		}

		return ::CreateDirectoryW(PrepareDirectoryCreatePathForLongPath(directoryPath).c_str(), NULL) != FALSE || ::GetLastError() == ERROR_ALREADY_EXISTS;
	}

	/**
	 * @brief Deletes a file through the reference long-path preparation helper.
	 */
	static bool DeleteFilePath(const std::wstring &path)
	{
		return ::DeleteFileW(PreparePathForLongPath(path).c_str()) != FALSE;
	}

	/**
	 * @brief Creates a directory through the reference long-path preparation helper.
	 */
	static bool CreateDirectoryPath(const std::wstring &path)
	{
		return ::CreateDirectoryW(PrepareDirectoryCreatePathForLongPath(path).c_str(), NULL) != FALSE || ::GetLastError() == ERROR_ALREADY_EXISTS;
	}

	/**
	 * @brief Removes a directory through the reference long-path preparation helper.
	 */
	static bool RemoveDirectoryPath(const std::wstring &path)
	{
		return ::RemoveDirectoryW(PreparePathForLongPath(path).c_str()) != FALSE;
	}

	/**
	 * @brief Renames or moves a file through the reference long-path preparation helper.
	 */
	static bool MoveFileReplace(const std::wstring &existingPath, const std::wstring &newPath)
	{
		return ::MoveFileExW(PreparePathForLongPath(existingPath).c_str(), PreparePathForLongPath(newPath).c_str(), MOVEFILE_REPLACE_EXISTING) != FALSE;
	}

	/**
	 * @brief Copies a file through the reference long-path preparation helper.
	 */
	static bool CopyFilePath(const std::wstring &existingPath, const std::wstring &newPath, const bool bFailIfExists)
	{
		return ::CopyFileW(PreparePathForLongPath(existingPath).c_str(), PreparePathForLongPath(newPath).c_str(), bFailIfExists ? TRUE : FALSE) != FALSE;
	}

private:
	/**
	 * @brief Creates a directory once and treats `already exists` as success during fixture setup.
	 */
	bool CreateDirectoryIfNeeded(const std::wstring &path)
	{
		if (::CreateDirectoryW(PrepareDirectoryCreatePathForLongPath(path).c_str(), NULL) != FALSE)
			return true;

		m_dwLastError = ::GetLastError();
		return m_dwLastError == ERROR_ALREADY_EXISTS;
	}

	std::vector<std::wstring> m_directories;
	std::wstring m_directoryPath;
	std::wstring m_filePath;
	std::vector<BYTE> m_payload;
	DWORD m_dwLastError = ERROR_SUCCESS;
};
}
