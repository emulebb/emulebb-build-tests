#include "../third_party/doctest/doctest.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#if defined(__has_include)
#if __has_include("MappedFileReader.h")
#include "MappedFileReader.h"
#define EMULEBB_TEST_HAVE_MAPPED_FILE_READER 1
#else
#define EMULEBB_TEST_HAVE_MAPPED_FILE_READER 0
#endif
#else
#define EMULEBB_TEST_HAVE_MAPPED_FILE_READER 0
#endif

namespace
{
	constexpr size_t HASH_BUFFER_SIZE = 8192u;
	constexpr unsigned long long PARTSIZE_BYTES = 9728000ull;
	constexpr size_t EMBLOCKSIZE_BYTES = 184320u;
	constexpr unsigned long long DETERMINISTIC_SAMPLE_SEED = 0x4d46524d41505045ull;

	using CMd4Digest = std::array<BYTE, 16>;
	using CSha1Digest = std::array<BYTE, 20>;

	enum class EReaderMode
	{
		Buffered,
		Win32,
		Mapped
	};

	struct CSampledFile
	{
		std::wstring Path;
		unsigned long long Length = 0;
	};

	struct CFileHashArtifacts
	{
		unsigned long long Length = 0;
		CMd4Digest FileMd4 = {};
		CSha1Digest AichMaster = {};
		std::vector<CMd4Digest> Md4PartHashes;
		std::vector<CSha1Digest> AichPartHashes;

		bool operator==(const CFileHashArtifacts &rhs) const
		{
			return Length == rhs.Length
				&& FileMd4 == rhs.FileMd4
				&& AichMaster == rhs.AichMaster
				&& Md4PartHashes == rhs.Md4PartHashes
				&& AichPartHashes == rhs.AichPartHashes;
		}
	};

	/**
	 * @brief Updates a simple byte-for-byte checksum while the tests compare reader paths.
	 */
	class CFnv1a64
	{
	public:
		void Add(const BYTE *pBytes, size_t nByteCount)
		{
			for (size_t i = 0; i < nByteCount; ++i) {
				m_nValue ^= static_cast<unsigned long long>(pBytes[i]);
				m_nValue *= 1099511628211ull;
			}
		}

		unsigned long long GetValue() const
		{
			return m_nValue;
		}

	private:
		unsigned long long m_nValue = 1469598103934665603ull;
	};

#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	class CFnvMappedVisitor : public IMappedFileRangeVisitor
	{
	public:
		void OnMappedFileBytes(const BYTE *pBytes, size_t nByteCount) override
		{
			m_Hash.Add(pBytes, nByteCount);
		}

		unsigned long long GetDigest() const
		{
			return m_Hash.GetValue();
		}

	private:
		CFnv1a64 m_Hash;
	};
#endif

	/**
	 * @brief Returns a deterministic fixture root owned by this test file.
	 */
	std::filesystem::path GetDeterministicSampleRoot()
	{
		WCHAR szTempPath[MAX_PATH] = {};
		REQUIRE(::GetTempPathW(_countof(szTempPath), szTempPath) != 0);
		WCHAR szProcessDirectory[64] = {};
		const int nWritten = _snwprintf_s(szProcessDirectory, _countof(szProcessDirectory), _TRUNCATE, L"pid-%lu", ::GetCurrentProcessId());
		REQUIRE(nWritten > 0);
		return std::filesystem::path(szTempPath) / L"emule-mapped-reader-fixtures" / szProcessDirectory;
	}

	/**
	 * @brief Streams a deterministic byte pattern to disk without allocating the whole file.
	 */
	void WriteDeterministicFixtureFile(const std::filesystem::path &rPath, unsigned long long nByteCount, BYTE bySalt)
	{
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, rPath.c_str(), L"wb") == 0);
		REQUIRE(pFile != NULL);

		BYTE buffer[HASH_BUFFER_SIZE] = {};
		unsigned long long nWritten = 0;
		while (nWritten < nByteCount) {
			const size_t nChunk = static_cast<size_t>(std::min<unsigned long long>(nByteCount - nWritten, sizeof buffer));
			for (size_t i = 0; i < nChunk; ++i)
				buffer[i] = static_cast<BYTE>(((nWritten + i) * 37ull + bySalt) & 0xFFu);
			REQUIRE(fwrite(buffer, 1, nChunk, pFile) == nChunk);
			nWritten += nChunk;
		}

		fclose(pFile);
	}

	/**
	 * @brief Creates or refreshes the deterministic corpus used by all mapped-reader parity tests.
	 */
	std::vector<CSampledFile> EnsureDeterministicSampleFiles()
	{
		static std::vector<CSampledFile> s_sample;
		if (!s_sample.empty())
			return s_sample;

		const std::filesystem::path root = GetDeterministicSampleRoot();
		std::error_code ec;
		std::filesystem::create_directories(root / L"nested", ec);
		ec.clear();
		std::filesystem::create_directories(root / L"part-boundary", ec);
		ec.clear();

		struct CFixtureSpec
		{
			const wchar_t *pszRelativePath;
			unsigned long long nLength;
			BYTE bySalt;
		};

		static const CFixtureSpec fixtures[] = {
			{L"alpha-small.bin", 4113ull, 0x11u},
			{L"nested\\beta-window.bin", 3ull * 1024ull * 1024ull + 257ull, 0x33u},
			{L"part-boundary\\gamma-part.bin", PARTSIZE_BYTES + 12345ull, 0x55u},
			{L"nested\\delta-large.bin", 2ull * 1024ull * 1024ull + 17ull, 0x77u},
		};

		for (const CFixtureSpec &fixture : fixtures) {
			const std::filesystem::path filePath = root / fixture.pszRelativePath;
			std::filesystem::create_directories(filePath.parent_path(), ec);
			ec.clear();

			bool bRewrite = true;
			if (std::filesystem::exists(filePath, ec)) {
				const auto nExistingSize = std::filesystem::file_size(filePath, ec);
				if (!ec && nExistingSize == fixture.nLength)
					bRewrite = false;
			}
			ec.clear();

			if (bRewrite)
				WriteDeterministicFixtureFile(filePath, fixture.nLength, fixture.bySalt);

			s_sample.push_back(CSampledFile{ filePath.wstring(), fixture.nLength });
		}

		return s_sample;
	}

	/**
	 * @brief Creates deterministic byte content so synthetic range comparisons stay readable.
	 */
	std::vector<BYTE> CreateMappedReaderFixture(size_t nByteCount)
	{
		std::vector<BYTE> data(nByteCount);
		for (size_t i = 0; i < nByteCount; ++i)
			data[i] = static_cast<BYTE>((i * 37u + 11u) & 0xFFu);
		return data;
	}

	/**
	 * @brief Creates a disposable binary file path for mapped-reader regression tests.
	 */
	std::wstring CreateMappedReaderTempPath()
	{
		WCHAR szTempPath[MAX_PATH] = {};
		WCHAR szTempFile[MAX_PATH] = {};
		REQUIRE(::GetTempPathW(_countof(szTempPath), szTempPath) != 0);
		REQUIRE(::GetTempFileNameW(szTempPath, L"mmr", 0, szTempFile) != 0);
		return std::wstring(szTempFile);
	}

	/**
	 * @brief Writes the supplied binary fixture to disk for mapped file reads.
	 */
	void WriteMappedReaderFixture(const std::wstring &rstrPath, const std::vector<BYTE> &rData)
	{
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, rstrPath.c_str(), L"wb") == 0);
		REQUIRE(pFile != NULL);
		REQUIRE(fwrite(rData.data(), 1, rData.size(), pFile) == rData.size());
		fclose(pFile);
	}

	/**
	 * @brief Returns a byte-exact slice for synthetic parity assertions.
	 */
	std::vector<BYTE> SliceMappedReaderFixture(const std::vector<BYTE> &rData, size_t nOffset, size_t nLength)
	{
		return std::vector<BYTE>(rData.begin() + nOffset, rData.begin() + nOffset + nLength);
	}

	/**
	 * @brief Reads a file through a CRT stream to mirror the legacy buffered path.
	 */
	unsigned long long ComputeBufferedDigest(const std::wstring &rstrPath)
	{
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, rstrPath.c_str(), L"rb") == 0);
		REQUIRE(pFile != NULL);

		CFnv1a64 hash;
		BYTE buffer[HASH_BUFFER_SIZE] = {};
		for (;;) {
			const size_t nRead = fread(buffer, 1, sizeof buffer, pFile);
			if (nRead != 0)
				hash.Add(buffer, nRead);
			if (nRead < sizeof buffer) {
				REQUIRE(feof(pFile) != 0);
				break;
			}
		}

		fclose(pFile);
		return hash.GetValue();
	}

	/**
	 * @brief Reads a file through explicit Win32 reads to provide an independent reference path.
	 */
	unsigned long long ComputeWin32Digest(const std::wstring &rstrPath)
	{
		HANDLE hFile = ::CreateFileW(rstrPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		REQUIRE(hFile != INVALID_HANDLE_VALUE);

		CFnv1a64 hash;
		BYTE buffer[HASH_BUFFER_SIZE] = {};
		for (;;) {
			DWORD dwRead = 0;
			REQUIRE(::ReadFile(hFile, buffer, sizeof buffer, &dwRead, NULL) != FALSE);
			if (dwRead == 0)
				break;
			hash.Add(buffer, dwRead);
		}

		::CloseHandle(hFile);
		return hash.GetValue();
	}

#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	/**
	 * @brief Reads a whole file through the workspace mapped reader implementation.
	 */
	unsigned long long ComputeMappedDigest(const std::wstring &rstrPath)
	{
		HANDLE hFile = ::CreateFileW(rstrPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		REQUIRE(hFile != INVALID_HANDLE_VALUE);

		LARGE_INTEGER fileSize = {};
		REQUIRE(::GetFileSizeEx(hFile, &fileSize) != FALSE);

		CFnvMappedVisitor visitor;
		DWORD dwError = ERROR_SUCCESS;
		CHECK(VisitMappedFileRange(hFile, 0, static_cast<ULONGLONG>(fileSize.QuadPart), visitor, &dwError));
		CHECK_EQ(dwError, static_cast<DWORD>(ERROR_SUCCESS));
		::CloseHandle(hFile);
		return visitor.GetDigest();
	}
#endif

	template <typename TDigestFn>
	double MeasureDigestPassMs(const std::vector<CSampledFile> &sample, TDigestFn DigestFn, unsigned long long *pnDigestOut)
	{
		const auto start = std::chrono::steady_clock::now();
		unsigned long long nDigest = 0;
		for (const CSampledFile &file : sample)
			nDigest ^= DigestFn(file.Path);
		const auto stop = std::chrono::steady_clock::now();

		if (pnDigestOut != NULL)
			*pnDigestOut = nDigest;

		return std::chrono::duration<double, std::milli>(stop - start).count();
	}

	unsigned long long GetSampleTotalBytes(const std::vector<CSampledFile> &sample)
	{
		unsigned long long nTotalBytes = 0;
		for (const CSampledFile &file : sample)
			nTotalBytes += file.Length;
		return nTotalBytes;
	}

	/**
	 * @brief Names the active reader path in benchmark output.
	 */
	const wchar_t* GetReaderModeName(EReaderMode eMode)
	{
		switch (eMode) {
		case EReaderMode::Buffered:
			return L"buffered";
		case EReaderMode::Win32:
			return L"win32";
		case EReaderMode::Mapped:
			return L"mapped";
		default:
			return L"unknown";
		}
	}

	/**
	 * @brief Chooses the workspace-preferred reader so the test run uses mapped I/O while the baseline keeps the buffered reference path.
	 */
	EReaderMode GetWorkspacePreferredReaderMode()
	{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
		return EReaderMode::Mapped;
#else
		return EReaderMode::Win32;
#endif
	}

	struct CHashAlgorithmProvider
	{
		BCRYPT_ALG_HANDLE Handle = NULL;
		DWORD ObjectLength = 0;
		DWORD HashLength = 0;
	};

	/**
	 * @brief Opens a reusable CNG provider for the requested digest algorithm.
	 */
	const CHashAlgorithmProvider& GetHashAlgorithmProvider(LPCWSTR pszAlgorithmId)
	{
		static CHashAlgorithmProvider s_md4Provider = {};
		static CHashAlgorithmProvider s_sha1Provider = {};
		CHashAlgorithmProvider *pProvider = (wcscmp(pszAlgorithmId, BCRYPT_MD4_ALGORITHM) == 0) ? &s_md4Provider : &s_sha1Provider;
		if (pProvider->Handle != NULL)
			return *pProvider;

		ULONG nResultLength = 0;
		REQUIRE(::BCryptOpenAlgorithmProvider(&pProvider->Handle, pszAlgorithmId, NULL, 0) == 0);
		REQUIRE(::BCryptGetProperty(pProvider->Handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&pProvider->ObjectLength), sizeof pProvider->ObjectLength, &nResultLength, 0) == 0);
		REQUIRE(nResultLength == sizeof pProvider->ObjectLength);
		REQUIRE(::BCryptGetProperty(pProvider->Handle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&pProvider->HashLength), sizeof pProvider->HashLength, &nResultLength, 0) == 0);
		REQUIRE(nResultLength == sizeof pProvider->HashLength);
		return *pProvider;
	}

	/**
	 * @brief Manages a single incremental CNG hash instance for MD4 and SHA1 parity checks.
	 */
	class CIncrementalHash
	{
	public:
		explicit CIncrementalHash(const CHashAlgorithmProvider &rProvider)
			: m_rProvider(rProvider)
			, m_HashObject(rProvider.ObjectLength)
		{
			REQUIRE(::BCryptCreateHash(m_rProvider.Handle, &m_hHash, m_HashObject.data(), static_cast<ULONG>(m_HashObject.size()), NULL, 0, 0) == 0);
		}

		~CIncrementalHash()
		{
			if (m_hHash != NULL)
				::BCryptDestroyHash(m_hHash);
		}

		void Add(const BYTE *pBytes, size_t nByteCount)
		{
			if (nByteCount == 0)
				return;
			REQUIRE(::BCryptHashData(m_hHash, const_cast<PUCHAR>(pBytes), static_cast<ULONG>(nByteCount), 0) == 0);
		}

		template <size_t N>
		std::array<BYTE, N> Finish()
		{
			REQUIRE(m_rProvider.HashLength == N);
			std::array<BYTE, N> digest = {};
			REQUIRE(::BCryptFinishHash(m_hHash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0);
			return digest;
		}

	private:
		const CHashAlgorithmProvider &m_rProvider;
		std::vector<UCHAR> m_HashObject;
		BCRYPT_HASH_HANDLE m_hHash = NULL;
	};

	/**
	 * @brief Visits a file range through the legacy CRT buffered path.
	 */
	template <typename TVisitor>
	void VisitFileRangeBuffered(const std::wstring &rstrPath, unsigned long long nOffset, unsigned long long nLength, TVisitor &&Visitor)
	{
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, rstrPath.c_str(), L"rb") == 0);
		REQUIRE(pFile != NULL);
		REQUIRE(_fseeki64(pFile, static_cast<__int64>(nOffset), SEEK_SET) == 0);

		BYTE buffer[HASH_BUFFER_SIZE] = {};
		unsigned long long nRemaining = nLength;
		while (nRemaining != 0) {
			const size_t nRequested = static_cast<size_t>(std::min<unsigned long long>(nRemaining, sizeof buffer));
			const size_t nRead = fread(buffer, 1, nRequested, pFile);
			REQUIRE(nRead == nRequested);
			Visitor(buffer, nRead);
			nRemaining -= nRead;
		}

		fclose(pFile);
	}

	/**
	 * @brief Visits a file range through explicit Win32 reads.
	 */
	template <typename TVisitor>
	void VisitFileRangeWin32(const std::wstring &rstrPath, unsigned long long nOffset, unsigned long long nLength, TVisitor &&Visitor)
	{
		HANDLE hFile = ::CreateFileW(rstrPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		REQUIRE(hFile != INVALID_HANDLE_VALUE);

		LARGE_INTEGER liOffset = {};
		liOffset.QuadPart = static_cast<LONGLONG>(nOffset);
		REQUIRE(::SetFilePointerEx(hFile, liOffset, NULL, FILE_BEGIN) != FALSE);

		BYTE buffer[HASH_BUFFER_SIZE] = {};
		unsigned long long nRemaining = nLength;
		while (nRemaining != 0) {
			DWORD dwRead = 0;
			const DWORD dwRequested = static_cast<DWORD>(std::min<unsigned long long>(nRemaining, sizeof buffer));
			REQUIRE(::ReadFile(hFile, buffer, dwRequested, &dwRead, NULL) != FALSE);
			REQUIRE(dwRead == dwRequested);
			Visitor(buffer, dwRead);
			nRemaining -= dwRead;
		}

		::CloseHandle(hFile);
	}

#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	/**
	 * @brief Adapts a lambda visitor to the production mapped reader interface.
	 */
	template <typename TVisitor>
	class CMappedLambdaVisitor : public IMappedFileRangeVisitor
	{
	public:
		explicit CMappedLambdaVisitor(TVisitor &Visitor)
			: m_Visitor(Visitor)
		{
		}

		void OnMappedFileBytes(const BYTE *pBytes, size_t nByteCount) override
		{
			m_Visitor(pBytes, nByteCount);
		}

	private:
		TVisitor &m_Visitor;
	};
#endif

	/**
	 * @brief Visits a file range through the workspace mapped reader implementation.
	 */
	template <typename TVisitor>
	void VisitFileRangeMapped(const std::wstring &rstrPath, unsigned long long nOffset, unsigned long long nLength, TVisitor &&Visitor)
	{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
		HANDLE hFile = ::CreateFileW(rstrPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		REQUIRE(hFile != INVALID_HANDLE_VALUE);

		DWORD dwError = ERROR_SUCCESS;
		CMappedLambdaVisitor<TVisitor> mappedVisitor(Visitor);
		REQUIRE(VisitMappedFileRange(hFile, nOffset, nLength, mappedVisitor, &dwError));
		REQUIRE(dwError == ERROR_SUCCESS);

		::CloseHandle(hFile);
#else
		(void)rstrPath;
		(void)nOffset;
		(void)nLength;
		(void)Visitor;
		CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
	}

	/**
	 * @brief Dispatches the byte-stream visitor through the requested file reader path.
	 */
	template <typename TVisitor>
	void VisitFileRange(const std::wstring &rstrPath, unsigned long long nOffset, unsigned long long nLength, EReaderMode eMode, TVisitor &&Visitor)
	{
		switch (eMode) {
		case EReaderMode::Buffered:
			VisitFileRangeBuffered(rstrPath, nOffset, nLength, std::forward<TVisitor>(Visitor));
			return;
		case EReaderMode::Win32:
			VisitFileRangeWin32(rstrPath, nOffset, nLength, std::forward<TVisitor>(Visitor));
			return;
		case EReaderMode::Mapped:
			VisitFileRangeMapped(rstrPath, nOffset, nLength, std::forward<TVisitor>(Visitor));
			return;
		default:
			CHECK_MESSAGE(false, "Unknown reader mode");
			return;
		}
	}

	/**
	 * @brief Hashes the buffered bytes into MD4 plus ordered SHA1 block hashes for one eMule part.
	 */
	struct CPartHashData
	{
		CMd4Digest Md4 = {};
		std::vector<CSha1Digest> AichBlockHashes;
	};

	/**
	 * @brief Streams one eMule part exactly once and records the raw MD4 plus AICH block hashes.
	 */
	CPartHashData ComputePartHashData(const std::wstring &rstrPath, unsigned long long nOffset, unsigned long long nLength, EReaderMode eMode)
	{
		CPartHashData result;
		CIncrementalHash md4Hasher(GetHashAlgorithmProvider(BCRYPT_MD4_ALGORITHM));
		std::unique_ptr<CIncrementalHash> pAichBlockHasher = std::make_unique<CIncrementalHash>(GetHashAlgorithmProvider(BCRYPT_SHA1_ALGORITHM));
		size_t nBytesInCurrentBlock = 0;

		auto FlushAichBlock = [&]() {
			result.AichBlockHashes.push_back(pAichBlockHasher->Finish<20>());
			pAichBlockHasher = std::make_unique<CIncrementalHash>(GetHashAlgorithmProvider(BCRYPT_SHA1_ALGORITHM));
			nBytesInCurrentBlock = 0;
		};

		VisitFileRange(rstrPath, nOffset, nLength, eMode, [&](const BYTE *pBytes, size_t nByteCount) {
			md4Hasher.Add(pBytes, nByteCount);
			while (nByteCount != 0) {
				const size_t nChunk = std::min(nByteCount, EMBLOCKSIZE_BYTES - nBytesInCurrentBlock);
				pAichBlockHasher->Add(pBytes, nChunk);
				nBytesInCurrentBlock += nChunk;
				pBytes += nChunk;
				nByteCount -= nChunk;

				if (nBytesInCurrentBlock == EMBLOCKSIZE_BYTES)
					FlushAichBlock();
			}
		});

		if (nLength != 0 && nBytesInCurrentBlock != 0)
			FlushAichBlock();

		result.Md4 = md4Hasher.Finish<16>();
		return result;
	}

	/**
	 * @brief Reduces ordered SHA1 leaves with the production left/right AICH balancing rules.
	 */
	CSha1Digest ReduceAichHashes(const std::vector<CSha1Digest> &rLeaves, size_t nStart, size_t nCount, bool bIsLeftBranch)
	{
		REQUIRE(nCount != 0);
		if (nCount == 1)
			return rLeaves[nStart];

		const size_t nLeftCount = (nCount + static_cast<size_t>(bIsLeftBranch)) / 2u;
		const size_t nRightCount = nCount - nLeftCount;
		REQUIRE(nRightCount != 0);

		const CSha1Digest leftHash = ReduceAichHashes(rLeaves, nStart, nLeftCount, true);
		const CSha1Digest rightHash = ReduceAichHashes(rLeaves, nStart + nLeftCount, nRightCount, false);

		CIncrementalHash parentHasher(GetHashAlgorithmProvider(BCRYPT_SHA1_ALGORITHM));
		parentHasher.Add(leftHash.data(), leftHash.size());
		parentHasher.Add(rightHash.data(), rightHash.size());
		return parentHasher.Finish<20>();
	}

	/**
	 * @brief Expands the part-root orientation sequence used by the production AICH tree.
	 */
	void CollectPartOrientations(size_t nPartCount, bool bIsLeftBranch, std::vector<bool> &rOrientations)
	{
		REQUIRE(nPartCount != 0);
		if (nPartCount == 1) {
			rOrientations.push_back(bIsLeftBranch);
			return;
		}

		const size_t nLeftCount = (nPartCount + static_cast<size_t>(bIsLeftBranch)) / 2u;
		CollectPartOrientations(nLeftCount, true, rOrientations);
		CollectPartOrientations(nPartCount - nLeftCount, false, rOrientations);
	}

	/**
	 * @brief Returns the MD4 of zero bytes for the special exact-partsize ed2k tail hash.
	 */
	const CMd4Digest& GetEmptyMd4Digest()
	{
		static const CMd4Digest s_EmptyMd4Digest = []() {
			CIncrementalHash hasher(GetHashAlgorithmProvider(BCRYPT_MD4_ALGORITHM));
			return hasher.Finish<16>();
		}();
		return s_EmptyMd4Digest;
	}

	/**
	 * @brief Reproduces the full eMule MD4 and AICH artifact pipeline for one file.
	 */
	CFileHashArtifacts ComputeFullHashArtifacts(const CSampledFile &rFile, EReaderMode eMode)
	{
		REQUIRE(rFile.Length != 0);

		CFileHashArtifacts artifacts = {};
		artifacts.Length = rFile.Length;
		const size_t nRealPartCount = static_cast<size_t>((rFile.Length + (PARTSIZE_BYTES - 1ull)) / PARTSIZE_BYTES);
		std::vector<bool> aichPartOrientations;
		if (rFile.Length > PARTSIZE_BYTES) {
			aichPartOrientations.reserve(nRealPartCount);
			CollectPartOrientations(nRealPartCount, true, aichPartOrientations);
			REQUIRE(aichPartOrientations.size() == nRealPartCount);
		}

		for (size_t nPart = 0; nPart < nRealPartCount; ++nPart) {
			const unsigned long long nOffset = static_cast<unsigned long long>(nPart) * PARTSIZE_BYTES;
			const unsigned long long nLength = std::min<unsigned long long>(PARTSIZE_BYTES, rFile.Length - nOffset);
			const CPartHashData partHashes = ComputePartHashData(rFile.Path, nOffset, nLength, eMode);

			if (rFile.Length < PARTSIZE_BYTES)
				artifacts.FileMd4 = partHashes.Md4;
			else
				artifacts.Md4PartHashes.push_back(partHashes.Md4);

			if (rFile.Length <= PARTSIZE_BYTES)
				artifacts.AichMaster = ReduceAichHashes(partHashes.AichBlockHashes, 0, partHashes.AichBlockHashes.size(), true);
			else {
				const CSha1Digest partHash = ReduceAichHashes(partHashes.AichBlockHashes, 0, partHashes.AichBlockHashes.size(), aichPartOrientations[nPart]);
				artifacts.AichPartHashes.push_back(partHash);
			}
		}

		if (rFile.Length >= PARTSIZE_BYTES) {
			if (rFile.Length % PARTSIZE_BYTES == 0ull)
				artifacts.Md4PartHashes.push_back(GetEmptyMd4Digest());

			CIncrementalHash fileMd4Hasher(GetHashAlgorithmProvider(BCRYPT_MD4_ALGORITHM));
			for (const CMd4Digest &partHash : artifacts.Md4PartHashes)
				fileMd4Hasher.Add(partHash.data(), partHash.size());
			artifacts.FileMd4 = fileMd4Hasher.Finish<16>();
		}

		if (rFile.Length > PARTSIZE_BYTES)
			artifacts.AichMaster = ReduceAichHashes(artifacts.AichPartHashes, 0, artifacts.AichPartHashes.size(), true);

		return artifacts;
	}

	/**
	 * @brief Feeds the full hashing artifacts into an aggregate digest for test-run-vs-baseline comparisons.
	 */
	void AddArtifactsToDigest(CFnv1a64 &rDigest, const CFileHashArtifacts &rArtifacts)
	{
		rDigest.Add(reinterpret_cast<const BYTE*>(&rArtifacts.Length), sizeof rArtifacts.Length);
		rDigest.Add(rArtifacts.FileMd4.data(), rArtifacts.FileMd4.size());
		rDigest.Add(rArtifacts.AichMaster.data(), rArtifacts.AichMaster.size());

		const size_t nMd4Count = rArtifacts.Md4PartHashes.size();
		rDigest.Add(reinterpret_cast<const BYTE*>(&nMd4Count), sizeof nMd4Count);
		for (const CMd4Digest &hash : rArtifacts.Md4PartHashes)
			rDigest.Add(hash.data(), hash.size());

		const size_t nAichCount = rArtifacts.AichPartHashes.size();
		rDigest.Add(reinterpret_cast<const BYTE*>(&nAichCount), sizeof nAichCount);
		for (const CSha1Digest &hash : rArtifacts.AichPartHashes)
			rDigest.Add(hash.data(), hash.size());
	}

	/**
	 * @brief Measures the full-file eMule hashing pipeline over the sampled corpus.
	 */
	double MeasureFullPipelineMs(const std::vector<CSampledFile> &sample, EReaderMode eMode, unsigned long long *pnAggregateDigestOut)
	{
		const auto start = std::chrono::steady_clock::now();
		CFnv1a64 aggregateDigest;
		for (const CSampledFile &file : sample)
			AddArtifactsToDigest(aggregateDigest, ComputeFullHashArtifacts(file, eMode));
		const auto stop = std::chrono::steady_clock::now();

		if (pnAggregateDigestOut != NULL)
			*pnAggregateDigestOut = aggregateDigest.GetValue();

		return std::chrono::duration<double, std::milli>(stop - start).count();
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Actual temp-file buffered and Win32 digests match on sampled files")
{
	const std::vector<CSampledFile> sample = EnsureDeterministicSampleFiles();
	REQUIRE_FALSE(sample.empty());

	for (const CSampledFile &file : sample)
		CHECK_EQ(ComputeBufferedDigest(file.Path), ComputeWin32Digest(file.Path));
}

TEST_CASE("Mapped file reader returns the exact requested slice across allocation boundaries")
{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	const std::vector<BYTE> fixture = CreateMappedReaderFixture(1024 * 1024 + 257);
	const std::wstring tempPath = CreateMappedReaderTempPath();
	WriteMappedReaderFixture(tempPath, fixture);

	HANDLE hFile = ::CreateFileW(tempPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	REQUIRE(hFile != INVALID_HANDLE_VALUE);

	CFnvMappedVisitor visitor;
	DWORD dwError = ERROR_SUCCESS;
	const size_t nOffset = 65530;
	const size_t nLength = 400000;
	CHECK(VisitMappedFileRange(hFile, nOffset, nLength, visitor, &dwError));
	CHECK_EQ(dwError, static_cast<DWORD>(ERROR_SUCCESS));

	CFnv1a64 referenceHash;
	const std::vector<BYTE> reference = SliceMappedReaderFixture(fixture, nOffset, nLength);
	referenceHash.Add(reference.data(), reference.size());
	CHECK_EQ(visitor.GetDigest(), referenceHash.GetValue());

	::CloseHandle(hFile);
	::DeleteFileW(tempPath.c_str());
#else
	CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
}

TEST_CASE("Mapped file reader spans multiple mapping windows without dropping bytes")
{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	const std::vector<BYTE> fixture = CreateMappedReaderFixture(9 * 1024 * 1024 + 123);
	const std::wstring tempPath = CreateMappedReaderTempPath();
	WriteMappedReaderFixture(tempPath, fixture);

	HANDLE hFile = ::CreateFileW(tempPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	REQUIRE(hFile != INVALID_HANDLE_VALUE);

	CFnvMappedVisitor visitor;
	DWORD dwError = ERROR_SUCCESS;
	const size_t nOffset = 123;
	const size_t nLength = fixture.size() - 246;
	CHECK(VisitMappedFileRange(hFile, nOffset, nLength, visitor, &dwError));
	CHECK_EQ(dwError, static_cast<DWORD>(ERROR_SUCCESS));

	CFnv1a64 referenceHash;
	const std::vector<BYTE> reference = SliceMappedReaderFixture(fixture, nOffset, nLength);
	referenceHash.Add(reference.data(), reference.size());
	CHECK_EQ(visitor.GetDigest(), referenceHash.GetValue());

	::CloseHandle(hFile);
	::DeleteFileW(tempPath.c_str());
#else
	CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
}

TEST_CASE("Mapped file reader accepts zero-length ranges without touching the visitor")
{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	const std::vector<BYTE> fixture = CreateMappedReaderFixture(128);
	const std::wstring tempPath = CreateMappedReaderTempPath();
	WriteMappedReaderFixture(tempPath, fixture);

	HANDLE hFile = ::CreateFileW(tempPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	REQUIRE(hFile != INVALID_HANDLE_VALUE);

	CFnvMappedVisitor visitor;
	DWORD dwError = ERROR_SUCCESS;
	CHECK(VisitMappedFileRange(hFile, 0, 0, visitor, &dwError));
	CHECK_EQ(dwError, static_cast<DWORD>(ERROR_SUCCESS));
	CHECK_EQ(visitor.GetDigest(), static_cast<unsigned long long>(1469598103934665603ull));

	::CloseHandle(hFile);
	::DeleteFileW(tempPath.c_str());
#else
	CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
}

TEST_CASE("Mapped file reader reports invalid handles")
{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	class CNoopVisitor : public IMappedFileRangeVisitor
	{
	public:
		void OnMappedFileBytes(const BYTE *, size_t) override
		{
		}
	} visitor;

	DWORD dwError = ERROR_SUCCESS;
	CHECK_FALSE(VisitMappedFileRange(INVALID_HANDLE_VALUE, 0, 1, visitor, &dwError));
	CHECK_EQ(dwError, static_cast<DWORD>(ERROR_INVALID_HANDLE));
#else
	CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
}

TEST_CASE("Mapped file reader matches buffered digest on sampled actual temp files")
{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	const std::vector<CSampledFile> sample = EnsureDeterministicSampleFiles();
	REQUIRE_FALSE(sample.empty());

	for (const CSampledFile &file : sample)
		CHECK_EQ(ComputeMappedDigest(file.Path), ComputeBufferedDigest(file.Path));
#else
	CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
}

TEST_CASE("Mapped file reader accepts a null error output pointer on successful reads")
{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	const std::vector<BYTE> fixture = CreateMappedReaderFixture(8192 + 17);
	const std::wstring tempPath = CreateMappedReaderTempPath();
	WriteMappedReaderFixture(tempPath, fixture);

	HANDLE hFile = ::CreateFileW(tempPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	REQUIRE(hFile != INVALID_HANDLE_VALUE);

	CFnvMappedVisitor visitor;
	CHECK(VisitMappedFileRange(hFile, 0, fixture.size(), visitor, NULL));

	CFnv1a64 referenceHash;
	referenceHash.Add(fixture.data(), fixture.size());
	CHECK_EQ(visitor.GetDigest(), referenceHash.GetValue());

	::CloseHandle(hFile);
	::DeleteFileW(tempPath.c_str());
#else
	CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
}

TEST_CASE("Mapped file reader returns exact tail slices at the end of the file")
{
#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	const std::vector<BYTE> fixture = CreateMappedReaderFixture(4096 + 33);
	const std::wstring tempPath = CreateMappedReaderTempPath();
	WriteMappedReaderFixture(tempPath, fixture);

	HANDLE hFile = ::CreateFileW(tempPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	REQUIRE(hFile != INVALID_HANDLE_VALUE);

	CFnvMappedVisitor visitor;
	DWORD dwError = ERROR_SUCCESS;
	const size_t nOffset = fixture.size() - 1u;
	CHECK(VisitMappedFileRange(hFile, nOffset, 1u, visitor, &dwError));
	CHECK_EQ(dwError, static_cast<DWORD>(ERROR_SUCCESS));

	CFnv1a64 referenceHash;
	referenceHash.Add(&fixture[nOffset], 1u);
	CHECK_EQ(visitor.GetDigest(), referenceHash.GetValue());

	::CloseHandle(hFile);
	::DeleteFileW(tempPath.c_str());
#else
	CHECK_MESSAGE(false, "MappedFileReader unavailable in this workspace");
#endif
}

TEST_SUITE_END;

TEST_SUITE_BEGIN("benchmark");

TEST_CASE("File reader benchmark reports sampled temp-file throughput")
{
	const std::vector<CSampledFile> sample = EnsureDeterministicSampleFiles();
	REQUIRE_FALSE(sample.empty());

	const unsigned long long nSeed = DETERMINISTIC_SAMPLE_SEED;
	const unsigned long long nTotalBytes = GetSampleTotalBytes(sample);
	unsigned long long nBufferedDigest = 0;
	unsigned long long nWin32Digest = 0;
	const double dBufferedMs = MeasureDigestPassMs(sample, ComputeBufferedDigest, &nBufferedDigest);
	const double dWin32Ms = MeasureDigestPassMs(sample, ComputeWin32Digest, &nWin32Digest);
	CHECK_EQ(nBufferedDigest, nWin32Digest);

	std::printf("BENCHMARK sample_root=%ls seed=%llu file_count=%zu total_bytes=%llu buffered_ms=%.3f win32_ms=%.3f buffered_mib_s=%.3f win32_mib_s=%.3f"
		, GetDeterministicSampleRoot().c_str()
		, nSeed
		, sample.size()
		, nTotalBytes
		, dBufferedMs
		, dWin32Ms
		, dBufferedMs > 0.0 ? (static_cast<double>(nTotalBytes) / (1024.0 * 1024.0)) / (dBufferedMs / 1000.0) : 0.0
		, dWin32Ms > 0.0 ? (static_cast<double>(nTotalBytes) / (1024.0 * 1024.0)) / (dWin32Ms / 1000.0) : 0.0);

#if EMULEBB_TEST_HAVE_MAPPED_FILE_READER
	unsigned long long nMappedDigest = 0;
	const double dMappedMs = MeasureDigestPassMs(sample, ComputeMappedDigest, &nMappedDigest);
	CHECK_EQ(nBufferedDigest, nMappedDigest);
	std::printf(" mapped_ms=%.3f mapped_mib_s=%.3f mapped_vs_buffered=%.3fx"
		, dMappedMs
		, dMappedMs > 0.0 ? (static_cast<double>(nTotalBytes) / (1024.0 * 1024.0)) / (dMappedMs / 1000.0) : 0.0
		, dMappedMs > 0.0 ? dBufferedMs / dMappedMs : 0.0);
#endif

	std::printf("\n");
}

TEST_SUITE_END;

TEST_SUITE_BEGIN("pipeline");

TEST_CASE("Actual temp-file full hashing artifacts match between buffered and preferred readers")
{
	const std::vector<CSampledFile> sample = EnsureDeterministicSampleFiles();
	REQUIRE_FALSE(sample.empty());

	const EReaderMode ePreferredMode = GetWorkspacePreferredReaderMode();
	for (const CSampledFile &file : sample)
		CHECK(ComputeFullHashArtifacts(file, EReaderMode::Buffered) == ComputeFullHashArtifacts(file, ePreferredMode));
}

TEST_SUITE_END;

TEST_SUITE_BEGIN("pipeline-benchmark");

TEST_CASE("Full hashing pipeline benchmark reports sampled temp-file parity and throughput")
{
	const std::vector<CSampledFile> sample = EnsureDeterministicSampleFiles();
	REQUIRE_FALSE(sample.empty());

	const unsigned long long nSeed = DETERMINISTIC_SAMPLE_SEED;
	const unsigned long long nTotalBytes = GetSampleTotalBytes(sample);
	const EReaderMode ePreferredMode = GetWorkspacePreferredReaderMode();
	unsigned long long nBufferedDigest = 0;
	unsigned long long nPreferredDigest = 0;
	const double dBufferedMs = MeasureFullPipelineMs(sample, EReaderMode::Buffered, &nBufferedDigest);
	const double dPreferredMs = MeasureFullPipelineMs(sample, ePreferredMode, &nPreferredDigest);
	CHECK_EQ(nBufferedDigest, nPreferredDigest);

	std::printf("PIPELINE_BENCHMARK sample_root=%ls seed=%llu file_count=%zu total_bytes=%llu buffered_ms=%.3f preferred_ms=%.3f preferred_kind=%ls buffered_mib_s=%.3f preferred_mib_s=%.3f preferred_vs_buffered=%.3fx aggregate_digest=%llu\n"
		, GetDeterministicSampleRoot().c_str()
		, nSeed
		, sample.size()
		, nTotalBytes
		, dBufferedMs
		, dPreferredMs
		, GetReaderModeName(ePreferredMode)
		, dBufferedMs > 0.0 ? (static_cast<double>(nTotalBytes) / (1024.0 * 1024.0)) / (dBufferedMs / 1000.0) : 0.0
		, dPreferredMs > 0.0 ? (static_cast<double>(nTotalBytes) / (1024.0 * 1024.0)) / (dPreferredMs / 1000.0) : 0.0
		, dPreferredMs > 0.0 ? dBufferedMs / dPreferredMs : 0.0
		, nPreferredDigest);
}

TEST_SUITE_END;
