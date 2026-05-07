#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include <algorithm>
#include <ctime>
#include <cstdio>
#include <vector>

#include "kademlia/utils/FastKad.h"
#include "kademlia/utils/KadPersistenceSeams.h"
#include "kademlia/utils/KadPublishGuard.h"
#include "kademlia/utils/NodesDatSupport.h"
#include "kademlia/utils/SafeKad.h"

namespace
{
	/**
	 * Creates a disposable sidecar path for Fast Kad persistence tests.
	 */
	CString CreateFastKadTempPath()
	{
		WCHAR szTempPath[MAX_PATH] = {};
		WCHAR szTempFile[MAX_PATH] = {};
		REQUIRE(::GetTempPathW(_countof(szTempPath), szTempPath) != 0);
		REQUIRE(::GetTempFileNameW(szTempPath, L"fkd", 0, szTempFile) != 0);
		::DeleteFileW(szTempFile);
		return CString(szTempFile);
	}

	/**
	 * Writes a deterministic Fast Kad sidecar fixture so ranking tests can control recency and health.
	 */
	void WriteFastKadFixture(LPCTSTR pszPath, const Kademlia::CUInt128 &uID, uint16 uUDPPort, uint64 uLastSuccessTime, uint32 uResponseTimeMs, sint16 nHealthScore)
	{
		const uint32 uMagic = 0x3146444Bu;
		const uint32 uVersion = 1;
		const uint32 uCount = 1;
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, pszPath, L"wb") == 0);
		REQUIRE(pFile != NULL);
		REQUIRE(fwrite(&uMagic, 1, sizeof uMagic, pFile) == sizeof uMagic);
		REQUIRE(fwrite(&uVersion, 1, sizeof uVersion, pFile) == sizeof uVersion);
		REQUIRE(fwrite(&uCount, 1, sizeof uCount, pFile) == sizeof uCount);
		REQUIRE(fwrite(uID.GetData(), 1, 16, pFile) == 16);
		REQUIRE(fwrite(&uUDPPort, 1, sizeof uUDPPort, pFile) == sizeof uUDPPort);
		REQUIRE(fwrite(&uLastSuccessTime, 1, sizeof uLastSuccessTime, pFile) == sizeof uLastSuccessTime);
		REQUIRE(fwrite(&uResponseTimeMs, 1, sizeof uResponseTimeMs, pFile) == sizeof uResponseTimeMs);
		REQUIRE(fwrite(&nHealthScore, 1, sizeof nHealthScore, pFile) == sizeof nHealthScore);
		fclose(pFile);
	}

	/**
	 * Writes a minimal v2 nodes.dat fixture with one structurally valid contact.
	 */
	void WriteNodesDatFixture(LPCTSTR pszPath, bool bBootstrapOnly)
	{
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, pszPath, L"wb") == 0);
		REQUIRE(pFile != NULL);

		const uint32 uStoredIP = 0x04030201u;
		const uint16 uUDPPort = 4665;
		const uint16 uTCPPort = 4662;
		const uint32 uUDPKey = 0x01010101u;
		const uint32 uUDPKeyIP = 0x02020202u;
		const uint8 uVerified = 1;
		const uint8 uContactVersion = 8;
		const byte abyID[16] = { 1 };

		if (bBootstrapOnly) {
			const uint32 uHeader = 0;
			const uint32 uVersion = 3;
			const uint32 uEdition = 1;
			const uint32 uCount = 1;
			REQUIRE(fwrite(&uHeader, 1, sizeof uHeader, pFile) == sizeof uHeader);
			REQUIRE(fwrite(&uVersion, 1, sizeof uVersion, pFile) == sizeof uVersion);
			REQUIRE(fwrite(&uEdition, 1, sizeof uEdition, pFile) == sizeof uEdition);
			REQUIRE(fwrite(&uCount, 1, sizeof uCount, pFile) == sizeof uCount);
			REQUIRE(fwrite(abyID, 1, sizeof abyID, pFile) == sizeof abyID);
			REQUIRE(fwrite(&uStoredIP, 1, sizeof uStoredIP, pFile) == sizeof uStoredIP);
			REQUIRE(fwrite(&uUDPPort, 1, sizeof uUDPPort, pFile) == sizeof uUDPPort);
			REQUIRE(fwrite(&uTCPPort, 1, sizeof uTCPPort, pFile) == sizeof uTCPPort);
			REQUIRE(fwrite(&uContactVersion, 1, sizeof uContactVersion, pFile) == sizeof uContactVersion);
		} else {
			const uint32 uHeader = 0;
			const uint32 uVersion = 2;
			const uint32 uCount = 1;
			REQUIRE(fwrite(&uHeader, 1, sizeof uHeader, pFile) == sizeof uHeader);
			REQUIRE(fwrite(&uVersion, 1, sizeof uVersion, pFile) == sizeof uVersion);
			REQUIRE(fwrite(&uCount, 1, sizeof uCount, pFile) == sizeof uCount);
			REQUIRE(fwrite(abyID, 1, sizeof abyID, pFile) == sizeof abyID);
			REQUIRE(fwrite(&uStoredIP, 1, sizeof uStoredIP, pFile) == sizeof uStoredIP);
			REQUIRE(fwrite(&uUDPPort, 1, sizeof uUDPPort, pFile) == sizeof uUDPPort);
			REQUIRE(fwrite(&uTCPPort, 1, sizeof uTCPPort, pFile) == sizeof uTCPPort);
			REQUIRE(fwrite(&uContactVersion, 1, sizeof uContactVersion, pFile) == sizeof uContactVersion);
			REQUIRE(fwrite(&uUDPKey, 1, sizeof uUDPKey, pFile) == sizeof uUDPKey);
			REQUIRE(fwrite(&uUDPKeyIP, 1, sizeof uUDPKeyIP, pFile) == sizeof uUDPKeyIP);
			REQUIRE(fwrite(&uVerified, 1, sizeof uVerified, pFile) == sizeof uVerified);
		}

		fclose(pFile);
	}

	/**
	 * Writes a deterministic `preferencesKad.dat` fixture with the current saver shape.
	 */
	void WriteKadPrefsFixture(LPCTSTR pszPath, bool bComplete)
	{
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, pszPath, L"wb") == 0);
		REQUIRE(pFile != NULL);

		const uint32 uIP = 0x01020304u;
		const uint16 uUnused = 0;
		const byte abyClientID[16] = { 1 };
		const uint8 uNoTags = 0;
		REQUIRE(fwrite(&uIP, 1, sizeof uIP, pFile) == sizeof uIP);
		REQUIRE(fwrite(&uUnused, 1, sizeof uUnused, pFile) == sizeof uUnused);
		REQUIRE(fwrite(abyClientID, 1, bComplete ? sizeof abyClientID : sizeof abyClientID - 1u, pFile) == (bComplete ? sizeof abyClientID : sizeof abyClientID - 1u));
		if (bComplete)
			REQUIRE(fwrite(&uNoTags, 1, sizeof uNoTags, pFile) == sizeof uNoTags);
		fclose(pFile);
	}

	/**
	 * Reads a whole file into a byte vector for replacement assertions.
	 */
	std::vector<char> ReadWholeFile(LPCTSTR pszPath)
	{
		FILE *pFile = NULL;
		REQUIRE(_wfopen_s(&pFile, pszPath, L"rb") == 0);
		REQUIRE(pFile != NULL);
		REQUIRE(_fseeki64(pFile, 0, SEEK_END) == 0);
		const __int64 nLength = _ftelli64(pFile);
		REQUIRE(nLength >= 0);
		REQUIRE(_fseeki64(pFile, 0, SEEK_SET) == 0);

		std::vector<char> data(static_cast<size_t>(nLength));
		REQUIRE(fread(data.data(), 1, data.size(), pFile) == data.size());
		fclose(pFile);
		return data;
	}

	BOOL WINAPI AlwaysFailMoveFileEx(LPCTSTR, LPCTSTR, DWORD)
	{
		return FALSE;
	}

	DWORD WINAPI ReturnAccessDenied()
	{
		return ERROR_ACCESS_DENIED;
	}

	PartFilePersistenceSeams::FileSystemOps MakePromotionFailureOps()
	{
		PartFilePersistenceSeams::FileSystemOps ops = PartFilePersistenceSeams::GetDefaultFileSystemOps();
		ops.MoveFileEx = AlwaysFailMoveFileEx;
		ops.GetLastError = ReturnAccessDenied;
		return ops;
	}
}

TEST_SUITE_BEGIN("kad-broadband");

TEST_CASE("Fast Kad raises its pending timeout estimate after repeated slow replies")
{
	Kademlia::CFastKad fastKad;
	const clock_t clkDefaultEstimate = fastKad.GetEstMaxResponseTime();
	for (uint32 uIndex = 1; uIndex <= 20; ++uIndex)
		fastKad.AddResponseTime(uIndex, 2 * CLOCKS_PER_SEC);

	CHECK(fastKad.GetEstMaxResponseTime() > clkDefaultEstimate);
	CHECK(fastKad.GetEstMaxResponseTime() <= 3 * CLOCKS_PER_SEC);
}

TEST_CASE("Fast Kad sidecar round-trips bootstrap metadata for known nodes")
{
	const CString strPath = CreateFastKadTempPath();
	Kademlia::CFastKad writer;
	const Kademlia::CUInt128 uFastNode(11ul);
	const Kademlia::CUInt128 uWarmNode(12ul);
	writer.TrackNodeResponse(uFastNode, 4665, 0x01020304u, 2 * CLOCKS_PER_SEC);
	writer.TrackNodeReachable(uWarmNode, 4666);

	std::vector<Kademlia::CFastKad::NodeKey> knownNodes;
	knownNodes.push_back(Kademlia::CFastKad::NodeKey(uFastNode, 4665));
	knownNodes.push_back(Kademlia::CFastKad::NodeKey(uWarmNode, 4666));
	writer.SaveNodesMetadata(strPath, knownNodes);

	Kademlia::CFastKad reader;
	reader.LoadNodesMetadata(strPath);
	CHECK(reader.GetBootstrapPriority(uFastNode, 4665) > 0);
	CHECK(reader.GetBootstrapPriority(uWarmNode, 4666) > 0);
	CHECK(reader.GetBootstrapPriority(uFastNode, 4665) > reader.GetBootstrapPriority(uWarmNode, 4666));

	::DeleteFile(strPath);
}

TEST_CASE("Fast Kad sidecar ignores invalid files without poisoning bootstrap priority state")
{
	const CString strPath = CreateFastKadTempPath();
	FILE *pFile = NULL;
	const uint32 uBadMagic = 0x0u;
	const uint32 uVersion = 1;
	const uint32 uCount = 1;
	REQUIRE(_wfopen_s(&pFile, strPath, L"wb") == 0);
	REQUIRE(pFile != NULL);
	REQUIRE(fwrite(&uBadMagic, 1, sizeof uBadMagic, pFile) == sizeof uBadMagic);
	REQUIRE(fwrite(&uVersion, 1, sizeof uVersion, pFile) == sizeof uVersion);
	REQUIRE(fwrite(&uCount, 1, sizeof uCount, pFile) == sizeof uCount);
	fclose(pFile);

	Kademlia::CFastKad fastKad;
	CHECK_EQ(fastKad.GetBootstrapPriority(Kademlia::CUInt128(21ul), 4672), 0ull);
	fastKad.LoadNodesMetadata(strPath);
	CHECK_EQ(fastKad.GetBootstrapPriority(Kademlia::CUInt128(21ul), 4672), 0ull);

	::DeleteFile(strPath);
}

TEST_CASE("Fast Kad sidecar save keeps dormant node metadata outside the current routing snapshot")
{
	const CString strPath = CreateFastKadTempPath();
	Kademlia::CFastKad writer;
	const Kademlia::CUInt128 uKnownNode(41ul);
	const Kademlia::CUInt128 uDormantNode(42ul);

	writer.TrackNodeReachable(uKnownNode, 4665);
	writer.TrackNodeFailure(uDormantNode, 4666);

	std::vector<Kademlia::CFastKad::NodeKey> knownNodes;
	knownNodes.push_back(Kademlia::CFastKad::NodeKey(uKnownNode, 4665));
	writer.SaveNodesMetadata(strPath, knownNodes);

	Kademlia::CFastKad reader;
	reader.LoadNodesMetadata(strPath);
	CHECK(reader.GetBootstrapPriority(uKnownNode, 4665) > 0);
	CHECK(reader.GetBootstrapPriority(uDormantNode, 4666) > 0);

	::DeleteFile(strPath);
}

TEST_CASE("Fast Kad bootstrap priority prefers recent healthy nodes and keys metadata by Kad ID plus UDP port")
{
	const CString strRecentPath = CreateFastKadTempPath();
	const CString strStalePath = CreateFastKadTempPath();
	const Kademlia::CUInt128 uNodeID(33ul);
	const uint64 uNow = static_cast<uint64>(time(NULL));

	WriteFastKadFixture(strRecentPath, uNodeID, 4665, uNow, 1200, 40);
	WriteFastKadFixture(strStalePath, uNodeID, 4666, uNow - (120ull * 24ull * 60ull * 60ull), 1200, -40);

	Kademlia::CFastKad fastKad;
	fastKad.LoadNodesMetadata(strRecentPath);
	const uint64 uRecentPriority = fastKad.GetBootstrapPriority(uNodeID, 4665);
	CHECK(uRecentPriority > 0);
	CHECK_EQ(fastKad.GetBootstrapPriority(uNodeID, 4666), 0ull);

	fastKad.LoadNodesMetadata(strStalePath);
	const uint64 uStalePriority = fastKad.GetBootstrapPriority(uNodeID, 4666);
	CHECK(uStalePriority > 0);
	CHECK(uRecentPriority > uStalePriority);

	::DeleteFile(strRecentPath);
	::DeleteFile(strStalePath);
}

TEST_CASE("Nodes.dat inspector accepts valid regular and bootstrap-only candidates")
{
	const CString strRegularPath = CreateFastKadTempPath();
	const CString strBootstrapPath = CreateFastKadTempPath();
	WriteNodesDatFixture(strRegularPath, false);
	WriteNodesDatFixture(strBootstrapPath, true);

	Kademlia::NodesDatFileInfo regularInfo;
	Kademlia::NodesDatFileInfo bootstrapInfo;
	CHECK(Kademlia::InspectNodesDatFile(strRegularPath, regularInfo));
	CHECK_EQ(regularInfo.m_uUsableContacts, 1u);
	CHECK_FALSE(regularInfo.m_bBootstrapOnly);
	CHECK(Kademlia::InspectNodesDatFile(strBootstrapPath, bootstrapInfo));
	CHECK_EQ(bootstrapInfo.m_uUsableContacts, 1u);
	CHECK(bootstrapInfo.m_bBootstrapOnly);

	::DeleteFile(strRegularPath);
	::DeleteFile(strBootstrapPath);
}

TEST_CASE("Nodes.dat inspector rejects malformed files without reporting usable contacts")
{
	const CString strPath = CreateFastKadTempPath();
	FILE *pFile = NULL;
	REQUIRE(_wfopen_s(&pFile, strPath, L"wb") == 0);
	REQUIRE(pFile != NULL);
	const uint32 uHeader = 0;
	const uint32 uVersion = 2;
	const uint32 uCount = 1;
	REQUIRE(fwrite(&uHeader, 1, sizeof uHeader, pFile) == sizeof uHeader);
	REQUIRE(fwrite(&uVersion, 1, sizeof uVersion, pFile) == sizeof uVersion);
	REQUIRE(fwrite(&uCount, 1, sizeof uCount, pFile) == sizeof uCount);
	fclose(pFile);

	Kademlia::NodesDatFileInfo fileInfo;
	CHECK_FALSE(Kademlia::InspectNodesDatFile(strPath, fileInfo));
	CHECK_EQ(fileInfo.m_uUsableContacts, 0u);

	::DeleteFile(strPath);
}

TEST_CASE("Nodes.dat inspector excludes private and zero-port contacts from usable counts")
{
	const CString strPath = CreateFastKadTempPath();
	FILE *pFile = NULL;
	REQUIRE(_wfopen_s(&pFile, strPath, L"wb") == 0);
	REQUIRE(pFile != NULL);

	const uint32 uHeader = 0;
	const uint32 uVersion = 2;
	const uint32 uCount = 2;
	const byte abyID[16] = { 1 };
	const uint32 uPrivateStoredIP = 0x0101A8C0u; // 192.168.1.1 stored in nodes.dat byte order
	const uint32 uPublicStoredIP = 0x01020304u;
	const uint16 uZeroPort = 0;
	const uint16 uValidPort = 4665;
	const uint16 uTCPPort = 4662;
	const uint8 uContactVersion = 8;
	const uint32 uUDPKey = 0x11111111u;
	const uint32 uUDPKeyIP = 0x22222222u;
	const uint8 uVerified = 1;

	REQUIRE(fwrite(&uHeader, 1, sizeof uHeader, pFile) == sizeof uHeader);
	REQUIRE(fwrite(&uVersion, 1, sizeof uVersion, pFile) == sizeof uVersion);
	REQUIRE(fwrite(&uCount, 1, sizeof uCount, pFile) == sizeof uCount);

	REQUIRE(fwrite(abyID, 1, sizeof abyID, pFile) == sizeof abyID);
	REQUIRE(fwrite(&uPrivateStoredIP, 1, sizeof uPrivateStoredIP, pFile) == sizeof uPrivateStoredIP);
	REQUIRE(fwrite(&uValidPort, 1, sizeof uValidPort, pFile) == sizeof uValidPort);
	REQUIRE(fwrite(&uTCPPort, 1, sizeof uTCPPort, pFile) == sizeof uTCPPort);
	REQUIRE(fwrite(&uContactVersion, 1, sizeof uContactVersion, pFile) == sizeof uContactVersion);
	REQUIRE(fwrite(&uUDPKey, 1, sizeof uUDPKey, pFile) == sizeof uUDPKey);
	REQUIRE(fwrite(&uUDPKeyIP, 1, sizeof uUDPKeyIP, pFile) == sizeof uUDPKeyIP);
	REQUIRE(fwrite(&uVerified, 1, sizeof uVerified, pFile) == sizeof uVerified);

	REQUIRE(fwrite(abyID, 1, sizeof abyID, pFile) == sizeof abyID);
	REQUIRE(fwrite(&uPublicStoredIP, 1, sizeof uPublicStoredIP, pFile) == sizeof uPublicStoredIP);
	REQUIRE(fwrite(&uZeroPort, 1, sizeof uZeroPort, pFile) == sizeof uZeroPort);
	REQUIRE(fwrite(&uTCPPort, 1, sizeof uTCPPort, pFile) == sizeof uTCPPort);
	REQUIRE(fwrite(&uContactVersion, 1, sizeof uContactVersion, pFile) == sizeof uContactVersion);
	REQUIRE(fwrite(&uUDPKey, 1, sizeof uUDPKey, pFile) == sizeof uUDPKey);
	REQUIRE(fwrite(&uUDPKeyIP, 1, sizeof uUDPKeyIP, pFile) == sizeof uUDPKeyIP);
	REQUIRE(fwrite(&uVerified, 1, sizeof uVerified, pFile) == sizeof uVerified);
	fclose(pFile);

	Kademlia::NodesDatFileInfo fileInfo;
	CHECK(Kademlia::InspectNodesDatFile(strPath, fileInfo));
	CHECK_EQ(fileInfo.m_uUsableContacts, 0u);

	::DeleteFile(strPath);
}

TEST_CASE("Nodes.dat replacement atomically swaps the target file contents")
{
	const CString strTargetPath = CreateFastKadTempPath();
	const CString strSourcePath = CreateFastKadTempPath();

	FILE *pTarget = NULL;
	REQUIRE(_wfopen_s(&pTarget, strTargetPath, L"wb") == 0);
	REQUIRE(pTarget != NULL);
	const char szOldData[] = "old";
	REQUIRE(fwrite(szOldData, 1, sizeof szOldData, pTarget) == sizeof szOldData);
	fclose(pTarget);

	FILE *pSource = NULL;
	REQUIRE(_wfopen_s(&pSource, strSourcePath, L"wb") == 0);
	REQUIRE(pSource != NULL);
	const char szNewData[] = "new";
	REQUIRE(fwrite(szNewData, 1, sizeof szNewData, pSource) == sizeof szNewData);
	fclose(pSource);

	CHECK(Kademlia::ReplaceNodesDatFile(strSourcePath, strTargetPath));
	CHECK_FALSE(::PathFileExists(strSourcePath));
	const std::vector<char> targetData = ReadWholeFile(strTargetPath);
	CHECK_EQ(targetData.size(), sizeof szNewData);
	CHECK(std::equal(targetData.begin(), targetData.end(), szNewData));

	::DeleteFile(strTargetPath);
}

TEST_CASE("Kad persistence seams validate preferences candidates before promotion")
{
	const CString strTargetPath = CreateFastKadTempPath();
	const CString strGoodPath = CreateFastKadTempPath();
	const CString strTruncatedPath = CreateFastKadTempPath();

	WriteKadPrefsFixture(strTargetPath, true);
	WriteKadPrefsFixture(strGoodPath, true);
	WriteKadPrefsFixture(strTruncatedPath, false);

	CHECK(Kademlia::InspectKadPrefsCandidate(strGoodPath));
	CHECK_FALSE(Kademlia::InspectKadPrefsCandidate(strTruncatedPath));

	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(Kademlia::InstallPreparedKadPrefsCandidate(strTruncatedPath, strTargetPath, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_DATA));
	CHECK(Kademlia::InspectKadPrefsCandidate(strTargetPath));

	::DeleteFile(strTargetPath);
	::DeleteFile(strGoodPath);
	::DeleteFile(strTruncatedPath);
}

TEST_CASE("Kad preferences promotion failure leaves live file intact")
{
	const CString strTargetPath = CreateFastKadTempPath();
	const CString strSourcePath = CreateFastKadTempPath();

	FILE *pTarget = NULL;
	REQUIRE(_wfopen_s(&pTarget, strTargetPath, L"wb") == 0);
	REQUIRE(pTarget != NULL);
	const char szOldData[] = "old prefs";
	REQUIRE(fwrite(szOldData, 1, sizeof szOldData, pTarget) == sizeof szOldData);
	fclose(pTarget);

	WriteKadPrefsFixture(strSourcePath, true);

	DWORD dwLastError = ERROR_SUCCESS;
	const PartFilePersistenceSeams::FileSystemOps ops = MakePromotionFailureOps();
	CHECK_FALSE(Kademlia::PromotePreparedKadFileWithOps(strSourcePath, strTargetPath, &dwLastError, ops));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_ACCESS_DENIED));
	CHECK(::PathFileExists(strSourcePath));

	const std::vector<char> targetData = ReadWholeFile(strTargetPath);
	CHECK_EQ(targetData.size(), sizeof szOldData);
	CHECK(std::equal(targetData.begin(), targetData.end(), szOldData));

	::DeleteFile(strTargetPath);
	::DeleteFile(strSourcePath);
}

TEST_CASE("Nodes.dat replacement failure leaves live file intact and candidate available")
{
	const CString strTargetPath = CreateFastKadTempPath();
	const CString strSourcePath = CreateFastKadTempPath();

	FILE *pTarget = NULL;
	REQUIRE(_wfopen_s(&pTarget, strTargetPath, L"wb") == 0);
	REQUIRE(pTarget != NULL);
	const char szOldData[] = "old nodes";
	REQUIRE(fwrite(szOldData, 1, sizeof szOldData, pTarget) == sizeof szOldData);
	fclose(pTarget);

	WriteNodesDatFixture(strSourcePath, false);

	DWORD dwLastError = ERROR_SUCCESS;
	const PartFilePersistenceSeams::FileSystemOps ops = MakePromotionFailureOps();
	CHECK_FALSE(Kademlia::ReplaceNodesDatFileWithOps(strSourcePath, strTargetPath, &dwLastError, ops));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_ACCESS_DENIED));
	CHECK(::PathFileExists(strSourcePath));

	const std::vector<char> targetData = ReadWholeFile(strTargetPath);
	CHECK_EQ(targetData.size(), sizeof szOldData);
	CHECK(std::equal(targetData.begin(), targetData.end(), szOldData));

	::DeleteFile(strTargetPath);
	::DeleteFile(strSourcePath);
}

TEST_CASE("Nodes.dat install rejects malformed candidates and preserves live file")
{
	const CString strTargetPath = CreateFastKadTempPath();
	const CString strMalformedPath = CreateFastKadTempPath();

	FILE *pTarget = NULL;
	REQUIRE(_wfopen_s(&pTarget, strTargetPath, L"wb") == 0);
	REQUIRE(pTarget != NULL);
	const char szOldData[] = "old nodes";
	REQUIRE(fwrite(szOldData, 1, sizeof szOldData, pTarget) == sizeof szOldData);
	fclose(pTarget);

	FILE *pCandidate = NULL;
	REQUIRE(_wfopen_s(&pCandidate, strMalformedPath, L"wb") == 0);
	REQUIRE(pCandidate != NULL);
	const uint32 uHeader = 0;
	const uint32 uVersion = 2;
	const uint32 uCount = 1;
	REQUIRE(fwrite(&uHeader, 1, sizeof uHeader, pCandidate) == sizeof uHeader);
	REQUIRE(fwrite(&uVersion, 1, sizeof uVersion, pCandidate) == sizeof uVersion);
	REQUIRE(fwrite(&uCount, 1, sizeof uCount, pCandidate) == sizeof uCount);
	fclose(pCandidate);

	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(Kademlia::InstallPreparedNodesDatFile(strMalformedPath, strTargetPath, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_DATA));

	const std::vector<char> targetData = ReadWholeFile(strTargetPath);
	CHECK_EQ(targetData.size(), sizeof szOldData);
	CHECK(std::equal(targetData.begin(), targetData.end(), szOldData));

	::DeleteFile(strTargetPath);
	::DeleteFile(strMalformedPath);
}

TEST_CASE("Nodes.dat install rejects bootstrap-only candidates and preserves live file")
{
	const CString strTargetPath = CreateFastKadTempPath();
	const CString strBootstrapPath = CreateFastKadTempPath();

	FILE *pTarget = NULL;
	REQUIRE(_wfopen_s(&pTarget, strTargetPath, L"wb") == 0);
	REQUIRE(pTarget != NULL);
	const char szOldData[] = "old nodes";
	REQUIRE(fwrite(szOldData, 1, sizeof szOldData, pTarget) == sizeof szOldData);
	fclose(pTarget);

	WriteNodesDatFixture(strBootstrapPath, true);

	DWORD dwLastError = ERROR_SUCCESS;
	CHECK_FALSE(Kademlia::InstallPreparedNodesDatFile(strBootstrapPath, strTargetPath, &dwLastError));
	CHECK_EQ(dwLastError, static_cast<DWORD>(ERROR_INVALID_DATA));

	const std::vector<char> targetData = ReadWholeFile(strTargetPath);
	CHECK_EQ(targetData.size(), sizeof szOldData);
	CHECK(std::equal(targetData.begin(), targetData.end(), szOldData));

	::DeleteFile(strTargetPath);
	::DeleteFile(strBootstrapPath);
}

TEST_CASE("Kad persistence seams preserve bootstrap guard and Fast Kad sidecar ordering")
{
	CHECK(Kademlia::ShouldSkipNodesDatSaveForBootstrapOnly(true, 0));
	CHECK_FALSE(Kademlia::ShouldSkipNodesDatSaveForBootstrapOnly(true, 1));
	CHECK_FALSE(Kademlia::ShouldSkipNodesDatSaveForBootstrapOnly(false, 0));

	CHECK(Kademlia::ShouldSaveFastKadSidecarAfterNodesPromotion(true));
	CHECK_FALSE(Kademlia::ShouldSaveFastKadSidecarAfterNodesPromotion(false));
}

TEST_CASE("Safe Kad bans a verified node that flips identities too quickly when strict mode is enabled")
{
	Kademlia::CSafeKad safeKad;
	safeKad.TrackNode(0x01020304u, 4665, Kademlia::CUInt128(1ul), true, true);

	CHECK(safeKad.IsBadNode(0x01020304u, 4665, Kademlia::CUInt128(2ul), KADEMLIA_VERSION8_49b, true, false, true));
	CHECK(safeKad.IsBanned(0x01020304u));
}

TEST_CASE("Safe Kad keeps problematic nodes only until the runtime cache is reset")
{
	Kademlia::CSafeKad safeKad;
	safeKad.TrackProblematicNode(0x0A000001u, 4672);
	CHECK(safeKad.IsProblematic(0x0A000001u, 4672));

	safeKad.ShutdownCleanup();
	CHECK_FALSE(safeKad.IsProblematic(0x0A000001u, 4672));
}

TEST_CASE("Safe Kad enforces the one-node-per-IP policy without banning stable identities")
{
	Kademlia::CSafeKad safeKad;
	const uint32 uIP = 0x0A0B0C0Du;

	CHECK_FALSE(safeKad.IsBadNode(uIP, 4665, Kademlia::CUInt128(101ul), KADEMLIA_VERSION8_49b, true, true, false));
	CHECK(safeKad.IsBadNode(uIP, 4666, Kademlia::CUInt128(102ul), KADEMLIA_VERSION8_49b, true, true, false));
	CHECK_FALSE(safeKad.IsBanned(uIP));
}

TEST_CASE("Kad publish guard accepts a valid high-ID source publish")
{
	Kademlia::PublishSourceMetadata metadata;
	metadata.m_bHasSourceType = true;
	metadata.m_uSourceType = 1;
	metadata.m_bHasSourcePort = true;
	metadata.m_uSourcePort = 4662;

	CHECK(Kademlia::ValidatePublishSourceMetadata(metadata));
}

TEST_CASE("Kad publish guard rejects low-ID source publishes without complete buddy information")
{
	Kademlia::PublishSourceMetadata metadata;
	metadata.m_bHasSourceType = true;
	metadata.m_uSourceType = 3;
	metadata.m_bHasSourcePort = true;
	metadata.m_uSourcePort = 4662;
	metadata.m_bHasBuddyIP = true;
	metadata.m_uBuddyIP = 0x05060708u;

	CHECK_FALSE(Kademlia::ValidatePublishSourceMetadata(metadata));
}

TEST_CASE("Kad publish guard accepts low-ID source publishes when the full buddy tuple is present")
{
	Kademlia::PublishSourceMetadata metadata;
	metadata.m_bHasSourceType = true;
	metadata.m_uSourceType = 3;
	metadata.m_bHasSourcePort = true;
	metadata.m_uSourcePort = 4662;
	metadata.m_bHasBuddyIP = true;
	metadata.m_uBuddyIP = 0x05060708u;
	metadata.m_bHasBuddyPort = true;
	metadata.m_uBuddyPort = 4672;
	metadata.m_bHasBuddyHash = true;

	CHECK(Kademlia::ValidatePublishSourceMetadata(metadata));
}

TEST_CASE("Kad publish guard exposes stable source-type classification for source publishes")
{
	CHECK(Kademlia::IsAcceptedPublishSourceType(1));
	CHECK(Kademlia::IsAcceptedPublishSourceType(3));
	CHECK_FALSE(Kademlia::IsAcceptedPublishSourceType(0));
	CHECK_FALSE(Kademlia::IsAcceptedPublishSourceType(7));

	CHECK_FALSE(Kademlia::IsLowIdPublishSourceType(1));
	CHECK(Kademlia::IsLowIdPublishSourceType(3));
}

TEST_CASE("Kad publish guard rejects low-ID publishes that still miss buddy hash or buddy port")
{
	Kademlia::PublishSourceMetadata metadata;
	metadata.m_bHasSourceType = true;
	metadata.m_uSourceType = 3;
	metadata.m_bHasSourcePort = true;
	metadata.m_uSourcePort = 4662;
	metadata.m_bHasBuddyIP = true;
	metadata.m_uBuddyIP = 0x05060708u;
	metadata.m_bHasBuddyPort = true;
	metadata.m_uBuddyPort = 4672;
	CHECK_FALSE(Kademlia::ValidatePublishSourceMetadata(metadata));

	metadata.m_bHasBuddyHash = true;
	metadata.m_bHasBuddyPort = false;
	CHECK_FALSE(Kademlia::ValidatePublishSourceMetadata(metadata));
}

TEST_CASE("Kad publish guard escalates repeated publish-source requests from the same IP")
{
	Kademlia::CKadPublishSourceThrottle throttle;
	uint32 dwNow = 1000;

	for (uint32 uCount = 0; uCount < 10; ++uCount)
		CHECK_EQ(throttle.TrackRequest(0x11223344u, dwNow, 10), Kademlia::KPUBLISH_ALLOW);

	CHECK_EQ(throttle.TrackRequest(0x11223344u, dwNow, 10), Kademlia::KPUBLISH_DROP);

	for (uint32 uCount = 0; uCount < 20; ++uCount)
		throttle.TrackRequest(0x11223344u, dwNow, 10);

	CHECK_EQ(throttle.TrackRequest(0x11223344u, dwNow, 10), Kademlia::KPUBLISH_BAN);
}

TEST_CASE("Kad publish throttle reset clears prior ban state and isolates different IPs")
{
	Kademlia::CKadPublishSourceThrottle throttle;
	uint32 dwNow = 2000;

	for (uint32 uCount = 0; uCount < 12; ++uCount)
		throttle.TrackRequest(0x11223344u, dwNow, 10);

	CHECK_EQ(throttle.TrackRequest(0x55667788u, dwNow, 10), Kademlia::KPUBLISH_ALLOW);

	throttle.Reset();
	CHECK_EQ(throttle.TrackRequest(0x11223344u, dwNow, 10), Kademlia::KPUBLISH_ALLOW);
}

TEST_CASE("Kad publish throttle reopens the window after one minute and drops stale entries on cleanup")
{
	Kademlia::CKadPublishSourceThrottle throttle;
	const uint32 uIP = 0x12345678u;
	uint32 dwNow = 5000;

	for (uint32 uCount = 0; uCount < 12; ++uCount)
		throttle.TrackRequest(uIP, dwNow, 10);
	CHECK_EQ(throttle.TrackRequest(uIP, dwNow, 10), Kademlia::KPUBLISH_DROP);

	dwNow += 60000;
	CHECK_EQ(throttle.TrackRequest(uIP, dwNow, 10), Kademlia::KPUBLISH_ALLOW);

	dwNow += 11 * 60000;
	CHECK_EQ(throttle.TrackRequest(0x87654321u, dwNow, 10), Kademlia::KPUBLISH_ALLOW);
	CHECK_EQ(throttle.TrackRequest(uIP, dwNow, 10), Kademlia::KPUBLISH_ALLOW);
}

TEST_CASE("Kad publish guard accepts additional supported source types only with complete low-ID buddy tuples")
{
	Kademlia::PublishSourceMetadata metadata;
	metadata.m_bHasSourceType = true;
	metadata.m_uSourceType = 5;
	metadata.m_bHasSourcePort = true;
	metadata.m_uSourcePort = 4662;
	CHECK_FALSE(Kademlia::ValidatePublishSourceMetadata(metadata));

	metadata.m_bHasBuddyIP = true;
	metadata.m_uBuddyIP = 0x05060708u;
	metadata.m_bHasBuddyPort = true;
	metadata.m_uBuddyPort = 4672;
	metadata.m_bHasBuddyHash = true;
	CHECK(Kademlia::ValidatePublishSourceMetadata(metadata));
}

TEST_CASE("Safe Kad leaves stable verified identities alone and tolerates cleanup on empty state")
{
	Kademlia::CSafeKad safeKad;
	safeKad.TrackNode(0x01020304u, 4665, Kademlia::CUInt128(1ul), true, true);

	CHECK_FALSE(safeKad.IsBadNode(0x01020304u, 4665, Kademlia::CUInt128(1ul), KADEMLIA_VERSION8_49b, true, false, true));
	safeKad.ShutdownCleanup();
	safeKad.ShutdownCleanup();
	CHECK_FALSE(safeKad.IsProblematic(0x01020304u, 4665));
}

TEST_SUITE_END;
