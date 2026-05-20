#include "../third_party/doctest/doctest.h"

#include "DownloadQueueDiskSpaceSeams.h"
#include "LongPathSeams.h"

#include <iterator>
#include <string>

#include <atlstr.h>

namespace
{
	using DownloadQueueDiskSpaceSeams::FileDiskSpaceState;
	using DownloadQueueDiskSpaceSeams::FileDiskSpaceStatus;
	using DownloadQueueDiskSpaceSeams::ProtectedVolumeSpaceState;
	using DownloadQueueDiskSpaceSeams::ProtectedVolumeAvailability;
	using DownloadQueueDiskSpaceSeams::RequiredFreeSpacePathCacheKey;
	using DownloadQueueDiskSpaceSeams::TempDirPlacementDecision;
	using DownloadQueueDiskSpaceSeams::TempDirVolumeCandidate;
	using DownloadQueueDiskSpaceSeams::VolumeIdentity;
	using DownloadQueueDiskSpaceSeams::VolumeKey;
	using DownloadQueueDiskSpaceSeams::VolumeResumeBudget;

	constexpr uint64_t kGiB = 1024ull * 1024ull * 1024ull;

	VolumeKey MakeDriveVolumeKey(const int iDriveNumber)
	{
		VolumeKey volumeKey = { iDriveNumber, std::wstring() };
		return volumeKey;
	}

	VolumeKey MakeShareVolumeKey(const wchar_t *pszShareName)
	{
		VolumeKey volumeKey = { -1, pszShareName != NULL ? std::wstring(pszShareName) : std::wstring() };
		return volumeKey;
	}

	FileDiskSpaceState MakeFileDiskSpaceState(const FileDiskSpaceStatus eStatus, const VolumeKey &rVolumeKey, const bool bIsNormalFile, const uint64_t nNeededBytes)
	{
		FileDiskSpaceState state = { eStatus, rVolumeKey, bIsNormalFile, nNeededBytes };
		return state;
	}

	VolumeResumeBudget MakeVolumeResumeBudget(const VolumeKey &rVolumeKey, const uint64_t nFreeBytes, const uint64_t nResumeHeadroomBytes = 0u)
	{
		VolumeResumeBudget budget = { rVolumeKey, nFreeBytes, nResumeHeadroomBytes };
		return budget;
	}

	RequiredFreeSpacePathCacheKey NormalizePathCacheKey(LPCTSTR pszPath)
	{
		return DownloadQueueDiskSpaceSeams::NormalizeRequiredFreeSpacePathCacheKey(RequiredFreeSpacePathCacheKey(pszPath));
	}

	ProtectedVolumeAvailability MakeVolumeAvailability(LPCTSTR pszVolumeId, const int64_t nAvailableBytes)
	{
		ProtectedVolumeAvailability availability = { VolumeIdentity(pszVolumeId), nAvailableBytes };
		return availability;
	}

	TempDirVolumeCandidate MakeTempCandidate(LPCTSTR pszVolumeId, const bool bFatVolume = false)
	{
		TempDirVolumeCandidate candidate = { VolumeIdentity(pszVolumeId), bFatVolume };
		return candidate;
	}

	TempDirPlacementDecision SelectTempDir(
		const TempDirVolumeCandidate *pCandidates,
		const std::size_t nCandidateCount,
		const ProtectedVolumeAvailability *pVolumes,
		const std::size_t nVolumeCount,
		const VolumeIdentity &rIncomingVolumeId,
		const uint64_t nFileSize)
	{
		return DownloadQueueDiskSpaceSeams::SelectTempDirForProtectedVolumeSnapshot(
			pCandidates,
			nCandidateCount,
			pVolumes,
			nVolumeCount,
			rIncomingVolumeId,
			nFileSize,
			0x00000000FFC00000ull);
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Queue disk-space seam detects protected-volume threshold breaches")
{
	const ProtectedVolumeSpaceState exactFit = { 1024u, 1024u };
	const ProtectedVolumeSpaceState aboveFloor = { 1025u, 1024u };
	const ProtectedVolumeSpaceState belowFloor = { 1023u, 1024u };
	const ProtectedVolumeSpaceState unresolvedWithFloor = {
		DownloadQueueDiskSpaceSeams::GetUnresolvedProtectedVolumeFreeBytes(),
		1024u
	};

	CHECK_FALSE(DownloadQueueDiskSpaceSeams::IsProtectedVolumeBreached(exactFit));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::IsProtectedVolumeBreached(aboveFloor));
	CHECK(DownloadQueueDiskSpaceSeams::IsProtectedVolumeBreached(belowFloor));
	CHECK(DownloadQueueDiskSpaceSeams::IsProtectedVolumeBreached(unresolvedWithFloor));
}

TEST_CASE("Queue disk-space seam detects any protected-volume breach in a snapshot")
{
	const ProtectedVolumeSpaceState allClear[] = {
		{ 2u * 1024u, 1024u },
		{ 4096u, 4096u }
	};
	const ProtectedVolumeSpaceState withBreach[] = {
		{ 2u * 1024u, 1024u },
		{ 4095u, 4096u }
	};

	CHECK_FALSE(DownloadQueueDiskSpaceSeams::HasProtectedVolumeBreach(NULL, 2u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::HasProtectedVolumeBreach(allClear, std::size(allClear)));
	CHECK(DownloadQueueDiskSpaceSeams::HasProtectedVolumeBreach(withBreach, std::size(withBreach)));
}

TEST_CASE("Queue disk-space seam keeps repeated breach enforcement but suppresses duplicate logs")
{
	const DownloadQueueDiskSpaceSeams::ProtectedDiskSpaceBreachAction clearAction =
		DownloadQueueDiskSpaceSeams::ResolveProtectedDiskSpaceBreachAction(false, true, true);
	CHECK(clearAction.ShouldClearBlock);
	CHECK_FALSE(clearAction.ShouldLogBreach);
	CHECK_FALSE(clearAction.ShouldStopDownloads);
	CHECK_FALSE(clearAction.ShouldRememberBlock);

	const DownloadQueueDiskSpaceSeams::ProtectedDiskSpaceBreachAction firstBreachAction =
		DownloadQueueDiskSpaceSeams::ResolveProtectedDiskSpaceBreachAction(true, false, false);
	CHECK_FALSE(firstBreachAction.ShouldClearBlock);
	CHECK(firstBreachAction.ShouldLogBreach);
	CHECK(firstBreachAction.ShouldStopDownloads);
	CHECK(firstBreachAction.ShouldRememberBlock);

	const DownloadQueueDiskSpaceSeams::ProtectedDiskSpaceBreachAction repeatedBreachAction =
		DownloadQueueDiskSpaceSeams::ResolveProtectedDiskSpaceBreachAction(true, true, true);
	CHECK_FALSE(repeatedBreachAction.ShouldClearBlock);
	CHECK_FALSE(repeatedBreachAction.ShouldLogBreach);
	CHECK(repeatedBreachAction.ShouldStopDownloads);
	CHECK(repeatedBreachAction.ShouldRememberBlock);
}

TEST_CASE("Queue disk-space seam invalidates cached path requirements only after reserved snapshot demand")
{
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldReserveProtectedVolumeSnapshotDemand(false, false, 1024u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldReserveProtectedVolumeSnapshotDemand(true, true, 1024u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldReserveProtectedVolumeSnapshotDemand(true, false, 0u));
	CHECK(DownloadQueueDiskSpaceSeams::ShouldReserveProtectedVolumeSnapshotDemand(true, false, 1024u));

	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldInvalidateRequiredFreeSpacePathCacheAfterReservation(false));
	CHECK(DownloadQueueDiskSpaceSeams::ShouldInvalidateRequiredFreeSpacePathCacheAfterReservation(true));
}

TEST_CASE("Queue disk-space seam fails closed when snapshot demand cannot be fully reserved")
{
	CHECK(DownloadQueueDiskSpaceSeams::WasProtectedVolumeSnapshotDemandFullyReserved(false, false, false, false));
	CHECK(DownloadQueueDiskSpaceSeams::WasProtectedVolumeSnapshotDemandFullyReserved(true, true, false, false));
	CHECK(DownloadQueueDiskSpaceSeams::WasProtectedVolumeSnapshotDemandFullyReserved(true, true, true, true));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::WasProtectedVolumeSnapshotDemandFullyReserved(true, false, false, false));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::WasProtectedVolumeSnapshotDemandFullyReserved(true, true, true, false));
}

TEST_CASE("Queue disk-space seam normalizes required-space cache keys")
{
	CHECK(NormalizePathCacheKey(_T("C:/Temp/eMule/Incoming/")) == NormalizePathCacheKey(_T("c:\\temp\\emule\\incoming")));
	CHECK(NormalizePathCacheKey(_T("D:\\")) == RequiredFreeSpacePathCacheKey(_T("d:\\")));
}

TEST_CASE("Queue disk-space production flow treats mounted temp and parent incoming as distinct volumes")
{
	const VolumeIdentity parentVolume(_T("\\\\?\\Volume{parent-drive}\\"));
	const VolumeIdentity mountedVolume(_T("\\\\?\\Volume{mounted-temp}\\"));
	const TempDirVolumeCandidate tempCandidates[] = {
		MakeTempCandidate(mountedVolume.c_str())
	};
	ProtectedVolumeAvailability volumes[] = {
		MakeVolumeAvailability(parentVolume.c_str(), static_cast<int64_t>(8u * kGiB)),
		MakeVolumeAvailability(mountedVolume.c_str(), static_cast<int64_t>(10u * kGiB))
	};

	const TempDirPlacementDecision enoughIncoming = SelectTempDir(
		tempCandidates,
		std::size(tempCandidates),
		volumes,
		std::size(volumes),
		parentVolume,
		5u * kGiB);
	CHECK(enoughIncoming.HasSelection);
	CHECK_EQ(enoughIncoming.CandidateIndex, 0u);

	volumes[0].AvailableBytes = static_cast<int64_t>(4u * kGiB);
	const TempDirPlacementDecision lowIncoming = SelectTempDir(
		tempCandidates,
		std::size(tempCandidates),
		volumes,
		std::size(volumes),
		parentVolume,
		5u * kGiB);
	CHECK_FALSE(lowIncoming.HasSelection);
}

TEST_CASE("Queue disk-space production flow accepts same mounted temp and incoming volume without double-reserving")
{
	const VolumeIdentity mountedVolume(_T("\\\\?\\Volume{mounted-shared}\\"));
	const TempDirVolumeCandidate tempCandidates[] = {
		MakeTempCandidate(mountedVolume.c_str())
	};
	const ProtectedVolumeAvailability volumes[] = {
		MakeVolumeAvailability(mountedVolume.c_str(), static_cast<int64_t>(6u * kGiB))
	};

	const TempDirPlacementDecision decision = SelectTempDir(
		tempCandidates,
		std::size(tempCandidates),
		volumes,
		std::size(volumes),
		mountedVolume,
		5u * kGiB);
	CHECK(decision.HasSelection);
	CHECK_EQ(decision.CandidateIndex, 0u);
}

TEST_CASE("Queue disk-space production flow fails closed for unresolved mounted temp candidates")
{
	const VolumeIdentity parentVolume(_T("\\\\?\\Volume{parent-drive}\\"));
	const VolumeIdentity unresolvedTemp(_T("#unresolved-volume:c:\\mounts\\missing-temp"));
	const TempDirVolumeCandidate tempCandidates[] = {
		MakeTempCandidate(unresolvedTemp.c_str())
	};
	const ProtectedVolumeAvailability volumes[] = {
		MakeVolumeAvailability(parentVolume.c_str(), static_cast<int64_t>(8u * kGiB)),
		MakeVolumeAvailability(unresolvedTemp.c_str(), 0)
	};

	const TempDirPlacementDecision decision = SelectTempDir(
		tempCandidates,
		std::size(tempCandidates),
		volumes,
		std::size(volumes),
		parentVolume,
		1u * kGiB);
	CHECK_FALSE(decision.HasSelection);
}

TEST_CASE("Queue disk-space seam pauses active normal files only when they still need growth below the floor")
{
	const VolumeKey volumeKey = MakeDriveVolumeKey(2);
	const FileDiskSpaceState growingNormalFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Active, volumeKey, true, 4096u);
	const FileDiskSpaceState fullyAllocatedNormalFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Active, volumeKey, true, 0u);

	CHECK(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(growingNormalFile, 1023u, 1024u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(growingNormalFile, 1024u, 1024u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(fullyAllocatedNormalFile, 1023u, 1024u));
}

TEST_CASE("Queue disk-space seam pauses non-normal active files whenever the floor is breached")
{
	const FileDiskSpaceState sparseFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Active, MakeDriveVolumeKey(3), false, 0u);

	CHECK(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(sparseFile, 0u, 1u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(sparseFile, 1u, 1u));
}

TEST_CASE("Queue disk-space seam never pauses files that are already out of the active download state")
{
	const VolumeKey volumeKey = MakeDriveVolumeKey(4);
	const FileDiskSpaceState pausedFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Paused, volumeKey, true, 1u);
	const FileDiskSpaceState insufficientFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Insufficient, volumeKey, true, 1u);
	const FileDiskSpaceState errorFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Error, volumeKey, true, 1u);
	const FileDiskSpaceState completingFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Completing, volumeKey, true, 1u);
	const FileDiskSpaceState completeFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Complete, volumeKey, true, 1u);

	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(pausedFile, 0u, 1u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(insufficientFile, 0u, 1u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(errorFile, 0u, 1u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(completingFile, 0u, 1u));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldPauseForDiskSpace(completeFile, 0u, 1u));
}

TEST_CASE("Queue disk-space seam never auto-resumes user-paused files and treats forced disk-full as zero free space")
{
	const VolumeKey volumeKey = MakeDriveVolumeKey(8);
	const FileDiskSpaceState pausedFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Paused, volumeKey, true, 1024u);
	const FileDiskSpaceState insufficientFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Insufficient, volumeKey, true, 1024u);
	VolumeResumeBudget budget = MakeVolumeResumeBudget(volumeKey, 0u, 1024u);

	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		pausedFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		insufficientFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
}

TEST_CASE("Queue disk-space production flow follows a real mounted-folder volume when present")
{
	const CString strMountedRoot(_T("C:\\M\\H20T00\\"));
	if (::GetFileAttributes(strMountedRoot) == INVALID_FILE_ATTRIBUTES)
		return;

	LongPathSeams::ResolvedVolumeContext mountedContext = {};
	LongPathSeams::ResolvedVolumeContext parentContext = {};
	DWORD dwError = ERROR_SUCCESS;
	REQUIRE(LongPathSeams::TryResolveContainingVolumeContext(strMountedRoot + _T("probe"), mountedContext, &dwError));
	REQUIRE(LongPathSeams::TryResolveContainingVolumeContext(_T("C:\\"), parentContext, &dwError));
	REQUIRE(mountedContext.strVolumeKey != parentContext.strVolumeKey);

	const VolumeIdentity mountedVolume(mountedContext.strVolumeKey.c_str());
	const VolumeIdentity parentVolume(parentContext.strVolumeKey.c_str());
	const TempDirVolumeCandidate tempCandidates[] = {
		MakeTempCandidate(mountedVolume.c_str())
	};
	ProtectedVolumeAvailability volumes[] = {
		MakeVolumeAvailability(parentVolume.c_str(), static_cast<int64_t>(6u * kGiB)),
		MakeVolumeAvailability(mountedVolume.c_str(), static_cast<int64_t>(10u * kGiB))
	};

	const TempDirPlacementDecision enoughParentIncoming = SelectTempDir(
		tempCandidates,
		std::size(tempCandidates),
		volumes,
		std::size(volumes),
		parentVolume,
		5u * kGiB);
	CHECK(enoughParentIncoming.HasSelection);
	CHECK_EQ(enoughParentIncoming.CandidateIndex, 0u);

	volumes[0].AvailableBytes = static_cast<int64_t>(4u * kGiB);
	const TempDirPlacementDecision lowParentIncoming = SelectTempDir(
		tempCandidates,
		std::size(tempCandidates),
		volumes,
		std::size(volumes),
		parentVolume,
		5u * kGiB);
	CHECK_FALSE(lowParentIncoming.HasSelection);
}

TEST_SUITE_END;

TEST_SUITE_BEGIN("divergence");

TEST_CASE("Queue disk-space seam resumes insufficient files only when the capped hysteresis budget is fully available")
{
	const VolumeKey volumeKey = MakeDriveVolumeKey(5);
	const FileDiskSpaceState insufficientFile = MakeFileDiskSpaceState(
		FileDiskSpaceStatus::Insufficient, volumeKey, true, PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes + 1u);

	VolumeResumeBudget budget = MakeVolumeResumeBudget(volumeKey, 0u);
	DownloadQueueDiskSpaceSeams::AccumulateResumeHeadroom(&budget, insufficientFile);

	CHECK_EQ(budget.ResumeHeadroomBytes, PartFilePersistenceSeams::kMaxInsufficientResumeHeadroomBytes);
	budget.FreeBytes = PartFilePersistenceSeams::kMinDownloadFreeBytes + budget.ResumeHeadroomBytes - 1u;
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		insufficientFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));

	budget.FreeBytes += 1u;
	CHECK(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		insufficientFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
}

TEST_CASE("Queue disk-space seam aggregates insufficient files on the same volume before any auto-resume")
{
	const VolumeKey volumeKey = MakeDriveVolumeKey(6);
	const FileDiskSpaceState firstFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Insufficient, volumeKey, true, 256u * 1024u * 1024u);
	const FileDiskSpaceState secondFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Insufficient, volumeKey, true, 512u * 1024u * 1024u);

	VolumeResumeBudget budget = MakeVolumeResumeBudget(volumeKey, 0u);
	DownloadQueueDiskSpaceSeams::AccumulateResumeHeadroom(&budget, firstFile);
	DownloadQueueDiskSpaceSeams::AccumulateResumeHeadroom(&budget, secondFile);

	CHECK_EQ(budget.ResumeHeadroomBytes, 768u * 1024u * 1024u);
	budget.FreeBytes = PartFilePersistenceSeams::kMinDownloadFreeBytes + budget.ResumeHeadroomBytes - 1u;
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		firstFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		secondFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));

	budget.FreeBytes += 1u;
	CHECK(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		firstFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
	CHECK(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		secondFile, budget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
}

TEST_CASE("Queue disk-space seam isolates auto-resume budgets by temp volume")
{
	const FileDiskSpaceState localFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Insufficient, MakeDriveVolumeKey(7), true, 1024u);
	const FileDiskSpaceState uncFile = MakeFileDiskSpaceState(FileDiskSpaceStatus::Insufficient, MakeShareVolumeKey(L"\\\\server\\share\\"), true, 1024u);

	VolumeResumeBudget localBudget = MakeVolumeResumeBudget(localFile.TempVolumeKey, PartFilePersistenceSeams::kMinDownloadFreeBytes + 1024u, 1024u);
	VolumeResumeBudget uncBudget = MakeVolumeResumeBudget(uncFile.TempVolumeKey, PartFilePersistenceSeams::kMinDownloadFreeBytes + 1024u, 1024u);

	CHECK(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		localFile, localBudget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
	CHECK(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		uncFile, uncBudget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		localFile, uncBudget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
	CHECK_FALSE(DownloadQueueDiskSpaceSeams::ShouldResumeForDiskSpace(
		uncFile, localBudget, PartFilePersistenceSeams::kMinDownloadFreeBytes));
}

TEST_SUITE_END;
