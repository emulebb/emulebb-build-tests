#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include <limits>

#include "AICHMaintenanceSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("AICH maintenance seam derives ordinary raw hash payload sizes without overflow")
{
	uint32 nPayloadSize = 0;

	CHECK(AICHMaintenanceSeams::TryDeriveAICHHashPayloadSize(20u, 4u, &nPayloadSize));
	CHECK_EQ(nPayloadSize, static_cast<uint32>(80u));
	CHECK(AICHMaintenanceSeams::TryDeriveAICHHashPayloadSize(0u, 0u, &nPayloadSize));
	CHECK_EQ(nPayloadSize, static_cast<uint32>(0u));
}

TEST_CASE("AICH maintenance seam rejects raw hash payload sizes that overflow 32-bit file IO spans")
{
	uint32 nPayloadSize = 0;

	CHECK_FALSE(AICHMaintenanceSeams::TryDeriveAICHHashPayloadSize(20u, 4u, NULL));
	CHECK_FALSE(AICHMaintenanceSeams::TryDeriveAICHHashPayloadSize((std::numeric_limits<size_t>::max)(), 2u, &nPayloadSize));
	CHECK_FALSE(AICHMaintenanceSeams::TryDeriveAICHHashPayloadSize(static_cast<size_t>((std::numeric_limits<uint32>::max)()), 2u, &nPayloadSize));
}

#if defined(EMULE_TEST_HAVE_AICH_HASH_INDEX_BUCKET_ESTIMATE)
TEST_CASE("AICH maintenance seam estimates bounded known2 hash index buckets")
{
	CHECK_EQ(AICHMaintenanceSeams::EstimateAICHHashIndexBucketCount(0u, 20u), AICHMaintenanceSeams::kMinAICHHashIndexBucketCount);
	CHECK_EQ(AICHMaintenanceSeams::EstimateAICHHashIndexBucketCount(1u, 20u), AICHMaintenanceSeams::kMinAICHHashIndexBucketCount);
	CHECK_EQ(AICHMaintenanceSeams::EstimateAICHHashIndexBucketCount(1u + 24u * 1000u, 20u), static_cast<UINT>(2001u));
	CHECK_EQ(AICHMaintenanceSeams::EstimateAICHHashIndexBucketCount((std::numeric_limits<ULONGLONG>::max)(), 20u), AICHMaintenanceSeams::kMaxAICHHashIndexBucketCount);
	CHECK_EQ(AICHMaintenanceSeams::EstimateAICHHashIndexBucketCount(1024u, 0u), AICHMaintenanceSeams::kMinAICHHashIndexBucketCount);
}
#endif

TEST_CASE("AICH maintenance seam yields briefly for foreground hashing and exits immediately on shutdown")
{
	const AICHSyncForegroundWaitAction waitingAction = AICHMaintenanceSeams::GetForegroundHashWaitAction({false, 1, false});
	CHECK_FALSE(waitingAction.bShouldExit);
	CHECK_EQ(waitingAction.dwSleepMilliseconds, static_cast<DWORD>(AICHMaintenanceSeams::kForegroundHashYieldDelayMs));

	const AICHSyncForegroundWaitAction idleAction = AICHMaintenanceSeams::GetForegroundHashWaitAction({false, 0, false});
	CHECK_FALSE(idleAction.bShouldExit);
	CHECK_EQ(idleAction.dwSleepMilliseconds, static_cast<DWORD>(0u));

	const AICHSyncForegroundWaitAction pendingPartAction = AICHMaintenanceSeams::GetForegroundHashWaitAction({false, 0, true});
	CHECK_FALSE(pendingPartAction.bShouldExit);
	CHECK_EQ(pendingPartAction.dwSleepMilliseconds, static_cast<DWORD>(AICHMaintenanceSeams::kForegroundHashYieldDelayMs));

	const AICHSyncForegroundWaitAction shutdownAction = AICHMaintenanceSeams::GetForegroundHashWaitAction({true, 3, true});
	CHECK(shutdownAction.bShouldExit);
	CHECK_EQ(shutdownAction.dwSleepMilliseconds, static_cast<DWORD>(0u));
}

TEST_CASE("AICH maintenance seam keeps the newest stored duplicate hash position")
{
	const StoredAICHHashUpdate olderDuplicate = AICHMaintenanceSeams::ResolveStoredAICHHashUpdate(40u, 30u);
	CHECK_FALSE(olderDuplicate.bShouldReplaceExisting);
	CHECK_EQ(olderDuplicate.nReplacedFilePos, static_cast<ULONGLONG>(0u));

	const StoredAICHHashUpdate newerDuplicate = AICHMaintenanceSeams::ResolveStoredAICHHashUpdate(40u, 55u);
	CHECK(newerDuplicate.bShouldReplaceExisting);
	CHECK_EQ(newerDuplicate.nReplacedFilePos, static_cast<ULONGLONG>(40u));

	const StoredAICHHashUpdate equalDuplicate = AICHMaintenanceSeams::ResolveStoredAICHHashUpdate(55u, 55u);
	CHECK_FALSE(equalDuplicate.bShouldReplaceExisting);
	CHECK_EQ(equalDuplicate.nReplacedFilePos, static_cast<ULONGLONG>(0u));
}

TEST_CASE("AICH maintenance seam invalidates malformed one-sided tree nodes")
{
	const IncompleteAICHTreeNodeAction incompleteLeft = AICHMaintenanceSeams::GetIncompleteAICHTreeNodeAction(true, false);
	CHECK(incompleteLeft.bHasIncompleteChildren);
	CHECK(incompleteLeft.bShouldInvalidateNodeHash);

	const IncompleteAICHTreeNodeAction incompleteRight = AICHMaintenanceSeams::GetIncompleteAICHTreeNodeAction(false, true);
	CHECK(incompleteRight.bHasIncompleteChildren);
	CHECK(incompleteRight.bShouldInvalidateNodeHash);

	const IncompleteAICHTreeNodeAction completeNode = AICHMaintenanceSeams::GetIncompleteAICHTreeNodeAction(true, true);
	CHECK_FALSE(completeNode.bHasIncompleteChildren);
	CHECK_FALSE(completeNode.bShouldInvalidateNodeHash);

	const IncompleteAICHTreeNodeAction emptyNode = AICHMaintenanceSeams::GetIncompleteAICHTreeNodeAction(false, false);
	CHECK_FALSE(emptyNode.bHasIncompleteChildren);
	CHECK_FALSE(emptyNode.bShouldInvalidateNodeHash);
}

TEST_SUITE_END;
