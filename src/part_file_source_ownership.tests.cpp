#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include "PartFileSourceOwnershipSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Part-file source ownership detaches download references before failed reask delete")
{
	PartFileSourceOwnershipState state = PartFileSourceOwnershipSeams::CreateLiveDownloadSourceState();

	const PartFileSourceAskOutcome outcome = PartFileSourceOwnershipSeams::ApplyImmediateTryToConnectFailure(state);

	CHECK(outcome == PartFileSourceAskOutcome::CallerOwnsFailedSource);
	CHECK(state.bCallerOwnsDelete);
	CHECK(state.bDeadSourceTracked);
	CHECK_FALSE(PartFileSourceOwnershipSeams::HasDownloadOwnerReferences(state));

	PartFileSourceOwnershipSeams::DeleteCallerOwnedFailedSource(state);

	CHECK(state.bDeleted);
	CHECK_FALSE(state.bKnownClient);
	CHECK_EQ(state.nDeleteCount, 1u);
}

TEST_CASE("Part-file source ownership rejects double delete after failed reask")
{
	PartFileSourceOwnershipState state = PartFileSourceOwnershipSeams::CreateLiveDownloadSourceState();

	(void)PartFileSourceOwnershipSeams::ApplyImmediateTryToConnectFailure(state);
	PartFileSourceOwnershipSeams::DeleteCallerOwnedFailedSource(state);

	CHECK_THROWS_AS(PartFileSourceOwnershipSeams::DeleteCallerOwnedFailedSource(state), CTestAssertException);
	CHECK_EQ(state.nDeleteCount, 1u);
}

TEST_CASE("Part-file source ownership keeps retryable sources attached and alive")
{
	PartFileSourceOwnershipState state = PartFileSourceOwnershipSeams::CreateLiveDownloadSourceState();

	const PartFileSourceAskOutcome outcome = PartFileSourceOwnershipSeams::KeepSourceForLaterRetry(state);

	CHECK(outcome == PartFileSourceAskOutcome::SourceKeptAlive);
	CHECK_FALSE(state.bCallerOwnsDelete);
	CHECK_FALSE(state.bDeleted);
	CHECK(state.bKnownClient);
	CHECK(PartFileSourceOwnershipSeams::HasDownloadOwnerReferences(state));
}

TEST_SUITE_END;
