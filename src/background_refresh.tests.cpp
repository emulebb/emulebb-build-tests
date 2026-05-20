#include "../third_party/doctest/doctest.h"

#include "BackgroundRefreshSeams.h"

TEST_SUITE_BEGIN("background_refresh");

TEST_CASE("Background refresh records attempts only after a worker starts")
{
	CHECK(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(true, true));
	CHECK_FALSE(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(false, true));
	CHECK_FALSE(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(true, false));
	CHECK_FALSE(BackgroundRefreshSeams::ShouldRecordRefreshAttempt(false, false));
}

TEST_CASE("Background refresh queued state is a single-owner atomic gate")
{
	BackgroundRefreshSeams::SRefreshState state;
	CHECK_FALSE(BackgroundRefreshSeams::IsRefreshQueued(state));

	CHECK(BackgroundRefreshSeams::TryMarkRefreshQueued(state));
	CHECK(BackgroundRefreshSeams::IsRefreshQueued(state));
	CHECK_FALSE(BackgroundRefreshSeams::TryMarkRefreshQueued(state));

	BackgroundRefreshSeams::ClearRefreshQueued(state);
	CHECK_FALSE(BackgroundRefreshSeams::IsRefreshQueued(state));
	CHECK(BackgroundRefreshSeams::TryMarkRefreshQueued(state));
}

TEST_CASE("Background refresh completion fallback clears abandoned queued state")
{
	std::shared_ptr<BackgroundRefreshSeams::SRefreshState> state(std::make_shared<BackgroundRefreshSeams::SRefreshState>());
	REQUIRE(BackgroundRefreshSeams::TryMarkRefreshQueued(*state));

	const BackgroundRefreshSeams::SRefreshCompletionPostResult result = BackgroundRefreshSeams::PostRefreshCompletion(NULL, WM_USER + 1, true, state);
	CHECK_FALSE(result.bDelivered);
	CHECK_FALSE(BackgroundRefreshSeams::IsRefreshQueued(*state));
}

namespace
{
struct TestRefreshContext
{
	int nId = 0;
};
}

TEST_CASE("Background refresh queued worker helper transfers context ownership on start")
{
	BackgroundRefreshSeams::SRefreshState state;
	std::unique_ptr<TestRefreshContext> context(new TestRefreshContext);
	context->nId = 42;

	TestRefreshContext *pStartedContext = NULL;
	int nCleanupCalls = 0;
	const bool bStarted = BackgroundRefreshSeams::StartQueuedRefreshWorker(
		state,
		context,
		[&](TestRefreshContext *pContext) {
			pStartedContext = pContext;
			return true;
		},
		[&](const TestRefreshContext&) {
			++nCleanupCalls;
		});

	CHECK(bStarted);
	const bool bContextTransferred = context.get() == NULL;
	const bool bWorkerReceivedContext = pStartedContext != NULL;
	CHECK(bContextTransferred);
	REQUIRE(bWorkerReceivedContext);
	CHECK(pStartedContext->nId == 42);
	CHECK(nCleanupCalls == 0);
	CHECK(BackgroundRefreshSeams::IsRefreshQueued(state));

	delete pStartedContext;
}

TEST_CASE("Background refresh queued worker helper cleans up failed starts")
{
	BackgroundRefreshSeams::SRefreshState state;
	std::unique_ptr<TestRefreshContext> context(new TestRefreshContext);
	context->nId = 7;

	int nCleanupCalls = 0;
	int nCleanedId = 0;
	const bool bStarted = BackgroundRefreshSeams::StartQueuedRefreshWorker(
		state,
		context,
		[](TestRefreshContext*) {
			return false;
		},
		[&](const TestRefreshContext& cleanedContext) {
			++nCleanupCalls;
			nCleanedId = cleanedContext.nId;
		});

	CHECK_FALSE(bStarted);
	const bool bContextReleasedAfterFailedStart = context.get() == NULL;
	CHECK(bContextReleasedAfterFailedStart);
	CHECK(nCleanupCalls == 1);
	CHECK(nCleanedId == 7);
	CHECK_FALSE(BackgroundRefreshSeams::IsRefreshQueued(state));
}

TEST_CASE("Background refresh queued worker helper cleans up duplicate requests")
{
	BackgroundRefreshSeams::SRefreshState state;
	REQUIRE(BackgroundRefreshSeams::TryMarkRefreshQueued(state));
	std::unique_ptr<TestRefreshContext> context(new TestRefreshContext);
	context->nId = 9;

	int nCleanupCalls = 0;
	bool bStartCalled = false;
	const bool bStarted = BackgroundRefreshSeams::StartQueuedRefreshWorker(
		state,
		context,
		[&](TestRefreshContext*) {
			bStartCalled = true;
			return true;
		},
		[&](const TestRefreshContext& cleanedContext) {
			++nCleanupCalls;
			CHECK(cleanedContext.nId == 9);
		});

	CHECK_FALSE(bStarted);
	const bool bDuplicateContextRetained = context.get() != NULL;
	CHECK(bDuplicateContextRetained);
	CHECK_FALSE(bStartCalled);
	CHECK(nCleanupCalls == 1);
	CHECK(BackgroundRefreshSeams::IsRefreshQueued(state));
}

TEST_SUITE_END();
