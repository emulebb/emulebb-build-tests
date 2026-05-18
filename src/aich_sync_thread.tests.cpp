#include "../third_party/doctest/doctest.h"
#include "../include/TestSupport.h"

#include <limits>

#include "AICHSyncThreadSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("AICH sync seam waits while foreground hash work is still active")
{
	CHECK(ShouldWaitForAICHSyncForegroundHashing({false, 1, false}));
	CHECK(ShouldWaitForAICHSyncForegroundHashing({false, 0, true}));
	CHECK_FALSE(ShouldWaitForAICHSyncForegroundHashing({false, 0, false}));
	CHECK_FALSE(ShouldWaitForAICHSyncForegroundHashing({true, 4, true}));
}

TEST_CASE("AICH sync seam hashes only live shared candidates while the app is still running")
{
	CHECK(ShouldCreateAICHSyncHash(false, true));
	CHECK_FALSE(ShouldCreateAICHSyncHash(false, false));
	CHECK_FALSE(ShouldCreateAICHSyncHash(true, true));
	CHECK_FALSE(ShouldCreateAICHSyncHash(true, false));
}

TEST_CASE("AICH sync seam validates only non-negative UI progress counts")
{
	CHECK(HasValidAICHSyncProgressCount(0));
	CHECK(HasValidAICHSyncProgressCount(7));
	CHECK(HasValidAICHSyncProgressCount((std::numeric_limits<INT_PTR>::max)()));
	CHECK_FALSE(HasValidAICHSyncProgressCount(-1));
}

#if defined(EMULE_TEST_HAVE_AICH_SYNC_PROGRESS_DELIVERY_ACTION) && defined(EMULE_TEST_HAVE_WORKER_UI_MESSAGE_DELIVERY)
TEST_CASE("AICH sync seam classifies UI progress delivery outcomes")
{
	CHECK(GetAICHSyncProgressDeliveryAction(-1, EWorkerUiMessageDelivery::Delivered) == EAICHSyncProgressDeliveryAction::IgnoreInvalidCount);
	CHECK(GetAICHSyncProgressDeliveryAction(0, EWorkerUiMessageDelivery::Delivered) == EAICHSyncProgressDeliveryAction::Delivered);
	CHECK(GetAICHSyncProgressDeliveryAction(3, EWorkerUiMessageDelivery::InvalidWindow) == EAICHSyncProgressDeliveryAction::DropUnavailableTarget);
	CHECK(GetAICHSyncProgressDeliveryAction(3, EWorkerUiMessageDelivery::Failed) == EAICHSyncProgressDeliveryAction::Failed);
}
#endif

TEST_SUITE_END;
