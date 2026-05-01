#include "../third_party/doctest/doctest.h"

#include "TransferWndSeams.h"

TEST_CASE("Transfer window seam validates secondary panes")
{
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneDownloading));
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneUploading));
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneOnQueue));
	CHECK(TransferWndSeams::IsValidSecondaryPane(TransferWndSeams::kSecondaryPaneClients));

	CHECK_FALSE(TransferWndSeams::IsValidSecondaryPane(-1));
	CHECK_FALSE(TransferWndSeams::IsValidSecondaryPane(4));
	CHECK_EQ(TransferWndSeams::NormalizeSecondaryPane(-1), TransferWndSeams::kSecondaryPaneUploading);
	CHECK_EQ(TransferWndSeams::NormalizeSecondaryPane(4), TransferWndSeams::kSecondaryPaneUploading);
	CHECK_EQ(TransferWndSeams::NormalizeSecondaryPane(TransferWndSeams::kSecondaryPaneClients), TransferWndSeams::kSecondaryPaneClients);
}

TEST_CASE("Transfer window seam validates primary list ids")
{
	CHECK(TransferWndSeams::IsValidPrimaryListId(TransferWndSeams::kPrimaryListSplit));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_DOWNLOADLIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_UPLOADLIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_QUEUELIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_CLIENTLIST));
	CHECK(TransferWndSeams::IsValidPrimaryListId(IDC_DOWNLOADCLIENTS));

	CHECK_FALSE(TransferWndSeams::IsValidPrimaryListId(0));
	CHECK_FALSE(TransferWndSeams::IsValidPrimaryListId(IDC_DOWNLOADLIST + IDC_QUEUELIST));
	CHECK_EQ(TransferWndSeams::NormalizePrimaryListId(0), TransferWndSeams::kPrimaryListSplit);
	CHECK_EQ(TransferWndSeams::NormalizePrimaryListId(IDC_CLIENTLIST), static_cast<std::uint32_t>(IDC_CLIENTLIST));
}

TEST_CASE("Transfer window seam keeps detail routing off invalid states")
{
	CHECK_FALSE(TransferWndSeams::IsUserDetailPrimaryListId(TransferWndSeams::kPrimaryListSplit));
	CHECK_FALSE(TransferWndSeams::IsUserDetailPrimaryListId(IDC_DOWNLOADLIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_UPLOADLIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_QUEUELIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_CLIENTLIST));
	CHECK(TransferWndSeams::IsUserDetailPrimaryListId(IDC_DOWNLOADCLIENTS));
	CHECK_FALSE(TransferWndSeams::IsUserDetailPrimaryListId(0));

	CHECK(TransferWndSeams::IsUserDetailSecondaryPane(TransferWndSeams::kSecondaryPaneUploading));
	CHECK_FALSE(TransferWndSeams::IsUserDetailSecondaryPane(-1));
	CHECK_FALSE(TransferWndSeams::IsUserDetailSecondaryPane(4));
}

TEST_CASE("Transfer window seam logs invalid state only")
{
	CHECK_FALSE(TransferWndSeams::ShouldLogInvalidState(true));
	CHECK(TransferWndSeams::ShouldLogInvalidState(false));
}
