#include "../third_party/doctest/doctest.h"

#include "AppWebLinksSeams.h"

#include <atlstr.h>
#include <set>

TEST_SUITE_BEGIN("parity");

TEST_CASE("App web links expose canonical eMuleBB documentation URLs")
{
	size_t uLinkCount = 0;
	const AppWebLinksSeams::SWebLink *pLinks = AppWebLinksSeams::GetDocumentationLinks(uLinkCount);

	REQUIRE(pLinks != NULL);
	REQUIRE(uLinkCount == 8u);

	const LPCTSTR apszExpectedUrls[] = {
		_T("https://emulebb.github.io/faq/"),
		_T("https://emulebb.github.io/emulebb-tooling/reference/GUIDE-SETUP/"),
		_T("https://emulebb.github.io/emulebb-tooling/reference/GUIDE-NETWORK/"),
		_T("https://emulebb.github.io/emulebb-tooling/reference/GUIDE-SHARING/"),
		_T("https://emulebb.github.io/emulebb-tooling/reference/GUIDE-DOWNLOADS-SEARCH/"),
		_T("https://emulebb.github.io/emulebb-tooling/reference/GUIDE-TOOLS-MENU/"),
		_T("https://emulebb.github.io/emulebb-tooling/reference/GUIDE-CONTROLLERS-REST/"),
		_T("https://emulebb.github.io/emulebb-tooling/reference/GUIDE-TROUBLESHOOTING/")
	};

	std::set<UINT> commandIDs;
	std::set<UINT> labelIDs;
	for (size_t i = 0; i < uLinkCount; ++i) {
		CHECK(CString(pLinks[i].pszUrl) == CString(apszExpectedUrls[i]));
		CHECK(pLinks[i].uCommandID >= MP_HM_LINK_DOC_FAQ);
		CHECK(pLinks[i].uCommandID <= MP_HM_LINK_DOC_TROUBLESHOOTING);
		CHECK(pLinks[i].uLabelStringID >= IDS_HM_LINK_DOC_FAQ);
		CHECK(pLinks[i].uLabelStringID <= IDS_HM_LINK_DOC_TROUBLESHOOTING);
		CHECK(commandIDs.insert(pLinks[i].uCommandID).second);
		CHECK(labelIDs.insert(pLinks[i].uLabelStringID).second);
	}
}

TEST_SUITE_END();
