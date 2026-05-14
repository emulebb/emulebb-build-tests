#include "../third_party/doctest/doctest.h"

#include "ConfigDefaultFilesSeams.h"

#include <vector>

namespace
{
	const ConfigDefaultFilesSeams::DefaultFileSpec *FindSpec(LPCTSTR pszFileName)
	{
		return ConfigDefaultFilesSeams::FindKnownDefaultFileSpec(pszFileName);
	}

	void CheckAction(LPCTSTR pszFileName, ConfigDefaultFilesSeams::EDefaultFileAction eAction)
	{
		const ConfigDefaultFilesSeams::DefaultFileSpec *pSpec = FindSpec(pszFileName);
		REQUIRE(pSpec != NULL);
		CHECK(pSpec->eAction == eAction);
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Config default file seams classify editable templates and internal state")
{
	CheckAction(_T("addresses.dat"), ConfigDefaultFilesSeams::RuntimeGenerated);
	CheckAction(_T("FakeFileFilter.dat"), ConfigDefaultFilesSeams::ActiveTemplate);
	CheckAction(_T("ipfilter.dat"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("webservices.dat"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("staticservers.dat"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("shareignore.dat"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("shareddir.dat"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("shareddir.monitored.dat"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("shareddir.monitor-owned.dat"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("Category.ini"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("Notifier.ini"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("fileinfo.ini"), ConfigDefaultFilesSeams::CommentedTemplate);
	CheckAction(_T("statistics.ini"), ConfigDefaultFilesSeams::CommentedTemplate);

	CheckAction(_T("preferences.dat"), ConfigDefaultFilesSeams::SkipInternalState);
	CheckAction(_T("preferencesKad.dat"), ConfigDefaultFilesSeams::SkipInternalState);
	CheckAction(_T("cryptkey.dat"), ConfigDefaultFilesSeams::SkipInternalState);
	CheckAction(_T("nodes.dat"), ConfigDefaultFilesSeams::SkipInternalState);
	CheckAction(_T("sharedfiles.dat"), ConfigDefaultFilesSeams::SkipInternalState);
	CheckAction(_T("AC_SearchStrings.dat"), ConfigDefaultFilesSeams::SkipInternalState);
	CheckAction(_T("PreviewApps.dat"), ConfigDefaultFilesSeams::SkipInternalState);
	CheckAction(_T("desktop.ini"), ConfigDefaultFilesSeams::SkipInternalState);

	CHECK(ConfigDefaultFilesSeams::FindKnownDefaultFileSpec(_T("category.ini")) != NULL);
	CHECK(ConfigDefaultFilesSeams::FindKnownDefaultFileSpec(_T("unknown.dat")) == NULL);
}

TEST_CASE("Config default file seams only create missing or blank template-backed files")
{
	const ConfigDefaultFilesSeams::DefaultFileSpec *pTemplateSpec = FindSpec(_T("ipfilter.dat"));
	const ConfigDefaultFilesSeams::DefaultFileSpec *pSkipSpec = FindSpec(_T("preferences.dat"));
	const ConfigDefaultFilesSeams::DefaultFileSpec *pRuntimeSpec = FindSpec(_T("addresses.dat"));
	REQUIRE(pTemplateSpec != NULL);
	REQUIRE(pSkipSpec != NULL);
	REQUIRE(pRuntimeSpec != NULL);

	const std::vector<unsigned char> empty;
	const std::vector<unsigned char> asciiWhitespace = { '\r', '\n', '\t', ' ' };
	const std::vector<unsigned char> utf8BomOnly = { 0xEF, 0xBB, 0xBF };
	const std::vector<unsigned char> utf16LeBomOnly = { 0xFF, 0xFE };
	const std::vector<unsigned char> customText = { 'u', 's', 'e', 'r' };

	CHECK(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pTemplateSpec, false, empty));
	CHECK(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pTemplateSpec, true, empty));
	CHECK(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pTemplateSpec, true, asciiWhitespace));
	CHECK(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pTemplateSpec, true, utf8BomOnly));
	CHECK(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pTemplateSpec, true, utf16LeBomOnly));
	CHECK_FALSE(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pTemplateSpec, true, customText));

	CHECK_FALSE(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pSkipSpec, false, empty));
	CHECK_FALSE(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(pRuntimeSpec, false, empty));
	CHECK_FALSE(ConfigDefaultFilesSeams::ShouldCreateDefaultFile(NULL, false, empty));
}

TEST_CASE("Config default file seams provide templates only for template-backed files")
{
	size_t uSpecCount = 0;
	const ConfigDefaultFilesSeams::DefaultFileSpec *pSpecs = ConfigDefaultFilesSeams::GetKnownDefaultFileSpecs(uSpecCount);
	REQUIRE(pSpecs != NULL);
	REQUIRE(uSpecCount > 0);

	for (size_t i = 0; i < uSpecCount; ++i) {
		const ConfigDefaultFilesSeams::DefaultFileSpec &rSpec = pSpecs[i];
		if (ConfigDefaultFilesSeams::IsTemplateAction(rSpec.eAction)) {
			REQUIRE(rSpec.pszTemplateText != NULL);
			CHECK(rSpec.pszTemplateText[0] != _T('\0'));
		} else
			CHECK(rSpec.pszTemplateText == NULL);
	}

	const ConfigDefaultFilesSeams::DefaultFileSpec *pFakeFileSpec = FindSpec(_T("FakeFileFilter.dat"));
	const ConfigDefaultFilesSeams::DefaultFileSpec *pWebServicesSpec = FindSpec(_T("webservices.dat"));
	const ConfigDefaultFilesSeams::DefaultFileSpec *pShareIgnoreSpec = FindSpec(_T("shareignore.dat"));
	REQUIRE(pFakeFileSpec != NULL);
	REQUIRE(pWebServicesSpec != NULL);
	REQUIRE(pShareIgnoreSpec != NULL);
	CHECK(CString(pFakeFileSpec->pszTemplateText).Find(_T("[tokens]")) >= 0);
	CHECK(CString(pWebServicesSpec->pszTemplateText).Find(_T("#cleanfilename")) >= 0);
	CHECK(CString(pShareIgnoreSpec->pszTemplateText).Find(_T("prefix*")) >= 0);
}

TEST_SUITE_END();
