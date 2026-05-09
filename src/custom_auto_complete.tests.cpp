#include "../third_party/doctest/doctest.h"

#include "CustomAutoCompleteSeams.h"

#include <cwchar>

namespace
{
	LPVOID STDAPICALLTYPE FailingEnumStringAllocator(SIZE_T)
	{
		return NULL;
	}
}

TEST_SUITE_BEGIN("parity");

TEST_CASE("Custom autocomplete enum string seam copies values into COM task memory")
{
	LPOLESTR pszValue = NULL;
	const HRESULT hr = CustomAutoCompleteSeams::CopyEnumString(CString(_T("incoming")), pszValue);

	REQUIRE(hr == S_OK);
	REQUIRE(pszValue != NULL);
	CHECK(std::wcscmp(pszValue, L"incoming") == 0);

	::CoTaskMemFree(pszValue);
}

TEST_CASE("Custom autocomplete enum string seam returns out-of-memory before copying through a null allocation")
{
	LPOLESTR pszValue = reinterpret_cast<LPOLESTR>(1);
	const HRESULT hr = CustomAutoCompleteSeams::CopyEnumString(CString(_T("incoming")), pszValue, FailingEnumStringAllocator);

	CHECK(hr == E_OUTOFMEMORY);
	CHECK(pszValue == NULL);
}

TEST_SUITE_END();
