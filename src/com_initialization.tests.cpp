#include "../third_party/doctest/doctest.h"

#include "ComInitializationSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("COM initialization seam keeps changed mode usable without ownership")
{
	using namespace ComInitializationSeams;

	CHECK(IsInitializationUsable(S_OK));
	CHECK(IsInitializationUsable(S_FALSE));
	CHECK(IsInitializationUsable(RPC_E_CHANGED_MODE));
	CHECK_FALSE(IsInitializationUsable(E_FAIL));

	CHECK(ShouldUninitializeAfterInitialization(S_OK));
	CHECK(ShouldUninitializeAfterInitialization(S_FALSE));
	CHECK_FALSE(ShouldUninitializeAfterInitialization(RPC_E_CHANGED_MODE));
	CHECK_FALSE(ShouldUninitializeAfterInitialization(E_FAIL));
}

TEST_CASE("COM seam wrappers own CoTaskMem and PROPVARIANT lifetimes")
{
	using namespace ComInitializationSeams;

	CScopedCoTaskMem<WCHAR> mem(static_cast<WCHAR*>(::CoTaskMemAlloc(sizeof(WCHAR) * 4)));
	const bool bAllocated = mem.Get() != NULL;
	REQUIRE(bAllocated);
	wcscpy_s(mem.Get(), 4, L"abc");
	CHECK(wcscmp(mem.Get(), L"abc") == 0);

	WCHAR *pDetached = mem.Detach();
	const bool bWrapperCleared = mem.Get() == NULL;
	CHECK(bWrapperCleared);
	const bool bDetached = pDetached != NULL;
	REQUIRE(bDetached);
	::CoTaskMemFree(pDetached);

	CScopedPropVariant value;
	CHECK(value.Get().vt == VT_EMPTY);
	value.Get().vt = VT_LPWSTR;
	value.Get().pwszVal = static_cast<LPWSTR>(::CoTaskMemAlloc(sizeof(WCHAR) * 4));
	const bool bVariantAllocated = value.Get().pwszVal != NULL;
	REQUIRE(bVariantAllocated);
	wcscpy_s(value.Get().pwszVal, 4, L"def");
	value.Clear();
	CHECK(value.Get().vt == VT_EMPTY);
}

TEST_SUITE_END;
