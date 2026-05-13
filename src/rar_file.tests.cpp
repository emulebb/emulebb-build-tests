#include "../third_party/doctest/doctest.h"

#include "RARFileSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("RAR file seam names the external UnRAR DLL by process architecture")
{
#ifdef _WIN64
	CHECK(CString(RARFileSeams::GetDllFileName()) == _T("UnRAR64.dll"));
	CHECK(CString(RARFileSeams::GetInstalledDllRelativeDirectory()) == _T("UnrarDLL\\x64"));
#else
	CHECK(CString(RARFileSeams::GetDllFileName()) == _T("UnRAR.dll"));
	CHECK(CString(RARFileSeams::GetInstalledDllRelativeDirectory()) == _T("UnrarDLL"));
#endif
}

TEST_CASE("RAR file seam builds only an absolute installed DLL candidate")
{
	const CString strDllPath(RARFileSeams::BuildInstalledDllPath(_T("C:\\Program Files (x86)")));

	CHECK(RARFileSeams::IsAbsoluteLoadCandidate(strDllPath));
#ifdef _WIN64
	CHECK(strDllPath == _T("C:\\Program Files (x86)\\UnrarDLL\\x64\\UnRAR64.dll"));
#else
	CHECK(strDllPath == _T("C:\\Program Files (x86)\\UnrarDLL\\UnRAR.dll"));
#endif

	CHECK(RARFileSeams::BuildInstalledDllPath(_T("")).IsEmpty());
	CHECK_FALSE(RARFileSeams::IsAbsoluteLoadCandidate(CString(RARFileSeams::GetDllFileName())));
}

TEST_CASE("RAR file seam accepts only current or newer UnRAR DLL API versions")
{
	CHECK_FALSE(RARFileSeams::IsCompatibleDllApiVersion(8));
	CHECK(RARFileSeams::IsCompatibleDllApiVersion(9));
	CHECK(RARFileSeams::IsCompatibleDllApiVersion(10));
}

TEST_CASE("RAR file seam exposes the required extraction exports")
{
	size_t count = 0;
	const char *const *exports = RARFileSeams::GetRequiredExportNames(count);

	REQUIRE(count == 4);
	CHECK(CStringA(exports[0]) == "RAROpenArchiveEx");
	CHECK(CStringA(exports[1]) == "RARCloseArchive");
	CHECK(CStringA(exports[2]) == "RARReadHeaderEx");
	CHECK(CStringA(exports[3]) == "RARProcessFileW");
}

TEST_SUITE_END;
