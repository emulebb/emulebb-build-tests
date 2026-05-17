#include "../third_party/doctest/doctest.h"

#include "AppCommandLineSeams.h"

#include <initializer_list>

namespace
{
std::vector<CString> Tokens(std::initializer_list<LPCTSTR> apszValues)
{
	std::vector<CString> tokens;
	for (LPCTSTR pszValue : apszValues)
		tokens.emplace_back(pszValue);
	return tokens;
}

AppCommandLineSeams::SParseResult Parse(std::initializer_list<LPCTSTR> apszValues)
{
	return AppCommandLineSeams::ParseTokens(Tokens(apszValues));
}
}

TEST_SUITE_BEGIN("startup");

TEST_CASE("App command line accepts help aliases without starting the app")
{
	const auto helpLong = Parse({_T("emule.exe"), _T("--help")});
	const auto helpShort = Parse({_T("emule.exe"), _T("-h")});
	const auto helpWindows = Parse({_T("emule.exe"), _T("/?")});

	CHECK(helpLong.eMode == AppCommandLineSeams::EMode::Help);
	CHECK(helpShort.eMode == AppCommandLineSeams::EMode::Help);
	CHECK(helpWindows.eMode == AppCommandLineSeams::EMode::Help);
	CHECK(helpLong.strUsage.Find(_T("--generate-webserver-cert")) >= 0);
}

TEST_CASE("App command line rejects unknown switches")
{
	const auto result = Parse({_T("emule.exe"), _T("--wat")});

	CHECK(result.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(result.strError == CString(_T("Unknown command-line switch: --wat")));
}

TEST_CASE("App command line accepts and normalizes an isolated profile base")
{
	const auto result = Parse({_T("emule.exe"), _T("-c"), _T("C:\\profiles\\test-root")});

	CHECK(result.eMode == AppCommandLineSeams::EMode::NormalStartup);
	CHECK(result.bHasConfigBaseDir);
	CHECK(result.strConfigBaseDir == CString(_T("C:\\profiles\\test-root\\")));
}

TEST_CASE("App command line rejects invalid and duplicate isolated profile bases")
{
	const auto relative = Parse({_T("emule.exe"), _T("-c"), _T("relative\\profile")});
	const auto duplicate = Parse({_T("emule.exe"), _T("/c"), _T("C:\\one"), _T("-c"), _T("C:\\two")});

	CHECK(relative.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(relative.strError == CString(_T("The -c option requires a canonical absolute eMule base directory like C:\\path.")));
	CHECK(duplicate.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(duplicate.strError == CString(_T("The -c option may be specified only once.")));
}

TEST_CASE("App command line accepts startup singleton switches")
{
	const auto result = Parse({_T("emule.exe"), _T("-ignoreinstances"), _T("-AutoStart"), _T("-assertfile")});

	CHECK(result.eMode == AppCommandLineSeams::EMode::NormalStartup);
	CHECK(result.bIgnoreInstances);
	CHECK(result.bAutoStart);
	CHECK(result.bAssertFile);
}

TEST_CASE("App command line rejects duplicate and valued no-value switches")
{
	const auto duplicate = Parse({_T("emule.exe"), _T("-ignoreinstances"), _T("-ignoreinstances")});
	const auto valued = Parse({_T("emule.exe"), _T("-AutoStart=yes")});

	CHECK(duplicate.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(duplicate.strError == CString(_T("The -ignoreinstances option may be specified only once.")));
	CHECK(valued.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(valued.strError == CString(_T("The -AutoStart option does not accept a value.")));
}

TEST_CASE("App command line preserves a single positional command link or file")
{
	const auto result = Parse({_T("emule.exe"), _T("ed2k://|file|operator-smoke.bin|42|0123456789abcdef0123456789abcdef|/")});
	const auto duplicate = Parse({_T("emule.exe"), _T("ed2k://|server|127.0.0.1|4661|/"), _T("exit")});

	CHECK(result.eMode == AppCommandLineSeams::EMode::NormalStartup);
	CHECK(result.strPositional == CString(_T("ed2k://|file|operator-smoke.bin|42|0123456789abcdef0123456789abcdef|/")));
	CHECK(duplicate.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(duplicate.strError == CString(_T("Only one positional command, link, or file argument is supported.")));
}

TEST_CASE("App command line parses certificate generation inputs")
{
	const auto result = Parse({
		_T("emule.exe"),
		_T("--generate-webserver-cert"),
		_T("--cert=cert.pem"),
		_T("--key"),
		_T("key.pem"),
		_T("--host"),
		_T("localhost"),
		_T("--host"),
		_T("127.0.0.1"),
		_T("--host"),
		_T("2001:db8::1")
	});

	CHECK(result.eMode == AppCommandLineSeams::EMode::GenerateWebServerCertificate);
	CHECK(result.strCertFile == CString(_T("cert.pem")));
	CHECK(result.strKeyFile == CString(_T("key.pem")));
	REQUIRE(result.astrCertDnsNames.size() == 1);
	REQUIRE(result.astrCertIpAddresses.size() == 2);
	CHECK(result.astrCertDnsNames[0] == CStringA("localhost"));
	CHECK(result.astrCertIpAddresses[0] == CStringA("127.0.0.1"));
	CHECK(result.astrCertIpAddresses[1] == CStringA("2001:db8::1"));
}

TEST_CASE("App command line rejects partial certificate generation inputs")
{
	const auto missingKey = Parse({_T("emule.exe"), _T("--generate-webserver-cert"), _T("--cert"), _T("cert.pem")});
	const auto certWithoutMode = Parse({_T("emule.exe"), _T("--cert"), _T("cert.pem"), _T("--key"), _T("key.pem")});
	const auto missingCertValue = Parse({_T("emule.exe"), _T("--generate-webserver-cert"), _T("--cert"), _T("--key"), _T("key.pem")});

	CHECK(missingKey.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(missingKey.strError == CString(_T("The --generate-webserver-cert command requires --cert and --key.")));
	CHECK(certWithoutMode.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(certWithoutMode.strError == CString(_T("The --cert, --key, and --host options require --generate-webserver-cert.")));
	CHECK(missingCertValue.eMode == AppCommandLineSeams::EMode::Invalid);
	CHECK(missingCertValue.strError == CString(_T("The --cert option requires a value.")));
}
