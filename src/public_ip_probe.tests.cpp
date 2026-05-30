#include "../third_party/doctest/doctest.h"

#include "PublicIpProbeSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("public IPv4 probe providers use HTTP IPv4 endpoints")
{
	size_t count = 0;
	const PublicIpProbeSeams::SPublicIpv4ProbeProvider* providers = PublicIpProbeSeams::GetPublicIpv4ProbeProviders(count);

	REQUIRE(count == 5);
	CHECK(CStringA(providers[0].pszUrl) == "http://api.ipify.org/");
	CHECK(CStringA(providers[1].pszUrl) == "http://ipv4.icanhazip.com/");
	CHECK(CStringA(providers[2].pszUrl) == "http://checkip.amazonaws.com/");
	CHECK(CStringA(providers[3].pszUrl) == "http://v4.ident.me/");
	CHECK(CStringA(providers[4].pszUrl) == "http://ipecho.net/plain");
	for (size_t i = 0; i < count; ++i) {
		CHECK(CStringA(providers[i].pszUrl).Left(7) == "http://");
		CHECK(CStringA(providers[i].pszHost).Find("ipv6") < 0);
	}
}

TEST_CASE("public IPv4 probe parses plain and HTTP responses")
{
	CStringA address;

	CHECK(PublicIpProbeSeams::TryParsePublicIpv4HttpResponse("203.0.113.9\r\n", address));
	CHECK(address == "203.0.113.9");

	CHECK(PublicIpProbeSeams::TryParsePublicIpv4HttpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n198.51.100.7\n", address));
	CHECK(address == "198.51.100.7");

	CHECK_FALSE(PublicIpProbeSeams::TryParsePublicIpv4HttpResponse("HTTP/1.1 500 Error\r\n\r\n198.51.100.7\n", address));
	CHECK_FALSE(PublicIpProbeSeams::TryParsePublicIpv4HttpResponse("not an ip\n", address));
	CHECK_FALSE(PublicIpProbeSeams::TryParsePublicIpv4HttpResponse("999.1.2.3\n", address));
	CHECK_FALSE(PublicIpProbeSeams::TryParsePublicIpv4HttpResponse("2001:db8::1\n", address));
}

TEST_SUITE_END();
