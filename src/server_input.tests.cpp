#include "../third_party/doctest/doctest.h"

#include "ServerInputSeams.h"

TEST_SUITE_BEGIN("parity");

TEST_CASE("Server input seam parses manual add-server text")
{
	const ServerInputSeams::ManualServerInput input = ServerInputSeams::ParseManualServerInput(
		CString(_T(" server.example.net ")),
		CString(_T("4661")),
		CString(_T(" Release server ")));

	CHECK(input.Valid);
	CHECK(input.Address == CString(_T("server.example.net")));
	CHECK(input.Port == 4661);
	CHECK(input.Name == CString(_T("Release server")));
}

TEST_CASE("Server input seam rejects missing server fields and port overflow")
{
	CHECK_FALSE(ServerInputSeams::ParseManualServerInput(CString(), CString(_T("4661")), CString()).Valid);
	CHECK_FALSE(ServerInputSeams::ParseManualServerInput(CString(_T("server.example.net")), CString(_T("0")), CString()).Valid);
	CHECK_FALSE(ServerInputSeams::ParseManualServerInput(CString(_T("server.example.net")), CString(_T("65536")), CString()).Valid);
	CHECK_FALSE(ServerInputSeams::ParseManualServerInput(CString(_T("server.example.net")), CString(_T("4661x")), CString()).Valid);
}

TEST_CASE("Server input seam validates server.met update URLs")
{
	const ServerInputSeams::ServerMetUrlInput input = ServerInputSeams::ParseServerMetUrlInput(CString(_T(" https://updates.example.net/server.met ")));
	CHECK(input.Valid);
	CHECK(input.Url == CString(_T("https://updates.example.net/server.met")));
	CHECK(input.Scheme == CString(_T("https")));
	CHECK(input.HostName == CString(_T("updates.example.net")));

	CHECK(ServerInputSeams::ParseServerMetUrlInput(CString(_T("http://updates.example.net/server.met"))).Valid);
	CHECK(ServerInputSeams::ParseServerMetUrlInput(CString(_T("ftp://updates.example.net/server.met"))).Valid);
	CHECK_FALSE(ServerInputSeams::ParseServerMetUrlInput(CString(_T("file://C:/server.met"))).Valid);
	CHECK_FALSE(ServerInputSeams::ParseServerMetUrlInput(CString(_T("https:///server.met"))).Valid);
}

TEST_SUITE_END();
