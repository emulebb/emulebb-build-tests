#include "../third_party/doctest/doctest.h"

#include <atomic>
#include <memory>

#include "AsyncDnsResolveSeams.h"

TEST_SUITE_BEGIN("async_dns_resolve");

TEST_CASE("async DNS request ids never use zero for scalar and atomic counters")
{
	UINT uNext = 0;
	CHECK_EQ(AsyncDnsResolveSeams::AllocateNonZeroRequestId(uNext), 1u);
	CHECK_EQ(uNext, 1u);

	uNext = UINT_MAX;
	CHECK_EQ(AsyncDnsResolveSeams::AllocateNonZeroRequestId(uNext), 1u);
	CHECK_EQ(uNext, 1u);

	std::atomic<UINT_PTR> uAtomicNext{0};
	CHECK_EQ(AsyncDnsResolveSeams::AllocateNonZeroRequestId(uAtomicNext), static_cast<UINT_PTR>(1));
}

TEST_CASE("async DNS seam builds legacy IPv4 socket address and error mapping")
{
	const SOCKADDR_IN sockAddr = AsyncDnsResolveSeams::BuildIpv4SocketAddress(0x01020304u, 4662);

	CHECK_EQ(sockAddr.sin_family, AF_INET);
	CHECK_EQ(sockAddr.sin_addr.s_addr, 0x01020304u);
	CHECK_EQ(sockAddr.sin_port, htons(4662));

	AsyncDnsResolveSeams::SHostnameResolveResult unresolved;
	CHECK_EQ(AsyncDnsResolveSeams::GetLegacyHostResolveError(unresolved), WSAHOST_NOT_FOUND);

	AsyncDnsResolveSeams::SHostnameResolveResult resolved;
	resolved.bHasIpv4Address = true;
	CHECK_EQ(AsyncDnsResolveSeams::GetLegacyHostResolveError(resolved), 0);
}

TEST_CASE("async DNS posted result ownership is released only after delivery")
{
	std::unique_ptr<AsyncDnsResolveSeams::SHostnameResolveResult> pResult(new AsyncDnsResolveSeams::SHostnameResolveResult);

	CHECK_FALSE(AsyncDnsResolveSeams::PostOwnedResult(NULL, WM_APP + 1, 0, pResult));
	CHECK_FALSE(static_cast<bool>(pResult));
}

TEST_CASE("async DNS launch helper owns work until a resolver thread starts")
{
	std::unique_ptr<AsyncDnsResolveSeams::SHostnameResolveWork> pWork = AsyncDnsResolveSeams::MakeHostnameResolveWork(
		reinterpret_cast<HWND>(static_cast<INT_PTR>(17)),
		WM_APP + 12,
		34,
		56,
		CStringA("example.test"),
		SOCK_DGRAM,
		4662);

	REQUIRE(static_cast<bool>(pWork));
	CHECK(pWork->hTargetWnd == reinterpret_cast<HWND>(static_cast<INT_PTR>(17)));
	CHECK(pWork->uCompletionMessage == WM_APP + 12);
	CHECK(pWork->wParam == 34);
	CHECK(pWork->uRequestId == 56);
	CHECK(pWork->strHostAddress == CStringA("example.test"));
	CHECK(pWork->nSocketType == SOCK_DGRAM);
	CHECK(pWork->nHostPort == 4662);

	std::unique_ptr<AsyncDnsResolveSeams::SHostnameResolveWork> pEmptyWork;
	CHECK_FALSE(AsyncDnsResolveSeams::StartHostnameResolveThread(pEmptyWork));
	CHECK_FALSE(static_cast<bool>(pEmptyWork));
}

TEST_SUITE_END;
