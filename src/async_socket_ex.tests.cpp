#include "../third_party/doctest/doctest.h"
#include "AsyncSocketExSeams.h"

#if __has_include("AsyncSocketExRuntimeSeams.h")
#include "AsyncSocketExRuntimeSeams.h"
#define EMULE_TEST_HAVE_ASYNC_SOCKET_RUNTIME_SEAMS 1
#endif

TEST_SUITE_BEGIN("parity");

TEST_CASE("Async socket seam maps a listening socket to readable poll interest")
{
	CHECK_EQ(GetAsyncSocketPollEvents(listening, FD_ACCEPT | FD_CLOSE), static_cast<short>(POLLIN));
}

TEST_CASE("Async socket seam keeps connecting sockets writable and optionally readable")
{
	CHECK_EQ(GetAsyncSocketPollEvents(connecting, FD_CONNECT), static_cast<short>(POLLOUT));
	CHECK_EQ(GetAsyncSocketPollEvents(connecting, FD_CONNECT | FD_READ), static_cast<short>(POLLIN | POLLOUT));
}

TEST_CASE("Async socket seam only polls connected sockets for the requested steady-state events")
{
	CHECK_EQ(GetAsyncSocketPollEvents(connected, FD_READ | FD_WRITE), static_cast<short>(POLLIN | POLLOUT));
	CHECK_EQ(GetAsyncSocketPollEvents(connected, FD_CLOSE), static_cast<short>(POLLIN));
	CHECK_EQ(GetAsyncSocketPollEvents(unconnected, FD_DEFAULT), static_cast<short>(0));
}

TEST_CASE("Async socket seam recognizes connect completion signals")
{
	CHECK(ShouldCompleteAsyncSocketConnect(connecting, POLLOUT));
	CHECK(ShouldCompleteAsyncSocketConnect(connecting, POLLERR));
	CHECK_FALSE(ShouldCompleteAsyncSocketConnect(connected, POLLOUT));
}

TEST_CASE("Async socket seam classifies WSAPoll hard failures separately from timeouts")
{
	CHECK(HasAsyncSocketPollFailure(SOCKET_ERROR));
	CHECK_FALSE(HasAsyncSocketPollFailure(0));
	CHECK_FALSE(HasAsyncSocketPollFailure(2));
}

TEST_CASE("Async socket seam recognizes terminal close signals without conflating readable readiness")
{
	CHECK(HasAsyncSocketCloseSignal(POLLERR));
	CHECK(HasAsyncSocketCloseSignal(POLLHUP));
	CHECK(HasAsyncSocketCloseSignal(POLLNVAL));
	CHECK_FALSE(HasAsyncSocketCloseSignal(POLLIN));
	CHECK_FALSE(HasAsyncSocketCloseSignal(POLLOUT));
}

#if defined(EMULE_TEST_HAVE_ASYNC_SOCKET_CONNECT_TARGET_SEAMS)
TEST_CASE("Async socket seam snapshots connect targets before the addrinfo list can be released")
{
	SOCKADDR_IN sockAddr = {};
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.s_addr = 0x01020304u;
	sockAddr.sin_port = 4662u;

	addrinfo addr = {};
	addr.ai_family = AF_INET;
	addr.ai_socktype = SOCK_STREAM;
	addr.ai_protocol = IPPROTO_TCP;
	addr.ai_addrlen = sizeof sockAddr;
	addr.ai_addr = reinterpret_cast<sockaddr*>(&sockAddr);

	AsyncSocketExConnectTarget target = {};
	REQUIRE(TryCaptureAsyncSocketConnectTarget(&addr, target));
	CHECK(target.nFamily == AF_INET);
	CHECK(target.nSocketType == SOCK_STREAM);
	CHECK(target.nProtocol == IPPROTO_TCP);
	CHECK(target.nSockAddrLen == sizeof sockAddr);

	const SOCKADDR_IN &copiedSockAddr = reinterpret_cast<const SOCKADDR_IN&>(target.sockAddr);
	CHECK(copiedSockAddr.sin_addr.s_addr == sockAddr.sin_addr.s_addr);
	CHECK(copiedSockAddr.sin_port == sockAddr.sin_port);
}

TEST_CASE("Async socket seam rejects impossible connect-target spans")
{
	addrinfo addr = {};
	AsyncSocketExConnectTarget target = {};

	CHECK_FALSE(TryCaptureAsyncSocketConnectTarget(&addr, target));

	sockaddr_storage addrStorage = {};
	addr.ai_addr = reinterpret_cast<sockaddr*>(&addrStorage);
	addr.ai_addrlen = 0;
	CHECK_FALSE(TryCaptureAsyncSocketConnectTarget(&addr, target));

	sockaddr_storage tooLarge = {};
	addr.ai_addr = reinterpret_cast<sockaddr*>(&tooLarge);
	addr.ai_addrlen = static_cast<int>(sizeof(tooLarge) + 1);
	CHECK_FALSE(TryCaptureAsyncSocketConnectTarget(&addr, target));
}
#endif

TEST_CASE("Async socket seam only yields callback-drain polling while callbacks remain in flight")
{
	CHECK(ShouldYieldForAsyncSocketCallbackDrain(1));
	CHECK(ShouldYieldForAsyncSocketCallbackDrain(7));
	CHECK_FALSE(ShouldYieldForAsyncSocketCallbackDrain(0));
	CHECK_FALSE(ShouldYieldForAsyncSocketCallbackDrain(-1));
}

#if defined(EMULE_TEST_HAVE_ASYNC_SOCKET_RUNTIME_SEAMS)
TEST_CASE("Async socket seam makes helper initialization failures release-visible")
{
	CHECK(AsyncSocketExRuntimeSeams::ShouldLogThreadDataInitFailure());
}
#endif

TEST_CASE("Async socket seam gates accept and read callbacks on state and requested interest")
{
	CHECK(ShouldDispatchAsyncSocketAccept(listening, FD_ACCEPT, POLLIN));
	CHECK_FALSE(ShouldDispatchAsyncSocketAccept(listening, FD_READ, POLLIN));
	CHECK_FALSE(ShouldDispatchAsyncSocketAccept(listening, FD_ACCEPT, POLLERR));
	CHECK(ShouldDispatchAsyncSocketRead(connected, FD_READ, POLLIN));
	CHECK_FALSE(ShouldDispatchAsyncSocketRead(listening, FD_READ, POLLIN));
	CHECK_FALSE(ShouldDispatchAsyncSocketRead(connected, FD_READ, POLLHUP));
}

TEST_CASE("Async socket seam gates write callbacks on state and requested interest")
{
	CHECK(ShouldDispatchAsyncSocketWrite(connected, FD_WRITE, POLLOUT));
	CHECK(ShouldDispatchAsyncSocketWrite(attached, FD_WRITE, POLLOUT));
	CHECK_FALSE(ShouldDispatchAsyncSocketWrite(connecting, FD_WRITE, POLLOUT));
	CHECK_FALSE(ShouldDispatchAsyncSocketWrite(connected, FD_READ, POLLOUT));
	CHECK_FALSE(ShouldDispatchAsyncSocketWrite(attached, FD_WRITE, POLLIN));
}

TEST_CASE("Async socket seam drains unread bytes before closing a readable connected socket")
{
	const AsyncSocketExCloseAction action = ClassifyAsyncSocketClose(connected, FD_READ | FD_CLOSE, POLLHUP, true);
	CHECK(action.bShouldReadDrain);
	CHECK_FALSE(action.bShouldClose);
}

TEST_CASE("Async socket seam closes immediately when no unread bytes remain")
{
	const AsyncSocketExCloseAction action = ClassifyAsyncSocketClose(connected, FD_READ | FD_CLOSE, POLLERR, false);
	CHECK_FALSE(action.bShouldReadDrain);
	CHECK(action.bShouldClose);
}

TEST_CASE("Async socket seam ignores close classification outside connected states")
{
	const AsyncSocketExCloseAction action = ClassifyAsyncSocketClose(listening, FD_CLOSE, POLLHUP, true);
	CHECK_FALSE(action.bShouldReadDrain);
	CHECK_FALSE(action.bShouldClose);
}

TEST_CASE("Async socket seam closes attached sockets immediately when close signals arrive without readable interest")
{
	const AsyncSocketExCloseAction action = ClassifyAsyncSocketClose(attached, FD_WRITE, POLLERR, true);
	CHECK_FALSE(action.bShouldReadDrain);
	CHECK(action.bShouldClose);
}

TEST_SUITE_END;
