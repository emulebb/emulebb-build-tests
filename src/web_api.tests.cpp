#include "../third_party/doctest/doctest.h"
#include "../include/LongPathTestSupport.h"
#include "WebApiCommandSeams.h"
#include "WebApiSurfaceSeams.h"
#include "WebServerArrCompatSeams.h"
#include "WebServerAuthStateSeams.h"
#include "WebServerJsonSeams.h"
#include "WebServerQBitCompatSeams.h"
#include "WebServerStaticFileSeams.h"
#include "WebSocketHttpSeams.h"
#include "WebSocketTlsSeams.h"
#include "SearchParamsPolicy.h"

#include <utility>

TEST_SUITE_BEGIN("web_api");

#ifdef EMULEBB_SEARCH_NETWORK_DEFAULTS
TEST_CASE("Automatic search method uses connected network defaults")
{
	CHECK_EQ(SearchParamsPolicy::ResolveAutomaticSearchType(false, false), SearchParamsPolicy::kAutomaticSearchType);
	CHECK_EQ(SearchParamsPolicy::ResolveAutomaticSearchType(true, false), SearchParamsPolicy::kEd2kGlobalSearchType);
	CHECK_EQ(SearchParamsPolicy::ResolveAutomaticSearchType(false, true), SearchParamsPolicy::kKadSearchType);
	CHECK_EQ(SearchParamsPolicy::ResolveAutomaticSearchType(true, true), SearchParamsPolicy::kEd2kGlobalSearchType);
}
#endif

TEST_CASE("WebSocket TLS seam loads cert and key bytes from overlong unicode paths")
{
	LongPathTestSupport::ScopedLongPathFixture fixture;
	INFO(fixture.LastError());
	REQUIRE(fixture.Initialize(true, 0u, 0x57454254u));

	const std::wstring certPath = fixture.MakeDirectoryChildPath((std::wstring(L"cert_") + LongPathTestSupport::MakeSpecialSegment() + L".crt").c_str());
	const std::wstring keyPath = fixture.MakeDirectoryChildPath((std::wstring(L"key_") + LongPathTestSupport::MakeSpecialSegment() + L".key").c_str());
	const std::vector<BYTE> certPayload = LongPathTestSupport::BuildDeterministicPayload(4097u, 0xC312u);
	const std::vector<BYTE> keyPayload = LongPathTestSupport::BuildDeterministicPayload(3073u, 0xC313u);
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(certPath, certPayload));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::WriteBytes(keyPath, keyPayload));

	std::vector<unsigned char> certBytes;
	std::vector<unsigned char> keyBytes;
	REQUIRE(WebSocketTlsSeams::TryLoadPemFileForMbedTls(CString(certPath.c_str()), certBytes));
	REQUIRE(WebSocketTlsSeams::TryLoadPemFileForMbedTls(CString(keyPath.c_str()), keyBytes));

	REQUIRE_EQ(certBytes.size(), certPayload.size() + 1u);
	REQUIRE_EQ(keyBytes.size(), keyPayload.size() + 1u);
	CHECK(std::equal(certPayload.begin(), certPayload.end(), certBytes.begin()));
	CHECK(std::equal(keyPayload.begin(), keyPayload.end(), keyBytes.begin()));
	CHECK_EQ(certBytes.back(), 0u);
	CHECK_EQ(keyBytes.back(), 0u);

	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(certPath));
	REQUIRE(LongPathTestSupport::ScopedLongPathFixture::DeleteFilePath(keyPath));
}

TEST_CASE("WebSocket HTTP seams parse Content-Length strictly")
{
	uint32_t value = 0;
	CHECK(WebSocketHttpSeams::TryParseContentLengthValue("42", value));
	CHECK_EQ(value, 42u);
	CHECK(WebSocketHttpSeams::TryParseContentLengthValue(" 42 ", value));
	CHECK_EQ(value, 42u);
	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthValue("-1", value));
	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthValue("10x", value));
	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthValue("999999999999999999999", value));

	CHECK(WebSocketHttpSeams::TryParseContentLengthValue("16777216", value));
	CHECK_EQ(value, 16777216u);
	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthValue("16777217", value));

	CHECK(WebSocketHttpSeams::ParseContentLengthHeaderLine("Content-Length: 12\r", value) == WebSocketHttpSeams::EContentLengthHeader::Valid);
	CHECK_EQ(value, 12u);
	CHECK(WebSocketHttpSeams::ParseContentLengthHeaderLine("content-length: 0", value) == WebSocketHttpSeams::EContentLengthHeader::Valid);
	CHECK_EQ(value, 0u);
	CHECK(WebSocketHttpSeams::ParseContentLengthHeaderLine("Content-Length-Extra: 12", value) == WebSocketHttpSeams::EContentLengthHeader::NotContentLength);
	CHECK(WebSocketHttpSeams::ParseContentLengthHeaderLine("Content-Length: -1", value) == WebSocketHttpSeams::EContentLengthHeader::Invalid);
}

TEST_CASE("WebSocket HTTP seams reject duplicate or invalid Content-Length headers")
{
	bool hasContentLength = false;
	uint32_t value = 0;

	CHECK(WebSocketHttpSeams::TryParseContentLengthHeaders(
		"POST /api/v1/searches HTTP/1.1\r\nHost: local\r\n\r\n",
		hasContentLength,
		value));
	CHECK_FALSE(hasContentLength);
	CHECK_EQ(value, 0u);

	CHECK(WebSocketHttpSeams::TryParseContentLengthHeaders(
		"POST /api/v1/searches HTTP/1.1\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n",
		hasContentLength,
		value));
	CHECK(hasContentLength);
	CHECK_EQ(value, 2u);

	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthHeaders(
		"POST /api/v1/searches HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
		hasContentLength,
		value));
	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthHeaders(
		"POST /api/v1/searches HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n",
		hasContentLength,
		value));
	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthHeaders(
		"POST /api/v1/searches HTTP/1.1\r\nContent-Length: 16777217\r\n\r\n",
		hasContentLength,
		value));
	CHECK_FALSE(WebSocketHttpSeams::TryParseContentLengthHeaders(
		"POST /api/v1/searches HTTP/1.1\r\nContent-Length: 2x\r\n\r\n",
		hasContentLength,
		value));
}

TEST_CASE("WebSocket HTTP seams reject duplicate sensitive header values")
{
	std::string value;
	CHECK(WebSocketHttpSeams::GetSingleHeaderValue(
		"POST /api/v1/searches HTTP/1.1\r\nContent-Type: application/json\r\nX-API-Key: secret\r\n\r\n",
		"content-type",
		value) == WebSocketHttpSeams::EHeaderValueResult::Found);
	CHECK_EQ(value, "application/json");

	CHECK(WebSocketHttpSeams::GetSingleHeaderValue(
		"POST /api/v1/searches HTTP/1.1\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n",
		"Content-Type",
		value) == WebSocketHttpSeams::EHeaderValueResult::Duplicate);
	CHECK(value.empty());

	CHECK(WebSocketHttpSeams::GetSingleHeaderValue(
		"GET /api/v1/app HTTP/1.1\r\nX-API-Key: secret\r\nx-api-key: other\r\n\r\n",
		"X-API-Key",
		value) == WebSocketHttpSeams::EHeaderValueResult::Duplicate);
	CHECK(value.empty());

	CHECK(WebSocketHttpSeams::GetSingleHeaderValue(
		"GET /api/v1/app HTTP/1.1\r\nHost: local\r\n\r\n",
		"X-API-Key",
		value) == WebSocketHttpSeams::EHeaderValueResult::Missing);
	CHECK(value.empty());
}

TEST_CASE("WebSocket HTTP seams bound incomplete header buffering")
{
	uint32_t headerLength = 0;
	CHECK(WebSocketHttpSeams::ScanHttpHeaderLength(
		"GET /api/v1/app HTTP/1.1\r\nHost: local\r\n\r\n",
		41,
		headerLength) == WebSocketHttpSeams::EHttpHeaderScanResult::Complete);
	CHECK_EQ(headerLength, 41u);

	CHECK(WebSocketHttpSeams::ScanHttpHeaderLength(
		"GET /api/v1/app HTTP/1.1\nHost: local\n\n",
		38,
		headerLength) == WebSocketHttpSeams::EHttpHeaderScanResult::Complete);
	CHECK_EQ(headerLength, 38u);

	const std::string incompleteHeader(static_cast<size_t>(WebSocketHttpSeams::kMaxHttpHeaderLength), 'A');
	CHECK(WebSocketHttpSeams::ScanHttpHeaderLength(
		incompleteHeader.data(),
		incompleteHeader.size(),
		headerLength) == WebSocketHttpSeams::EHttpHeaderScanResult::Incomplete);
	CHECK_EQ(headerLength, 0u);

	const std::string oversizedHeader(static_cast<size_t>(WebSocketHttpSeams::kMaxHttpHeaderLength + 1u), 'A');
	CHECK(WebSocketHttpSeams::ScanHttpHeaderLength(
		oversizedHeader.data(),
		oversizedHeader.size(),
		headerLength) == WebSocketHttpSeams::EHttpHeaderScanResult::TooLarge);
	CHECK_EQ(headerLength, 0u);
}

TEST_CASE("WebSocket HTTP seams wait for complete declared bodies")
{
	CHECK_FALSE(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(0u, 0u, 0u));
	CHECK_FALSE(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(40u, 41u, 0u));
	CHECK(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(41u, 41u, 0u));
	CHECK(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(45u, 41u, 0u));

	CHECK_FALSE(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(41u, 41u, 4u));
	CHECK_FALSE(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(44u, 41u, 4u));
	CHECK(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(45u, 41u, 4u));
	CHECK(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(46u, 41u, 4u));

	CHECK_FALSE(WebSocketHttpSeams::IsCompleteHttpRequestBuffered(
		static_cast<size_t>(UINT32_MAX),
		UINT32_MAX,
		UINT32_MAX));
}

TEST_CASE("WebSocket HTTP seams reject receive-buffer DWORD growth overflow")
{
	uint32_t bufferSize = 0;

	CHECK(WebSocketHttpSeams::TryCalculateReceiveBufferSize(100u, 50u, 4096u, bufferSize));
	CHECK_EQ(bufferSize, static_cast<uint32_t>(4246u));
	CHECK(WebSocketHttpSeams::TryCalculateReceiveBufferSize(UINT32_MAX - 10u, 10u, 0u, bufferSize));
	CHECK_EQ(bufferSize, UINT32_MAX);
	CHECK_FALSE(WebSocketHttpSeams::TryCalculateReceiveBufferSize(UINT32_MAX - 10u, 11u, 0u, bufferSize));
	CHECK_FALSE(WebSocketHttpSeams::TryCalculateReceiveBufferSize(UINT32_MAX - 10u, 10u, 1u, bufferSize));
}

TEST_CASE("WebSocket HTTP seams parse request methods exactly")
{
	std::string method;
	std::string target;

	CHECK(WebSocketHttpSeams::TryParseRequestLine("GET /api/v1/app HTTP/1.1\r\nHost: local\r\n", method, target));
	CHECK_EQ(method, "GET");
	CHECK_EQ(target, "/api/v1/app");
	CHECK(WebSocketHttpSeams::IsSupportedDispatchMethod(method));

	CHECK(WebSocketHttpSeams::TryParseRequestLine("GETTING /api/v1/app HTTP/1.1\r\n", method, target));
	CHECK_EQ(method, "GETTING");
	CHECK_EQ(target, "/api/v1/app");
	CHECK_FALSE(WebSocketHttpSeams::IsSupportedDispatchMethod(method));

	CHECK_FALSE(WebSocketHttpSeams::TryParseRequestLine("GET\r\n", method, target));
	CHECK(method.empty());
	CHECK(target.empty());

	CHECK(WebSocketHttpSeams::TryParseRequestLine("get /api/v1/app HTTP/1.1\r\n", method, target));
	CHECK_EQ(method, "get");
	CHECK_EQ(target, "/api/v1/app");
	CHECK_FALSE(WebSocketHttpSeams::IsSupportedDispatchMethod(method));

	CHECK(WebSocketHttpSeams::TryParseRequestLine("GETTINGTOOMUCH /api/v1/app HTTP/1.1\r\n", method, target));
	CHECK_EQ(method, "GETTINGTOOMUCH");
	CHECK_EQ(target, "/api/v1/app");
	CHECK_FALSE(WebSocketHttpSeams::IsSupportedDispatchMethod(method));
}

TEST_CASE("WebSocket HTTP seams bound accepted-client thread fanout")
{
	CHECK(WebSocketHttpSeams::kAcceptedClientIoTimeoutMs > 0u);
	CHECK_EQ(WebSocketHttpSeams::kAcceptedClientReadBufferBytes, static_cast<size_t>(4u * 1024u));
	CHECK(WebSocketHttpSeams::CanStartAcceptedClientThread(0u));
	CHECK(WebSocketHttpSeams::CanStartAcceptedClientThread(WebSocketHttpSeams::kMaxAcceptedClientThreads - 1u));
	CHECK_FALSE(WebSocketHttpSeams::CanStartAcceptedClientThread(WebSocketHttpSeams::kMaxAcceptedClientThreads));
	CHECK_FALSE(WebSocketHttpSeams::CanStartAcceptedClientThread(WebSocketHttpSeams::kMaxAcceptedClientThreads + 1u));
	CHECK(
		WebSocketHttpSeams::GetSocketThreadShutdownFollowUp(true)
		== WebSocketHttpSeams::ESocketThreadShutdownFollowUp::CompleteShutdown);
	CHECK(
		WebSocketHttpSeams::GetSocketThreadShutdownFollowUp(false)
		== WebSocketHttpSeams::ESocketThreadShutdownFollowUp::WaitWithoutTimeout);
}

TEST_CASE("WebSocket HTTP seams keep draining accepts after remote IP rejection")
{
#ifdef EMULEBB_WEBSOCKET_HTTP_SEAMS_HAS_REJECTED_IP_ACTION
	CHECK(WebSocketHttpSeams::GetRejectedRemoteAccessIpAction() ==
		WebSocketHttpSeams::ERejectedRemoteAccessIpAction::ContinueAcceptDrain);
#else
	MESSAGE("Rejected remote-access IP action seam is not available in this workspace.");
#endif
}

TEST_CASE("WebSocket HTTP seams bound queued response bytes")
{
	CHECK(WebSocketHttpSeams::CanQueueResponseBytes(0u, 1024u));
	CHECK(WebSocketHttpSeams::CanQueueResponseBytes(
		WebSocketHttpSeams::kMaxQueuedResponseBytes - 1024u,
		1024u));
	CHECK_FALSE(WebSocketHttpSeams::CanQueueResponseBytes(WebSocketHttpSeams::kMaxQueuedResponseBytes, 1u));
	CHECK_FALSE(WebSocketHttpSeams::CanQueueResponseBytes(0u, static_cast<uint32_t>(WebSocketHttpSeams::kMaxQueuedResponseBytes + 1u)));

	CHECK_EQ(WebSocketHttpSeams::ConsumeQueuedResponseBytes(1024u, 512u), static_cast<uint64_t>(512u));
	CHECK_EQ(WebSocketHttpSeams::ConsumeQueuedResponseBytes(1024u, 1024u), static_cast<uint64_t>(0u));
	CHECK_EQ(WebSocketHttpSeams::ConsumeQueuedResponseBytes(1024u, 2048u), static_cast<uint64_t>(0u));
}

TEST_CASE("WebServer static file seam contains requests under the web root")
{
	CString path;

	CHECK(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("/assets/site.css"), path));
	CHECK(PathHelpers::ArePathsEquivalent(path, _T("C:\\webroot\\assets\\site.css")));

	CHECK(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot"), _T("images\\logo.png"), path));
	CHECK(PathHelpers::ArePathsEquivalent(path, _T("C:\\webroot\\images\\logo.png")));

	CHECK_FALSE(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("/../secret.css"), path));
	CHECK_FALSE(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("/%2e%2e/secret.css"), path));
	CHECK_FALSE(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("/assets%2fsecret.css"), path));
	CHECK_FALSE(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("C:\\Windows\\win.ini"), path));
	CHECK_FALSE(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("C:Windows\\win.ini"), path));
	CHECK_FALSE(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("\\\\server\\share\\x.css"), path));
	CHECK_FALSE(WebServerStaticFileSeams::TryBuildContainedStaticFilePath(_T("C:\\webroot\\"), _T("/safe.css:stream"), path));
}

TEST_CASE("WebServer static file seam keeps content metadata and size limits bounded")
{
	auto toString = [](const CStringA &rstrValue)
	{
		return std::string(static_cast<LPCSTR>(rstrValue));
	};

	CHECK(toString(WebServerStaticFileSeams::GetStaticContentTypeHeader(_T("/site.css"))) == "Content-Type: text/css\r\n");
	CHECK(toString(WebServerStaticFileSeams::GetStaticContentTypeHeader(_T("/app.js"))) == "Content-Type: text/javascript\r\n");
	CHECK(toString(WebServerStaticFileSeams::GetStaticContentTypeHeader(_T("/favicon.ico"))) == "Content-Type: image/x-icon\r\n");
	CHECK(toString(WebServerStaticFileSeams::GetStaticContentTypeHeader(_T("/photo.jpeg"))) == "Content-Type: image/jpeg\r\n");
	CHECK(toString(WebServerStaticFileSeams::GetStaticContentTypeHeader(_T("/unknown.txt"))).empty());

	CHECK(WebServerStaticFileSeams::IsStaticFileSizeAllowed(1024ull * 1024ull, 1));
	CHECK_FALSE(WebServerStaticFileSeams::IsStaticFileSizeAllowed(1024ull * 1024ull + 1ull, 1));
	CHECK(WebServerStaticFileSeams::IsStaticFileSizeAllowed(0xffffffffffffffffull, 0));
	CHECK_EQ(WebServerStaticFileSeams::kStaticFileChunkSize, 64u * 1024u);
}

TEST_CASE("WebServer auth state seam preserves legacy timeout and bad-login thresholds")
{
	CHECK_FALSE(WebServerAuthStateSeams::ShouldDenyForBadLoginFaults(4));
	CHECK(WebServerAuthStateSeams::ShouldDenyForBadLoginFaults(5));

	CHECK_FALSE(WebServerAuthStateSeams::IsBadLoginExpired(1000, 500, 600));
	CHECK(WebServerAuthStateSeams::IsBadLoginExpired(1100, 500, 600));

	CHECK_FALSE(WebServerAuthStateSeams::IsSessionExpired(299, 5));
	CHECK(WebServerAuthStateSeams::IsSessionExpired(300, 5));
	CHECK_FALSE(WebServerAuthStateSeams::IsSessionExpired(100000, 0));
}

TEST_CASE("Web API exposes stable server priority names for the REST surface")
{
	CHECK(std::string(WebApiSurfaceSeams::GetServerPriorityName(2)) == "low");
	CHECK(std::string(WebApiSurfaceSeams::GetServerPriorityName(0)) == "normal");
	CHECK(std::string(WebApiSurfaceSeams::GetServerPriorityName(1)) == "high");
	CHECK(std::string(WebApiSurfaceSeams::GetServerPriorityName(99)) == "normal");
}

TEST_CASE("Web API exposes stable upload state names for the REST surface")
{
	CHECK(std::string(WebApiSurfaceSeams::GetUploadStateName(0)) == "uploading");
	CHECK(std::string(WebApiSurfaceSeams::GetUploadStateName(1)) == "queued");
	CHECK(std::string(WebApiSurfaceSeams::GetUploadStateName(2)) == "connecting");
	CHECK(std::string(WebApiSurfaceSeams::GetUploadStateName(3)) == "banned");
	CHECK(std::string(WebApiSurfaceSeams::GetUploadStateName(4)) == "idle");
	CHECK(std::string(WebApiSurfaceSeams::GetUploadStateName(255)) == "idle");
}

TEST_CASE("Web API exposes stable download source state names for the REST surface")
{
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(0)) == "downloading");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(1)) == "onqueue");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(2)) == "connected");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(3)) == "connecting");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(4)) == "waitcallback");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(5)) == "waitcallbackkad");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(6)) == "reqhashset");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(7)) == "noneededparts");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(8)) == "toomanyconns");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(9)) == "toomanyconnskad");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(10)) == "lowtolowip");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(11)) == "banned");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(12)) == "error");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(13)) == "none");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(14)) == "remotequeuefull");
	CHECK(std::string(WebApiSurfaceSeams::GetDownloadStateName(255)) == "unknown");
}

TEST_CASE("Web API shares bounded transfer progress ratios across native and Arr surfaces")
{
	CHECK_EQ(WebApiSurfaceSeams::BuildTransferProgressRatio(0, 0), 0.0);
	CHECK_EQ(WebApiSurfaceSeams::BuildTransferProgressRatio(0, 100), 0.0);
	CHECK_EQ(WebApiSurfaceSeams::BuildTransferProgressRatio(50, 100), 0.5);
	CHECK_EQ(WebApiSurfaceSeams::BuildTransferProgressRatio(100, 100), 1.0);
	CHECK_EQ(WebApiSurfaceSeams::BuildTransferProgressRatio(120, 100), 1.0);
	CHECK_EQ(WebApiSurfaceSeams::BuildTransferProgressRatio(1, 3), 0.3333);
	CHECK_EQ(WebApiSurfaceSeams::BuildTransferProgressRatio(2, 3), 0.6667);
}

TEST_CASE("Web API parses the final transfer priority vocabulary")
{
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("auto"), WebApiSurfaceSeams::ETransferPriority::Auto);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("verylow"), WebApiSurfaceSeams::ETransferPriority::VeryLow);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("low"), WebApiSurfaceSeams::ETransferPriority::Low);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("normal"), WebApiSurfaceSeams::ETransferPriority::Normal);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("high"), WebApiSurfaceSeams::ETransferPriority::High);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("veryhigh"), WebApiSurfaceSeams::ETransferPriority::VeryHigh);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("veryLow"), WebApiSurfaceSeams::ETransferPriority::Invalid);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("very_high"), WebApiSurfaceSeams::ETransferPriority::Invalid);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("invalid"), WebApiSurfaceSeams::ETransferPriority::Invalid);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName(nullptr), WebApiSurfaceSeams::ETransferPriority::Invalid);
	CHECK(WebApiSurfaceSeams::IsTransferPriorityName("auto"));
	CHECK(WebApiSurfaceSeams::IsTransferPriorityName("veryhigh"));
	CHECK_FALSE(WebApiSurfaceSeams::IsTransferPriorityName("release"));
	CHECK(WebApiSurfaceSeams::IsCategoryPriorityName("verylow"));
	CHECK_FALSE(WebApiSurfaceSeams::IsCategoryPriorityName("auto"));
	CHECK(WebApiSurfaceSeams::IsSharedUploadPriorityName("release"));
	CHECK_FALSE(WebApiSurfaceSeams::IsSharedUploadPriorityName("veryhigh"));
	CHECK_FALSE(WebApiSurfaceSeams::IsSharedUploadPriorityName("Release"));
	CHECK(WebApiSurfaceSeams::IsServerPriorityName("normal"));
	CHECK_FALSE(WebApiSurfaceSeams::IsServerPriorityName("veryhigh"));
}

TEST_CASE("Web API parses the expanded mutable preference vocabulary")
{
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("uploadLimitKiBps"), WebApiSurfaceSeams::EMutablePreference::MaxUploadKiB);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("downloadLimitKiBps"), WebApiSurfaceSeams::EMutablePreference::MaxDownloadKiB);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxConnections"), WebApiSurfaceSeams::EMutablePreference::MaxConnections);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxConnectionsPerFiveSeconds"), WebApiSurfaceSeams::EMutablePreference::MaxConPerFive);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxSourcesPerFile"), WebApiSurfaceSeams::EMutablePreference::MaxSourcesPerFile);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("uploadClientDataRate"), WebApiSurfaceSeams::EMutablePreference::UploadClientDataRate);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxUploadSlots"), WebApiSurfaceSeams::EMutablePreference::MaxUploadSlots);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("queueSize"), WebApiSurfaceSeams::EMutablePreference::QueueSize);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("autoConnect"), WebApiSurfaceSeams::EMutablePreference::AutoConnect);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("newAutoUp"), WebApiSurfaceSeams::EMutablePreference::NewAutoUp);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("newAutoDown"), WebApiSurfaceSeams::EMutablePreference::NewAutoDown);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("creditSystem"), WebApiSurfaceSeams::EMutablePreference::CreditSystem);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("safeServerConnect"), WebApiSurfaceSeams::EMutablePreference::SafeServerConnect);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("networkKademlia"), WebApiSurfaceSeams::EMutablePreference::NetworkKademlia);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("networkEd2k"), WebApiSurfaceSeams::EMutablePreference::NetworkEd2K);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("autoBroadbandIo"), WebApiSurfaceSeams::EMutablePreference::AutoBroadbandIO);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("unsupported"), WebApiSurfaceSeams::EMutablePreference::Invalid);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName(nullptr), WebApiSurfaceSeams::EMutablePreference::Invalid);
}

TEST_CASE("Web API preference bounds match UI and INI persistence ranges")
{
	CHECK_FALSE(WebApiSurfaceSeams::IsFiniteKiBpsPreferenceValue(0));
	CHECK(WebApiSurfaceSeams::IsFiniteKiBpsPreferenceValue(1));
	CHECK(WebApiSurfaceSeams::IsFiniteKiBpsPreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMaxFiniteKiBps));
	CHECK_FALSE(WebApiSurfaceSeams::IsFiniteKiBpsPreferenceValue(WebApiSurfaceSeams::kMutablePreferenceUnlimitedSentinel));

	CHECK_FALSE(WebApiSurfaceSeams::IsPositiveSignedIntPreferenceValue(0));
	CHECK(WebApiSurfaceSeams::IsPositiveSignedIntPreferenceValue(1));
	CHECK(WebApiSurfaceSeams::IsPositiveSignedIntPreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMaxSignedInt));
	CHECK_FALSE(WebApiSurfaceSeams::IsPositiveSignedIntPreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMaxSignedInt + 1));

	CHECK_FALSE(WebApiSurfaceSeams::IsQueueSizePreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMinQueueSize - 1));
	CHECK(WebApiSurfaceSeams::IsQueueSizePreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMinQueueSize));
	CHECK(WebApiSurfaceSeams::IsQueueSizePreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMaxQueueSize));
	CHECK_FALSE(WebApiSurfaceSeams::IsQueueSizePreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMaxQueueSize + 1));

	CHECK_FALSE(WebApiSurfaceSeams::IsUploadSlotPreferenceValue(0));
	CHECK(WebApiSurfaceSeams::IsUploadSlotPreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMinUploadSlots));
	CHECK(WebApiSurfaceSeams::IsUploadSlotPreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMaxUploadSlots));
	CHECK_FALSE(WebApiSurfaceSeams::IsUploadSlotPreferenceValue(WebApiSurfaceSeams::kMutablePreferenceMaxUploadSlots + 1));
}

TEST_CASE("Web API validates lowercase compact search method and type tokens")
{
	const std::vector<std::string> nativeSearchTypes = {"", "arc", "audio", "iso", "image", "pro", "video", "doc", "emulecollection"};
	CHECK_EQ(WebServerJsonSeams::GetRestSearchFileTypeNames(), nativeSearchTypes);

	CHECK_EQ(std::string(WebServerJsonSeams::GetDefaultSearchMethodName()), "automatic");
	CHECK(WebServerJsonSeams::IsSearchMethodName("automatic"));
	CHECK(WebServerJsonSeams::IsSearchMethodName("kad"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchMethodName("AUTOMATIC"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchMethodName("KaD"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchMethodName(""));
	CHECK_FALSE(WebServerJsonSeams::IsSearchMethodName("contentdb"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchMethodName("gloabal"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchFileTypeName("ISO"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchFileTypeName("Iso"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName(""));
	CHECK_FALSE(WebServerJsonSeams::IsSearchFileTypeName("any"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName("arc"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName("audio"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchFileTypeName("cdimage"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName("image"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName("pro"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName("video"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName("doc"));
	CHECK(WebServerJsonSeams::IsSearchFileTypeName("emulecollection"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchFileTypeName("emuleCollection"));
	CHECK_FALSE(WebServerJsonSeams::IsSearchFileTypeName("ebook"));

	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName("automatic"), WebApiCommandSeams::ESearchMethod::Automatic);
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName("global"), WebApiCommandSeams::ESearchMethod::Global);
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName("gLoBaL"), WebApiCommandSeams::ESearchMethod::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName(""), WebApiCommandSeams::ESearchMethod::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName(nullptr), WebApiCommandSeams::ESearchMethod::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName(""), WebApiCommandSeams::ESearchFileType::Any);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("any"), WebApiCommandSeams::ESearchFileType::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("arc"), WebApiCommandSeams::ESearchFileType::Archive);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("audio"), WebApiCommandSeams::ESearchFileType::Audio);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("VIDEO"), WebApiCommandSeams::ESearchFileType::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("video"), WebApiCommandSeams::ESearchFileType::Video);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("Video"), WebApiCommandSeams::ESearchFileType::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("doc"), WebApiCommandSeams::ESearchFileType::Document);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("iso"), WebApiCommandSeams::ESearchFileType::CdImage);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("Iso"), WebApiCommandSeams::ESearchFileType::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName(std::string("iso\0video", 9)), WebApiCommandSeams::ESearchFileType::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("CDIMAGE"), WebApiCommandSeams::ESearchFileType::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("image"), WebApiCommandSeams::ESearchFileType::Image);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("pro"), WebApiCommandSeams::ESearchFileType::Program);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("emulecollection"), WebApiCommandSeams::ESearchFileType::EmuleCollection);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName(nullptr), WebApiCommandSeams::ESearchFileType::Invalid);
	CHECK_EQ(std::string(WebServerJsonSeams::GetNativeSearchFileTypeName("video")), "Video");
	CHECK_EQ(WebServerJsonSeams::GetRestSearchFileTypeName("Video"), "video");
	CHECK_EQ(WebServerJsonSeams::GetRestSearchFileTypeName("ebook"), "");
}

TEST_CASE("Web API command helpers share REST parser primitives")
{
	uint64_t uValue = 0;
	CHECK(WebApiCommandSeams::TryParseUnsignedDecimalString("18446744073709551615", uValue));
	CHECK_EQ(uValue, 18446744073709551615ull);
	CHECK_FALSE(WebApiCommandSeams::TryParseUnsignedDecimalString("18446744073709551616", uValue));
	CHECK_FALSE(WebApiCommandSeams::TryParseUnsignedDecimalString("+1", uValue));
	CHECK_EQ(WebApiCommandSeams::TrimAsciiWhitespace("\t linux \r\n"), "linux");
	CHECK_EQ(WebApiCommandSeams::ToLowerAscii("LiNuX"), "linux");
	CHECK(WebApiCommandSeams::IsLowercaseMd4HexString("0123456789abcdef0123456789abcdef"));
	CHECK_FALSE(WebApiCommandSeams::IsLowercaseMd4HexString("0123456789ABCDEF0123456789ABCDEF"));
}

TEST_CASE("Web API shares strict bounded unsigned parsing across native REST and Arr adapters")
{
	uint64_t ullValue = 0;
	CHECK(WebServerJsonSeams::TryParseUnsignedDecimalValue("42", ullValue));
	CHECK_EQ(ullValue, 42u);
	CHECK_FALSE(WebServerJsonSeams::TryParseUnsignedDecimalValue("+42", ullValue));
	CHECK_FALSE(WebServerJsonSeams::TryParseUnsignedDecimalValue(" 42", ullValue));
	CHECK_FALSE(WebServerJsonSeams::TryParseUnsignedDecimalValue("18446744073709551616", ullValue));
	CHECK(WebServerJsonSeams::TryParseJsonUInt64(WebServerJsonSeams::json(42), ullValue));
	CHECK_EQ(ullValue, 42u);
	CHECK_FALSE(WebServerJsonSeams::TryParseJsonUInt64(WebServerJsonSeams::json(-1), ullValue));
	CHECK_FALSE(WebServerJsonSeams::TryParseJsonUInt64(WebServerJsonSeams::json("42"), ullValue));
	CHECK(WebServerJsonSeams::TryParseJsonUInt64(WebServerJsonSeams::json("42"), ullValue, true));
	CHECK_EQ(ullValue, 42u);
	CHECK_FALSE(WebServerJsonSeams::TryParseJsonUInt64(WebServerJsonSeams::json("18446744073709551616"), ullValue, true));

	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?limit=+42", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "limit must be an unsigned number");

	WebServerArrCompatSeams::STorznabRequest torznabRequest;
	std::string error;
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=tvsearch&q=Show&season=+1&ep=2", torznabRequest, error));
	CHECK_EQ(error, "season must be an unsigned decimal value in the range 0..9999");

	std::string addUrl;
	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryValidateAddRequestUrl(
		"magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef00000000&dn=x&xl=+42",
		addUrl,
		error));
	CHECK_EQ(error, "magnet URLs are not supported");
}

TEST_CASE("Web API only allows shared-file removal for files that are shared and not mandatory")
{
	CHECK(WebApiSurfaceSeams::CanRemoveSharedFile(true, false));
	CHECK_FALSE(WebApiSurfaceSeams::CanRemoveSharedFile(false, false));
	CHECK_FALSE(WebApiSurfaceSeams::CanRemoveSharedFile(true, true));
}

TEST_CASE("Web API shared-file metadata distinguishes rule-backed and manual shares")
{
	CHECK(WebServerJsonSeams::BuildSharedByRuleFlag(true));
	CHECK_FALSE(WebServerJsonSeams::BuildSharedByRuleFlag(false));
}

TEST_CASE("Web API UI dispatch uses a bounded wait result")
{
	CHECK(WebServerJsonSeams::kRestUiDispatchTimeoutMs > 0u);
	CHECK(WebServerJsonSeams::DidRestUiDispatchComplete(TRUE));
	CHECK_FALSE(WebServerJsonSeams::DidRestUiDispatchComplete(FALSE));
}

TEST_CASE("Web API rejects REST command execution during app shutdown")
{
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandDuringShutdown(true));
	CHECK_FALSE(WebServerJsonSeams::ShouldRejectRestCommandDuringShutdown(false));
	CHECK_FALSE(WebServerJsonSeams::IsRestMutationMethod("GET"));
	CHECK(WebServerJsonSeams::IsRestMutationMethod("POST"));
	CHECK(WebServerJsonSeams::IsRestMutationMethod("PATCH"));
	CHECK(WebServerJsonSeams::IsRestMutationMethod("DELETE"));

	CHECK(WebServerJsonSeams::GetLifecyclePolicyForCommand("app/version") == WebServerJsonSeams::ERestLifecyclePolicy::Read);
	CHECK(WebServerJsonSeams::GetLifecyclePolicyForCommand("status/get") == WebServerJsonSeams::ERestLifecyclePolicy::Read);
	CHECK(WebServerJsonSeams::GetLifecyclePolicyForCommand("transfers/list") == WebServerJsonSeams::ERestLifecyclePolicy::Read);
	CHECK(WebServerJsonSeams::GetLifecyclePolicyForCommand("transfers/add") == WebServerJsonSeams::ERestLifecyclePolicy::Mutation);
	CHECK(WebServerJsonSeams::GetLifecyclePolicyForCommand("app/preferences/set") == WebServerJsonSeams::ERestLifecyclePolicy::Mutation);
	CHECK(WebServerJsonSeams::GetLifecyclePolicyForCommand("app/shutdown") == WebServerJsonSeams::ERestLifecyclePolicy::Shutdown);
	CHECK(WebServerJsonSeams::GetLifecyclePolicyForCommand("app/capture_dump") == WebServerJsonSeams::ERestLifecyclePolicy::DiagnosticUnsafe);

	const SAppLifecycleStatus starting = BuildAppLifecycleStatus(APP_STATE_STARTING, false, false);
	CHECK_FALSE(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(starting, WebServerJsonSeams::ERestLifecyclePolicy::Read));
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(starting, WebServerJsonSeams::ERestLifecyclePolicy::Mutation));
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(starting, WebServerJsonSeams::ERestLifecyclePolicy::Shutdown));
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(starting, WebServerJsonSeams::ERestLifecyclePolicy::DiagnosticUnsafe));

	const SAppLifecycleStatus runningBeforeStartupComplete = BuildAppLifecycleStatus(APP_STATE_RUNNING, false, false);
	CHECK_FALSE(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(runningBeforeStartupComplete, WebServerJsonSeams::ERestLifecyclePolicy::Read));
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(runningBeforeStartupComplete, WebServerJsonSeams::ERestLifecyclePolicy::Mutation));
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(runningBeforeStartupComplete, WebServerJsonSeams::ERestLifecyclePolicy::Shutdown));
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(runningBeforeStartupComplete, WebServerJsonSeams::ERestLifecyclePolicy::DiagnosticUnsafe));

	const SAppLifecycleStatus running = BuildAppLifecycleStatus(APP_STATE_RUNNING, true, true);
	CHECK_FALSE(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(running, WebServerJsonSeams::ERestLifecyclePolicy::Read));
	CHECK_FALSE(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(running, WebServerJsonSeams::ERestLifecyclePolicy::Mutation));
	CHECK_FALSE(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(running, WebServerJsonSeams::ERestLifecyclePolicy::Shutdown));
	CHECK_FALSE(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(running, WebServerJsonSeams::ERestLifecyclePolicy::DiagnosticUnsafe));

	const SAppLifecycleStatus shuttingDown = BuildAppLifecycleStatus(APP_STATE_SHUTTINGDOWN, true, true);
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(shuttingDown, WebServerJsonSeams::ERestLifecyclePolicy::Read));
	CHECK(WebServerJsonSeams::ShouldRejectRestCommandForLifecycle(shuttingDown, WebServerJsonSeams::ERestLifecyclePolicy::Mutation));
}

TEST_CASE("Web API busy errors map to service unavailable")
{
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("SERVICE_BUSY"), 503);
}

TEST_CASE("Web API parses the search start command vocabulary and trims the query")
{
	WebApiCommandSeams::SSearchStartRequest request;
	std::string error;
	const std::string strUnicodeQuery(std::string("linux ") + std::string("\xC3\xBC", 2) + "ber");
	CHECK_EQ(std::string(WebApiCommandSeams::GetDefaultSearchMethodName()), "automatic");
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName(WebApiCommandSeams::GetDefaultSearchMethodName()), WebApiCommandSeams::ESearchMethod::Automatic);

	const WebApiCommandSeams::json params = {
		{"query", "\t 1080p \n"},
		{"method", "kad"},
		{"type", "iso"},
		{"extension", ".mkv"},
		{"minSizeBytes", 700u},
		{"maxSizeBytes", 4096u}
	};

	CHECK(WebApiCommandSeams::TryParseSearchStartRequest(params, request, error));
	CHECK(error.empty());
	CHECK_EQ(request.strQuery, "1080p");
	CHECK_EQ(request.eMethod, WebApiCommandSeams::ESearchMethod::Kad);
	CHECK_EQ(request.eFileType, WebApiCommandSeams::ESearchFileType::CdImage);
	CHECK_EQ(request.strFileType, "iso");
	CHECK_EQ(request.strExtension, ".mkv");
	CHECK(request.bHasMinSize);
	CHECK(request.bHasMaxSize);
	CHECK_EQ(request.ullMinSize, 700u);
	CHECK_EQ(request.ullMaxSize, 4096u);

	error.clear();
	CHECK(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "feature film"}, {"method", "global"}, {"type", "video"}}, request, error));
	CHECK_EQ(request.eMethod, WebApiCommandSeams::ESearchMethod::Global);
	CHECK_EQ(request.eFileType, WebApiCommandSeams::ESearchFileType::Video);
	CHECK_EQ(request.strFileType, "video");

	error.clear();
	CHECK(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", strUnicodeQuery}}, request, error));
	CHECK_EQ(request.strQuery, strUnicodeQuery);
	CHECK_EQ(request.strFileType, "");
}

TEST_CASE("Web API rejects invalid search start payloads before they touch the UI")
{
	WebApiCommandSeams::SSearchStartRequest request;
	std::string error;

	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "   "}}, request, error));
	CHECK_EQ(error, "query must not be empty");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"method", "contentdb"}}, request, error));
	CHECK_EQ(error, "method must be one of automatic, server, global, kad");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"type", "ebook"}}, request, error));
	CHECK_EQ(error, "type is not supported");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"type", "Iso"}}, request, error));
	CHECK_EQ(error, "type is not supported");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"type", "Video"}}, request, error));
	CHECK_EQ(error, "type is not supported");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"type", std::string("iso\0video", 9)}}, request, error));
	CHECK_EQ(error, "type is not supported");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"minSizeBytes", -1}}, request, error));
	CHECK_EQ(error, "minSizeBytes must be an unsigned number");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", 7}}, request, error));
	CHECK_EQ(error, "query must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"method", 7}}, request, error));
	CHECK_EQ(error, "method must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"type", 7}}, request, error));
	CHECK_EQ(error, "type must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"extension", 7}}, request, error));
	CHECK_EQ(error, "extension must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"maxSizeBytes", -1}}, request, error));
	CHECK_EQ(error, "maxSizeBytes must be an unsigned number");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"minSizeBytes", 4096}, {"maxSizeBytes", 700}}, request, error));
	CHECK_EQ(error, "maxSizeBytes must be greater than or equal to minSizeBytes");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"minAvailability", 1000001}}, request, error));
	CHECK_EQ(error, "minAvailability must be an unsigned number in the range 0..1000000");

	error.clear();
	const std::string strInvalidUtf8(std::string("bad ") + std::string("\xC3\x28", 2));
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", strInvalidUtf8}}, request, error));
	CHECK_EQ(error, "query must be valid UTF-8 without control characters");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", std::string("bad\x01query", 9)}}, request, error));
	CHECK_EQ(error, "query must be valid UTF-8 without control characters");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", std::string(WebServerJsonSeams::kMaxSearchQueryLength + 1, 'x')}}, request, error));
	CHECK_EQ(error, "query must be at most 160 characters");
}

TEST_CASE("Web API shares search text normalization between native REST and Torznab")
{
	WebApiCommandSeams::SSearchStartRequest nativeRequest;
	WebServerArrCompatSeams::STorznabRequest torznabRequest;
	std::string error;
	const std::string strExpectedQuery(std::string("Example Name ") + std::string("\xC3\xBC", 2) + "ber");

	CHECK(WebApiCommandSeams::TryParseSearchStartRequest(
		WebApiCommandSeams::json{{"query", std::string("\t Example \r\n  Name  ") + std::string("\xC3\xBC", 2) + "ber "}},
		nativeRequest,
		error));
	CHECK_EQ(nativeRequest.strQuery, strExpectedQuery);

	error.clear();
	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest(
		"/indexer/emulebb/api?t=search&q=++Example+%0D%0A++Name++%C3%BCber+",
		torznabRequest,
		error));
	CHECK_EQ(torznabRequest.strQuery, strExpectedQuery);
}

TEST_CASE("Web API parses search identifiers as decimal uint32 strings")
{
	uint32_t uSearchID = 0;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json("12345"), uSearchID, error));
	CHECK_EQ(uSearchID, 12345u);

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json(""), uSearchID, error));
	CHECK_EQ(error, "searchId must not be empty");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json("12x"), uSearchID, error));
	CHECK_EQ(error, "searchId must be a valid uint32 decimal string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json("+12"), uSearchID, error));
	CHECK_EQ(error, "searchId must be a valid uint32 decimal string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json(" 12"), uSearchID, error));
	CHECK_EQ(error, "searchId must be a valid uint32 decimal string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json(7), uSearchID, error));
	CHECK_EQ(error, "searchId must be a decimal string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json("4294967296"), uSearchID, error));
	CHECK_EQ(error, "searchId must be a valid uint32 decimal string");
}

TEST_CASE("Web API parses transfer list selectors and validates categories")
{
	WebApiCommandSeams::STransfersListRequest request;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransfersListRequest(WebApiCommandSeams::json{{"state", "downloading"}, {"categoryId", 3}}, request, error));
	CHECK_EQ(request.strState, "downloading");
	CHECK(request.bHasCategory);
	CHECK_EQ(request.uCategory, 3u);

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransfersListRequest(WebApiCommandSeams::json{{"state", 7}}, request, error));
	CHECK_EQ(error, "state must be a string when provided");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransfersListRequest(WebApiCommandSeams::json{{"state", "missing_files"}}, request, error));
	CHECK_EQ(error, "state must be one of downloading, paused, queued, checking, completing, completed, error, missingfiles");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransfersListRequest(WebApiCommandSeams::json{{"categoryId", -1}}, request, error));
	CHECK_EQ(error, "categoryId must be an unsigned number");
}

TEST_CASE("Web API trims transfer add links and rejects empty payloads")
{
	std::string link;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransferAddLink(WebApiCommandSeams::json{{"link", " ed2k://|file|ubuntu.iso|1|0123456789abcdef0123456789abcdef|/ "}}, link, error));
	CHECK_EQ(link, "ed2k://|file|ubuntu.iso|1|0123456789abcdef0123456789abcdef|/");

	error.clear();
	CHECK(WebApiCommandSeams::TryParseTransferAddLink(WebApiCommandSeams::json{{"link", " ed2k://|server|1.2.3.4|4661|/ "}}, link, error));
	CHECK_EQ(link, "ed2k://|server|1.2.3.4|4661|/");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferAddLink(WebApiCommandSeams::json{{"link", "https://example.test/file.bin"}}, link, error));
	CHECK_EQ(error, "link must start with ed2k://");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferAddLink(WebApiCommandSeams::json{{"link", "   "}}, link, error));
	CHECK_EQ(error, "link must not be empty");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferAddLink(WebApiCommandSeams::json{{"link", 7}}, link, error));
	CHECK_EQ(error, "link must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferAddLink(WebApiCommandSeams::json::object(), link, error));
	CHECK_EQ(error, "link must be a string");
}

TEST_CASE("Web API preserves source-oriented ed2k links after trimming transport whitespace")
{
	std::string link;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransferAddLink(
		WebApiCommandSeams::json{{"link", "\n\ted2k://|file|ubuntu.iso|1|0123456789abcdef0123456789abcdef|sources,1.2.3.4:4662|/\r\n"}},
		link,
		error));
	CHECK_EQ(link, "ed2k://|file|ubuntu.iso|1|0123456789abcdef0123456789abcdef|sources,1.2.3.4:4662|/");
}

TEST_CASE("Web API validates native transfer add bodies before dispatch")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "link or links is required");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","links":[]})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "link and links are mutually exclusive");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"links":[]})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "links must not be empty");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"links":["ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","   "]})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "links must be a non-empty string array");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","paused":"true"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "paused must be a boolean");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"links":[" ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/ "]})", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "transfers/add");
	CHECK_EQ(route.params["links"][0].get<std::string>(), "ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/");
}

TEST_CASE("Web API parses bulk transfer mutations with the final deleteFiles spelling")
{
	WebApiCommandSeams::STransferBulkMutationRequest request;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransferBulkMutationRequest(
		WebApiCommandSeams::json{
			{"hashes", WebApiCommandSeams::json::array({"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"})},
			{"deleteFiles", true}
		},
		request,
		error));
	CHECK_EQ(request.hashes.size(), 2u);
	CHECK(request.bDeleteFiles);
	CHECK_EQ(request.hashes[0].get<std::string>(), "0123456789abcdef0123456789abcdef");
	CHECK_EQ(request.hashes[1].get<std::string>(), "fedcba9876543210fedcba9876543210");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferBulkMutationRequest(WebApiCommandSeams::json{{"hashes", "abc"}}, request, error));
	CHECK_EQ(error, "hashes must be a string array");
}

TEST_CASE("Web API validates bulk transfer hash arrays and delete flags")
{
	WebApiCommandSeams::STransferBulkMutationRequest request;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransferBulkMutationRequest(
		WebApiCommandSeams::json{
			{"hashes", WebApiCommandSeams::json::array()},
			{"deleteFiles", true}
		},
		request,
		error));
	CHECK(request.bDeleteFiles);
	CHECK_EQ(request.hashes.size(), 0u);

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferBulkMutationRequest(WebApiCommandSeams::json::object(), request, error));
	CHECK_EQ(error, "hashes must be a string array");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferBulkMutationRequest(
		WebApiCommandSeams::json{
			{"hashes", WebApiCommandSeams::json::array({"0123456789abcdef0123456789abcdeg"})},
			{"deleteFiles", true}
		},
		request,
		error));
	CHECK_EQ(error, "hashes must be a string array of 32-character lowercase hex strings");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferBulkMutationRequest(
		WebApiCommandSeams::json{
			{"hashes", WebApiCommandSeams::json::array({"0123456789abcdef0123456789abcdef"})},
			{"deleteFiles", "yes"}
		},
		request,
		error));
	CHECK_EQ(error, "deleteFiles must be a boolean");
}

TEST_CASE("Web API validates transfer rename payloads")
{
	WebApiCommandSeams::STransferRenameRequest request;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransferRenameRequest(
		WebApiCommandSeams::json{{"name", " renamed.bin "}},
		request,
		error));
	CHECK_EQ(request.strName, "renamed.bin");
	CHECK(request.bExplicitUserRename);

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferRenameRequest(WebApiCommandSeams::json::object(), request, error));
	CHECK_EQ(error, "name must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferRenameRequest(
		WebApiCommandSeams::json{{"name", 7}},
		request,
		error));
	CHECK_EQ(error, "name must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferRenameRequest(
		WebApiCommandSeams::json{{"name", "   "}},
		request,
		error));
	CHECK_EQ(error, "name must not be empty");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferRenameRequest(
		WebApiCommandSeams::json{{"name", std::string(256, 'a')}},
		request,
		error));
	CHECK_EQ(error, "name must be at most 255 characters");

	error.clear();
	std::string strControlName("bad");
	strControlName.push_back('\x01');
	strControlName += "name.bin";
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferRenameRequest(
		WebApiCommandSeams::json{{"name", strControlName}},
		request,
		error));
	CHECK_EQ(error, "name must be valid UTF-8 without control characters");
}

TEST_CASE("Web API validates shared-file rating/comment payloads")
{
	WebApiCommandSeams::SSharedFileRatingCommentRequest request;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseSharedFileRatingCommentRequest(
		WebApiCommandSeams::json{{"comment", "good release"}, {"rating", 5}},
		request,
		error));
	CHECK_EQ(request.strComment, "good release");
	CHECK_EQ(request.iRating, 5);

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSharedFileRatingCommentRequest(
		WebApiCommandSeams::json{{"rating", 3}},
		request,
		error));
	CHECK_EQ(error, "comment must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSharedFileRatingCommentRequest(
		WebApiCommandSeams::json{{"comment", 7}, {"rating", 3}},
		request,
		error));
	CHECK_EQ(error, "comment must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSharedFileRatingCommentRequest(
		WebApiCommandSeams::json{{"comment", "bad"}},
		request,
		error));
	CHECK_EQ(error, "rating must be an integer between 0 and 5");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSharedFileRatingCommentRequest(
		WebApiCommandSeams::json{{"comment", "bad"}, {"rating", 6}},
		request,
		error));
	CHECK_EQ(error, "rating must be an integer between 0 and 5");
}

TEST_CASE("Web API recognizes REST request targets without disturbing legacy HTML paths")
{
	CHECK(WebServerJsonSeams::IsApiRequestTarget("/api/v1"));
	CHECK(WebServerJsonSeams::IsApiRequestTarget("/api/v1/app"));
	CHECK(WebServerJsonSeams::IsApiRequestTarget("/API/V1/logs?limit=2"));
	CHECK_FALSE(WebServerJsonSeams::IsApiRequestTarget("/"));
	CHECK_FALSE(WebServerJsonSeams::IsApiRequestTarget("/serverlist"));
}

TEST_CASE("Web API leaves legacy HTML GET targets outside REST and compat dispatch")
{
	const char *const pszLegacyTargets[] = {
		"/",
		"/serverlist",
		"/serverlist?ses=123",
		"/transfer",
		"/search?ses=123",
		"/graphs",
		"/emule.tmpl"
	};

	for (const char *const pszTarget : pszLegacyTargets) {
		CAPTURE(pszTarget);
		CHECK_FALSE(WebServerJsonSeams::IsApiRequestTarget(pszTarget));
		CHECK_FALSE(WebServerArrCompatSeams::IsArrCompatRequestTarget(pszTarget));
		CHECK_FALSE(WebServerQBitCompatSeams::IsQBitRequestTarget(pszTarget));
	}
}

TEST_CASE("Web API recognizes the Prowlarr Torznab compatibility endpoint")
{
	std::string path;
	std::string error;

	CHECK(WebServerArrCompatSeams::IsArrCompatRequestTarget("/indexer/emulebb/api"));
	CHECK(WebServerArrCompatSeams::IsArrCompatRequestTarget("/INDEXER/EMULEBB/API?t=caps"));
	CHECK(WebServerArrCompatSeams::IsArrCompatRequestTarget("/indexer/emulebb/api%2x?t=caps"));
	CHECK_FALSE(WebServerArrCompatSeams::IsArrCompatRequestTarget("/api/v1/indexer/emulebb/api"));
	CHECK_FALSE(WebServerArrCompatSeams::IsArrCompatRequestTarget("/indexer/emulebb"));

	CHECK(WebServerArrCompatSeams::TryGetArrCompatRequestPathLower("/INDEXER/EMULEBB/API?t=caps", path, error));
	CHECK_EQ(path, "/indexer/emulebb/api");
	CHECK_FALSE(WebServerArrCompatSeams::TryGetArrCompatRequestPathLower("/indexer/emulebb/api%2x?t=caps", path, error));
	CHECK_EQ(error, "malformed percent escape");
}

TEST_CASE("Web API maps Torznab requests to native eMule search hints")
{
	CHECK_EQ(WebServerArrCompatSeams::kTorznabParseErrorHttpStatus, 400);

	std::map<std::string, std::string> normalizedQuery;
	std::string queryError;
	CHECK(WebServerArrCompatSeams::TryParseTorznabQueryParameters("/indexer/emulebb/api?T=search&APIKEY=secret", normalizedQuery, queryError));
	CHECK_EQ(normalizedQuery["t"], "search");
	CHECK_EQ(normalizedQuery["apikey"], "secret");

	queryError.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabQueryParameters("/indexer/emulebb/api?t=search&t=movie", normalizedQuery, queryError));
	CHECK_EQ(queryError, "duplicate query parameter: t");
	CHECK(normalizedQuery.empty());

	WebServerArrCompatSeams::STorznabRequest request;
	std::string error;

	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=tvsearch&q=Example+++Name&season=1&ep=2&cat=5000", request, error));
	CHECK_EQ(request.strQuery, "Example Name");
	CHECK_EQ(request.eFamily, WebServerArrCompatSeams::ETorznabFamily::Tv);
	CHECK_EQ(std::string(WebServerArrCompatSeams::GetRestSearchType(request.eFamily)), "video");
	const std::vector<std::string> queries = WebServerArrCompatSeams::BuildNativeQueries(request);
	REQUIRE_EQ(queries.size(), 3u);
	CHECK_EQ(queries[0], "Example Name S01E02");
	CHECK_EQ(queries[1], "Example Name 1x02");
	CHECK_EQ(queries[2], "Example Name");

	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=movie&q=Feature&year=2026&cat=2000", request, error));
	CHECK_EQ(WebServerArrCompatSeams::BuildNativeQueries(request), std::vector<std::string>{"Feature 2026", "Feature"});

	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=movie&q=Feature&cat=2000&offset=100&limit=25", request, error));
	CHECK_EQ(request.uOffset, 100u);
	CHECK_EQ(request.uLimit, 25u);
	const std::string pagedCacheKey(WebServerArrCompatSeams::BuildCacheKey(request));
	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=movie&q=Feature&cat=2000&offset=0&limit=100", request, error));
	CHECK_EQ(WebServerArrCompatSeams::BuildCacheKey(request), pagedCacheKey);
	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Feature&cat=2000&limit=0", request, error));
	CHECK_EQ(request.uLimit, WebServerArrCompatSeams::kDefaultTorznabLimit);

	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Album&cat=3000", request, error));
	CHECK_EQ(request.eFamily, WebServerArrCompatSeams::ETorznabFamily::Audio);
	CHECK_EQ(std::string(WebServerArrCompatSeams::GetRestSearchType(request.eFamily)), "audio");

	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Unknown&cat=9999", request, error));
	CHECK_EQ(request.eFamily, WebServerArrCompatSeams::ETorznabFamily::Unknown);

	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Mixed&cat=2000,3000", request, error));
	CHECK_EQ(request.eFamily, WebServerArrCompatSeams::ETorznabFamily::Any);

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Bad&cat=abc", request, error));
	CHECK_EQ(error, "cat must contain unsigned decimal Torznab category IDs");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Bad&cat=999999999999999999999", request, error));
	CHECK_EQ(error, "cat must contain unsigned decimal Torznab category IDs");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Bad&cat=2000,", request, error));
	CHECK_EQ(error, "cat must contain unsigned decimal Torznab category IDs");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=movie&q=Bad&cat=+2000", request, error));
	CHECK_EQ(error, "cat must contain unsigned decimal Torznab category IDs");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=tvsearch&q=Bad&season=x&ep=2", request, error));
	CHECK_EQ(error, "season must be an unsigned decimal value in the range 0..9999");
	CHECK(request.strQuery.empty());

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=tvsearch&q=Bad&season=10000&ep=2", request, error));
	CHECK_EQ(error, "season must be an unsigned decimal value in the range 0..9999");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=tvsearch&q=Bad&season=999999999999999999999&ep=2", request, error));
	CHECK_EQ(error, "season must be an unsigned decimal value in the range 0..9999");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=tvsearch&q=Bad&season=1&ep=10000", request, error));
	CHECK_EQ(error, "ep must be an unsigned decimal value in the range 0..9999");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=movie&q=Bad&year=10000", request, error));
	CHECK_EQ(error, "year must be an unsigned decimal value in the range 0..9999");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Bad&offset=1000001", request, error));
	CHECK_EQ(error, "offset must be an unsigned decimal value in the range 0..1000000");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=Bad&limit=101", request, error));
	CHECK_EQ(error, "limit must be an unsigned decimal value in the range 0..100");

	std::string longQuery(WebServerArrCompatSeams::kMaxTorznabQueryLength + 1, 'x');
	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=" + longQuery, request, error));
	CHECK_EQ(error, "q must be at most 160 characters");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=bad%C3%28", request, error));
	CHECK_EQ(error, "q must be valid UTF-8 without control characters");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&q=bad%2xescape", request, error));
	CHECK_EQ(error, "malformed percent escape");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search&t=movie&q=Dup", request, error));
	CHECK_EQ(error, "duplicate query parameter: t");

	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=search", request, error));
	const std::vector<std::string> rssQueries = WebServerArrCompatSeams::BuildNativeQueries(request);
	CHECK(rssQueries.empty());
}

TEST_CASE("Web API exposes deterministic Torznab eD2K links and safe XML text")
{
	CHECK_EQ(
		WebServerArrCompatSeams::BuildEd2kDownloadLink("0123456789ABCDEF0123456789ABCDEF", "A&B.mkv", 42),
		"ed2k://|file|A%26B.mkv|42|0123456789abcdef0123456789abcdef|/");
	CHECK(WebServerArrCompatSeams::BuildEd2kDownloadLink("0123456789abcdef0123456789abcdef", "", 42).empty());
	CHECK(WebServerArrCompatSeams::BuildEd2kDownloadLink("0123456789abcdef0123456789abcdef", "bad\x01name.mkv", 42).empty());
	CHECK(WebServerArrCompatSeams::BuildEd2kDownloadLink("0123456789abcdef0123456789abcdef", "A&B.mkv", 0).empty());
	CHECK_EQ(WebServerArrCompatSeams::XmlEscape("<tag attr=\"x\">A&B</tag>"), "&lt;tag attr=&quot;x&quot;&gt;A&amp;B&lt;/tag&gt;");
	CHECK_EQ(WebServerJsonSeams::UrlEncodeUtf8("A B+100%"), "A%20B%2B100%25");
	CHECK(WebServerArrCompatSeams::DoesResultMatchFamily(WebServerArrCompatSeams::ETorznabFamily::Movie, "release.mkv", 10));
	CHECK_FALSE(WebServerArrCompatSeams::DoesResultMatchFamily(WebServerArrCompatSeams::ETorznabFamily::Audio, "release.mkv", 10));
	CHECK(WebServerArrCompatSeams::DoesResultMatchFamily(WebServerArrCompatSeams::ETorznabFamily::Book, "manual.pdf", 10));
	CHECK_FALSE(WebServerArrCompatSeams::DoesResultMatchFamily(WebServerArrCompatSeams::ETorznabFamily::Movie, "manual.pdf", 10));
	CHECK_EQ(std::string(WebServerArrCompatSeams::GetRestSearchType(WebServerArrCompatSeams::ETorznabFamily::Movie)), "video");
	CHECK_EQ(std::string(WebServerArrCompatSeams::GetRestSearchType(WebServerArrCompatSeams::ETorznabFamily::Tv)), "video");
	CHECK_EQ(WebServerArrCompatSeams::BuildRestSearchTypeNames(WebServerArrCompatSeams::ETorznabFamily::Movie), std::vector<std::string>{"video"});
	CHECK_EQ(WebServerArrCompatSeams::BuildRestSearchTypeNames(WebServerArrCompatSeams::ETorznabFamily::Book), std::vector<std::string>{"doc"});
	const std::vector<std::pair<WebServerArrCompatSeams::ETorznabFamily, std::string>> familySearchTypes = {
		{WebServerArrCompatSeams::ETorznabFamily::Movie, "video"},
		{WebServerArrCompatSeams::ETorznabFamily::Tv, "video"},
		{WebServerArrCompatSeams::ETorznabFamily::Audio, "audio"},
		{WebServerArrCompatSeams::ETorznabFamily::Book, "doc"},
		{WebServerArrCompatSeams::ETorznabFamily::Other, ""},
		{WebServerArrCompatSeams::ETorznabFamily::Any, ""},
		{WebServerArrCompatSeams::ETorznabFamily::Unknown, ""}
	};
	for (const auto &rFamilySearchType : familySearchTypes) {
		const std::vector<std::string> searchTypes = WebServerArrCompatSeams::BuildRestSearchTypeNames(rFamilySearchType.first);
		CAPTURE(static_cast<int>(rFamilySearchType.first));
		REQUIRE_EQ(searchTypes.size(), 1u);
		CHECK_EQ(searchTypes[0], rFamilySearchType.second);
		CHECK(WebServerJsonSeams::IsSearchFileTypeName(searchTypes[0]));
	}
	CHECK_EQ(WebServerArrCompatSeams::BuildNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Movie), std::vector<std::string>{"global", "kad"});
	CHECK_EQ(WebServerArrCompatSeams::BuildNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Tv), std::vector<std::string>{"global", "kad"});
	CHECK_EQ(WebServerArrCompatSeams::BuildNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Book), std::vector<std::string>{"automatic"});
	CHECK_EQ(WebServerArrCompatSeams::BuildAvailableNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Movie, true, true), std::vector<std::string>{"global", "kad"});
	CHECK_EQ(WebServerArrCompatSeams::BuildAvailableNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Movie, true, false), std::vector<std::string>{"global"});
	CHECK_EQ(WebServerArrCompatSeams::BuildAvailableNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Movie, false, true), std::vector<std::string>{"kad"});
	CHECK(WebServerArrCompatSeams::BuildAvailableNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Movie, false, false).empty());
	CHECK_EQ(WebServerArrCompatSeams::BuildAvailableNativeSearchMethodNames(WebServerArrCompatSeams::ETorznabFamily::Book, false, false), std::vector<std::string>{"automatic"});
	CHECK(WebServerArrCompatSeams::IsConnectedNetworkSearchMethod("GLOBAL"));
	CHECK(WebServerArrCompatSeams::IsConnectedNetworkSearchMethod("kad"));
	CHECK_FALSE(WebServerArrCompatSeams::IsConnectedNetworkSearchMethod("automatic"));
	CHECK_EQ(WebServerArrCompatSeams::BuildNativeSearchMethodsCacheToken(std::vector<std::string>{"global", "kad"}), "global,kad");
	CHECK_EQ(WebServerArrCompatSeams::BuildNativeSearchMethodsCacheToken(std::vector<std::string>()), "none");
	WebServerArrCompatSeams::STorznabRequest cacheRequest;
	std::string cacheError;
	CHECK(WebServerArrCompatSeams::TryParseTorznabRequest("/indexer/emulebb/api?t=movie&q=Feature&cat=2000", cacheRequest, cacheError));
	CHECK(WebServerArrCompatSeams::BuildCacheKey(cacheRequest, std::vector<std::string>{"global"}) != WebServerArrCompatSeams::BuildCacheKey(cacheRequest, std::vector<std::string>{"kad"}));
	CHECK_EQ(WebServerArrCompatSeams::GetNativeSearchTimeoutMilliseconds(WebServerArrCompatSeams::ETorznabFamily::Movie), WebServerArrCompatSeams::kTorznabMediaSearchTimeoutMs);
	CHECK_EQ(WebServerArrCompatSeams::GetNativeSearchTimeoutMilliseconds(WebServerArrCompatSeams::ETorznabFamily::Book), WebServerArrCompatSeams::kTorznabDefaultSearchTimeoutMs);
	CHECK_EQ(WebServerArrCompatSeams::GetNativeSearchMethodProbeTimeoutMilliseconds(WebServerArrCompatSeams::ETorznabFamily::Movie, 2), WebServerArrCompatSeams::kTorznabMediaSearchTimeoutMs / 2);
	CHECK_EQ(WebServerArrCompatSeams::GetNativeSearchMethodProbeTimeoutMilliseconds(WebServerArrCompatSeams::ETorznabFamily::Book, 1), WebServerArrCompatSeams::kTorznabDefaultSearchTimeoutMs);
	CHECK_FALSE(WebServerArrCompatSeams::ShouldCacheTorznabResults(0));
	CHECK(WebServerArrCompatSeams::ShouldCacheTorznabResults(1));
	CHECK_EQ(WebServerArrCompatSeams::kTorznabBusyHttpStatus, 503);
}

TEST_CASE("Web API recognizes qBittorrent compatibility routes")
{
	std::string path;
	std::string error;

	CHECK(WebServerQBitCompatSeams::IsQBitRequestTarget("/api/v2/app/webapiVersion"));
	CHECK(WebServerQBitCompatSeams::IsQBitRequestTarget("/API/V2/torrents/add"));
	CHECK_FALSE(WebServerQBitCompatSeams::IsQBitRequestTarget("/api/v1/torrents/add"));
	CHECK_FALSE(WebServerQBitCompatSeams::IsQBitRequestTarget("/indexer/emulebb/api"));

	CHECK(WebServerQBitCompatSeams::TryGetQBitRequestPathLower("/API/V2/torrents/files?hash=bad", path, error));
	CHECK_EQ(path, "/api/v2/torrents/files");
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetQBitRequestPathLower("/api/v2/torrents/files%2x?hash=bad", path, error));
	CHECK_EQ(error, "malformed percent escape");
	CHECK(WebServerQBitCompatSeams::IsQBitRequestTarget("/api/v2/torrents/files%2x?hash=bad"));

	std::string category;
	error.clear();
	CHECK(WebServerQBitCompatSeams::TryGetOptionalCategoryQueryParam("/api/v2/torrents/info", category, error));
	CHECK(category.empty());
	CHECK(WebServerQBitCompatSeams::TryGetOptionalCategoryQueryParam("/api/v2/torrents/info?category=Movies", category, error));
	CHECK_EQ(category, "Movies");
	CHECK(WebServerQBitCompatSeams::TryGetOptionalCategoryQueryParam("/api/v2/torrents/info?category=++Movies++", category, error));
	CHECK_EQ(category, "Movies");
	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetOptionalCategoryQueryParam("/api/v2/torrents/info?category=%2x", category, error));
	CHECK_EQ(error, "malformed percent escape");
	CHECK(category.empty());
	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetOptionalCategoryQueryParam("/api/v2/torrents/info?category=Movies&category=TV", category, error));
	CHECK_EQ(error, "duplicate query parameter: category");
	CHECK(category.empty());
	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetOptionalCategoryQueryParam("/api/v2/torrents/info?category=bad%01name", category, error));
	CHECK_EQ(error, "category must be valid UTF-8 without control characters");
	CHECK(category.empty());

	std::string hash;
	error.clear();
	CHECK(WebServerQBitCompatSeams::TryGetRequiredHashQueryParam("/api/v2/torrents/properties?hash=0123456789ABCDEF0123456789ABCDEF", hash, error));
	CHECK_EQ(hash, "0123456789abcdef0123456789abcdef");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetRequiredHashQueryParam("/api/v2/torrents/properties", hash, error));
	CHECK_EQ(error, "hash query parameter is required");
	CHECK(hash.empty());

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetRequiredHashQueryParam("/api/v2/torrents/files?hash=bad", hash, error));
	CHECK_EQ(error, "hash must be a 32-character eD2K hash");
	CHECK(hash.empty());

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetRequiredHashQueryParam("/api/v2/torrents/files?hash=%2x", hash, error));
	CHECK_EQ(error, "malformed percent escape");
	CHECK(hash.empty());

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetRequiredHashQueryParam("/api/v2/torrents/files?hash=0123456789abcdef0123456789abcdef&hash=fedcba9876543210fedcba9876543210", hash, error));
	CHECK_EQ(error, "duplicate query parameter: hash");
	CHECK(hash.empty());
}

TEST_CASE("Web API keeps adapter error responses outside native JSON envelopes")
{
	const std::string torznabContentType(WebServerArrCompatSeams::kTorznabXmlContentTypeHeader);
	CHECK(torznabContentType.find("application/xml") != std::string::npos);
	CHECK(torznabContentType.find("application/json") == std::string::npos);
	CHECK_EQ(WebServerArrCompatSeams::kTorznabParseErrorHttpStatus, 400);

	const std::string qbitTextContentType(WebServerQBitCompatSeams::kQBitTextContentTypeHeader);
	CHECK(qbitTextContentType.find("text/plain") != std::string::npos);
	CHECK(qbitTextContentType.find("application/json") == std::string::npos);
	CHECK_EQ(std::string(WebServerQBitCompatSeams::kQBitFailureBody), "Fails.");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::kQBitNotFoundBody), "Not found");
	CHECK(std::string(WebServerQBitCompatSeams::kQBitFailureBody).find("{\"error\"") == std::string::npos);
}

TEST_CASE("Web API declares the qBittorrent compatibility endpoint contract")
{
	const std::vector<WebServerQBitCompatSeams::SQBitRouteSpec> &specs = WebServerQBitCompatSeams::GetQBitRouteSpecs();
	CHECK_EQ(specs.size(), 19u);

	size_t unauthenticatedCount = 0;
	for (size_t i = 0; i < specs.size(); ++i) {
		const bool bCanResolveSpec = WebServerQBitCompatSeams::FindQBitRouteSpec(specs[i].pszMethod, specs[i].pszPath) == &specs[i];
		CHECK(bCanResolveSpec);
		if (!specs[i].bRequiresAuth)
			++unauthenticatedCount;
		for (size_t j = i + 1; j < specs.size(); ++j) {
			const bool bDuplicateRoute = std::string(specs[i].pszMethod) == specs[j].pszMethod
				&& std::string(specs[i].pszPath) == specs[j].pszPath;
			CHECK_FALSE(bDuplicateRoute);
		}
	}
	CHECK_EQ(unauthenticatedCount, 2u);

	const bool bRejectsLowerGetPublicVersion = WebServerQBitCompatSeams::FindQBitRouteSpec("get", "/api/v2/app/webapiversion") == NULL;
	const bool bRejectsPostAppVersion = WebServerQBitCompatSeams::FindQBitRouteSpec("POST", "/api/v2/app/version") == NULL;
	const bool bRejectsGetAdd = WebServerQBitCompatSeams::FindQBitRouteSpec("GET", "/api/v2/torrents/add") == NULL;
	const bool bRejectsGetDelete = WebServerQBitCompatSeams::FindQBitRouteSpec("GET", "/api/v2/torrents/delete") == NULL;
	const bool bRejectsUnknown = WebServerQBitCompatSeams::FindQBitRouteSpec("GET", "/api/v2/unknown") == NULL;
	const bool bAcceptsPublicVersion = WebServerQBitCompatSeams::FindQBitRouteSpec("GET", "/api/v2/app/webapiversion") != NULL;
	const WebServerQBitCompatSeams::SQBitRouteSpec *const pPublicVersion = WebServerQBitCompatSeams::FindQBitRouteSpec("GET", "/api/v2/app/webapiversion");
	const WebServerQBitCompatSeams::SQBitRouteSpec *const pTorrentsInfo = WebServerQBitCompatSeams::FindQBitRouteSpec("GET", "/api/v2/torrents/info");
	const bool bRejectsPostPublicVersion = WebServerQBitCompatSeams::FindQBitRouteSpec("POST", "/api/v2/app/webapiversion") == NULL;
	CHECK(bRejectsLowerGetPublicVersion);
	CHECK(bRejectsPostAppVersion);
	CHECK(bRejectsGetAdd);
	CHECK(bRejectsGetDelete);
	CHECK(bRejectsUnknown);
	CHECK(bAcceptsPublicVersion);
	REQUIRE(pPublicVersion != NULL);
	CHECK_FALSE(pPublicVersion->bRequiresAuth);
	REQUIRE(pTorrentsInfo != NULL);
	CHECK(pTorrentsInfo->bRequiresAuth);
	CHECK(bRejectsPostPublicVersion);
}

TEST_CASE("Web API validates qBittorrent session cookies by exact pair")
{
	CHECK(WebServerQBitCompatSeams::HasCookiePair("SID=abc123", "SID", "abc123"));
	CHECK(WebServerQBitCompatSeams::HasCookiePair("theme=dark; SID=abc123; other=1", "SID", "abc123"));
	CHECK(WebServerQBitCompatSeams::HasCookiePair("theme=dark;SID=abc123", "SID", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("XSID=abc123", "SID", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("theme=dark; XSID=abc123", "SID", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=abc1234", "SID", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=", "SID", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=abc123", "", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=", "SID", ""));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=abc123", "SID", ""));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=abc123; SID=abc123", "SID", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=wrong; SID=abc123", "SID", "abc123"));
	CHECK_FALSE(WebServerQBitCompatSeams::HasCookiePair("SID=abc123; SID=wrong", "SID", "abc123"));
}

TEST_CASE("Web API preserves native transfer meaning in qBittorrent states")
{
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("completed", false)), "pausedUP");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("checking", false)), "checkingDL");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("completing", false)), "checkingDL");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("error", false)), "error");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("missingfiles", false)), "missingFiles");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("paused", false)), "pausedDL");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("queued", false)), "queuedDL");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("downloading", false)), "downloading");
	CHECK_EQ(std::string(WebServerQBitCompatSeams::GetQBitStateForNativeTransferState("downloading", true)), "pausedDL");
}

TEST_CASE("Web API validates qBittorrent login form credentials exactly")
{
	std::map<std::string, std::string> form;
	std::string error;
	CHECK(WebServerQBitCompatSeams::IsFormContentType("application/x-www-form-urlencoded"));
	CHECK(WebServerQBitCompatSeams::IsFormContentType(" Application/X-WWW-Form-Urlencoded ; charset=UTF-8 "));
	CHECK_FALSE(WebServerQBitCompatSeams::IsFormContentType("application/json"));
	CHECK(WebServerQBitCompatSeams::TryValidateFormRequestMetadata("", "", error));
	CHECK(WebServerQBitCompatSeams::TryValidateFormRequestMetadata("username=emule", "application/x-www-form-urlencoded", error));
	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryValidateFormRequestMetadata("{}", "application/json", error));
	CHECK_EQ(error, "Content-Type must be application/x-www-form-urlencoded for form request bodies");

	REQUIRE(WebServerQBitCompatSeams::TryParseFormBody("username=emule&password=secret", form, error));
	CHECK(WebServerQBitCompatSeams::IsValidLoginForm(form, "emule", "secret"));

	CHECK_FALSE(WebServerQBitCompatSeams::IsValidLoginForm(form, "not-emule", "secret"));
	CHECK_FALSE(WebServerQBitCompatSeams::IsValidLoginForm(form, "emule", "secret-wrong"));

	REQUIRE(WebServerQBitCompatSeams::TryParseFormBody("password=secret", form, error));
	CHECK_FALSE(WebServerQBitCompatSeams::IsValidLoginForm(form, "emule", "secret"));

	REQUIRE(WebServerQBitCompatSeams::TryParseFormBody("username=emule", form, error));
	CHECK_FALSE(WebServerQBitCompatSeams::IsValidLoginForm(form, "emule", "secret"));
}

TEST_CASE("Web API shares URL encoding across native and Arr compatibility seams")
{
	const std::string encoded(WebServerJsonSeams::UrlEncodeUtf8("operator-movie-title + [test].mkv"));
	CHECK_EQ(encoded, "operator-movie-title%20%2B%20%5Btest%5D.mkv");
	CHECK_EQ(WebServerJsonSeams::UrlDecodeUtf8(encoded), "operator-movie-title + [test].mkv");
	std::string decoded;
	std::string error;
	CHECK(WebServerJsonSeams::TryUrlDecodeUtf8(encoded, decoded, error));
	CHECK_EQ(decoded, "operator-movie-title + [test].mkv");
	CHECK(WebServerJsonSeams::TryUrlDecodeUtf8("operator+movie", decoded, error));
	CHECK_EQ(decoded, "operator movie");
	CHECK(WebServerJsonSeams::TryUrlDecodePathSegmentUtf8("operator+movie", decoded, error));
	CHECK_EQ(decoded, "operator+movie");
	CHECK_FALSE(WebServerJsonSeams::TryUrlDecodeUtf8("bad%2xescape", decoded, error));
	CHECK_EQ(error, "malformed percent escape");

	const std::string link(WebServerArrCompatSeams::BuildEd2kDownloadLink(
		"0123456789abcdef0123456789abcdef",
		"operator-movie-title + [test].mkv",
		42));
	CHECK(link.find("|" + encoded + "|42|") != std::string::npos);
}

TEST_CASE("Web API shares strict percent decoding across native and Arr adapters")
{
	std::map<std::string, std::string> fields;
	std::string error;
	CHECK_FALSE(WebServerJsonSeams::TryParseQueryString("/api/v1/logs?limit=%2x", fields, error));
	CHECK_EQ(error, "malformed percent escape");
	CHECK(fields.empty());

	error.clear();
	CHECK(WebServerJsonSeams::TryParseQueryString("/api/v1/transfers?q=downloading+stalled", fields, error));
	REQUIRE(fields.find("q") != fields.end());
	CHECK_EQ(fields["q"], "downloading stalled");

	error.clear();
	CHECK_FALSE(WebServerArrCompatSeams::TryParseTorznabQueryParameters("/indexer/emulebb/api?t=search&q=%2x", fields, error));
	CHECK_EQ(error, "malformed percent escape");
	CHECK(fields.empty());

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseFormBody("urls=%2x", fields, error));
	CHECK_EQ(error, "malformed percent escape");
	CHECK(fields.empty());

	error.clear();
	std::string addUrl;
	CHECK_FALSE(WebServerQBitCompatSeams::TryValidateAddRequestUrl("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef00000000&dn=%2x&xl=42", addUrl, error));
	CHECK_EQ(error, "magnet URLs are not supported");
	CHECK(addUrl.empty());
}

TEST_CASE("Web API accepts qBittorrent add forms only for native eD2K links")
{
	std::map<std::string, std::string> form;
	std::string error;
	CHECK(WebServerQBitCompatSeams::TryParseFormBody("category=RADARR_ENG&stopped=true&urls=ed2k%3A%2F%2F%7Cfile%7CLa%2520Dolce%2520Vita.mkv%7C42%7C0123456789abcdef0123456789abcdef%7C%2F", form, error));
	CHECK_EQ(form["category"], "RADARR_ENG");
	CHECK_EQ(form["urls"], "ed2k://|file|La%20Dolce%20Vita.mkv|42|0123456789abcdef0123456789abcdef|/");

	WebServerQBitCompatSeams::SQBitTorrentAddRequest request;
	CHECK(WebServerQBitCompatSeams::TryParseTorrentAddRequest("category=RADARR_ENG&stopped=true&urls=ed2k%3A%2F%2F%7Cfile%7CLa%2520Dolce%2520Vita.mkv%7C42%7C0123456789abcdef0123456789abcdef%7C%2F", request, error));
	CHECK_EQ(request.strCategory, "RADARR_ENG");
	CHECK(request.bPaused);
	CHECK_EQ(request.strUrl, "ed2k://|file|La%20Dolce%20Vita.mkv|42|0123456789abcdef0123456789abcdef|/");

	error.clear();
	CHECK(WebServerQBitCompatSeams::TryParseTorrentAddRequest("category=++RADARR_ENG++&urls=ed2k%3A%2F%2F%7Cfile%7Cx%7C42%7C0123456789abcdef0123456789abcdef%7C%2F", request, error));
	CHECK_EQ(request.strCategory, "RADARR_ENG");

	error.clear();
	CHECK(WebServerQBitCompatSeams::TryParseTorrentAddRequest("paused=false&urls=ed2k%3A%2F%2F%7Cfile%7Cx%7C42%7C0123456789abcdef0123456789abcdef%7C%2F", request, error));
	CHECK_FALSE(request.bPaused);
}

TEST_CASE("Web API rejects unsafe qBittorrent add forms before native dispatch")
{
	WebServerQBitCompatSeams::SQBitTorrentAddRequest request;
	std::map<std::string, std::string> form;
	std::string error;
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseTorrentAddRequest("urls=http%3A%2F%2Fexample.invalid%2Ffile.torrent", request, error));
	CHECK_EQ(error, "only eD2K URLs are supported");

	CHECK_FALSE(WebServerQBitCompatSeams::TryParseTorrentAddRequest("urls=magnet%3A%3Fxt%3Durn%3Abtih%3A0123456789abcdef0123456789abcdef00000000%26dn%3Dx%26xl%3D42", request, error));
	CHECK_EQ(error, "magnet URLs are not supported");

	CHECK_FALSE(WebServerQBitCompatSeams::TryParseFormBody("category=a&category=b", form, error));
	CHECK_EQ(error, "duplicate form field: category");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseFormBody("category=bad%2xescape", form, error));
	CHECK_EQ(error, "malformed percent escape");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseFormBody("=bad", form, error));
	CHECK_EQ(error, "form field name must not be empty");

	CHECK(WebServerQBitCompatSeams::TryParseFormBody("category=", form, error));
	std::string category;
	CHECK_FALSE(WebServerQBitCompatSeams::TryGetRequiredNonEmptyFormField(form, "category", category, error));
	CHECK_EQ(error, "category form field is required");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseTorrentAddRequest("category=bad%01name&urls=ed2k%3A%2F%2F%7Cfile%7Cx%7C42%7C0123456789abcdef0123456789abcdef%7C%2F", request, error));
	CHECK_EQ(error, "category must be valid UTF-8 without control characters");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseTorrentAddRequest("paused=maybe&urls=ed2k%3A%2F%2F%7Cfile%7Cx%7C42%7C0123456789abcdef0123456789abcdef%7C%2F", request, error));
	CHECK_EQ(error, "paused must be a boolean form value");
}

TEST_CASE("Web API parses qBittorrent category creation through native category policy")
{
	std::string category;
	std::string error;

	CHECK(WebServerQBitCompatSeams::TryParseCreateCategoryRequest("category=++RADARR_ENG++", category, error));
	CHECK_EQ(category, "RADARR_ENG");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseCreateCategoryRequest("category=", category, error));
	CHECK_EQ(error, "category must not be empty");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseCreateCategoryRequest("category=bad%01name", category, error));
	CHECK_EQ(error, "category must be valid UTF-8 without control characters");
}

TEST_CASE("Web API parses qBittorrent hash mutations safely")
{
	WebServerQBitCompatSeams::SQBitHashMutationRequest request;
	std::string error;

	CHECK(WebServerQBitCompatSeams::TryParseDeleteRequest("hashes=0123456789ABCDEF0123456789ABCDEF%7Cfedcba9876543210fedcba9876543210&deleteFiles=true", request, error));
	REQUIRE_EQ(request.hashes.size(), 2u);
	CHECK_EQ(request.hashes[0], "0123456789abcdef0123456789abcdef");
	CHECK_EQ(request.hashes[1], "fedcba9876543210fedcba9876543210");
	CHECK(request.bDeleteFiles);

	CHECK(WebServerQBitCompatSeams::TryParseDeleteRequest("hashes=0123456789abcdef0123456789abcdef&deleteFiles=false", request, error));
	CHECK(request.bDeleteFiles);

	error.clear();
	CHECK(WebServerQBitCompatSeams::TryParseDeleteRequest("hashes=0123456789abcdef0123456789abcdef&deleteFiles=0", request, error));
	CHECK(request.bDeleteFiles);

	CHECK(WebServerQBitCompatSeams::TryParseSetCategoryRequest("hashes=0123456789abcdef0123456789abcdef&category=SONARR_ENG", request, error));
	CHECK_EQ(request.strCategory, "SONARR_ENG");

	CHECK(WebServerQBitCompatSeams::TryParseSetCategoryRequest("hashes=0123456789abcdef0123456789abcdef&category=++SONARR_ENG++", request, error));
	CHECK_EQ(request.strCategory, "SONARR_ENG");

	CHECK(WebServerQBitCompatSeams::TryParseHashesOnlyRequest("hashes=0123456789abcdef0123456789abcdef", request, error));
	CHECK_EQ(request.hashes[0], "0123456789abcdef0123456789abcdef");

	CHECK(WebServerQBitCompatSeams::TryParseForceStartRequest("hashes=0123456789abcdef0123456789abcdef&value=false", request, error));
	CHECK_EQ(request.hashes[0], "0123456789abcdef0123456789abcdef");

	CHECK_FALSE(WebServerQBitCompatSeams::TryParseDeleteRequest("hashes=all&deleteFiles=true", request, error));
	CHECK_EQ(error, "hashes=all is not supported");

	CHECK_FALSE(WebServerQBitCompatSeams::TryParseDeleteRequest("hashes=bad", request, error));
	CHECK_EQ(error, "hashes must contain only 32-character eD2K hashes");

	CHECK_FALSE(WebServerQBitCompatSeams::TryParseDeleteRequest("hashes=0123456789abcdef0123456789abcdef%7C0123456789ABCDEF0123456789ABCDEF", request, error));
	CHECK_EQ(error, "hashes must not contain duplicates");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseDeleteRequest("hashes=0123456789abcdef0123456789abcdef&deleteFiles=wat", request, error));
	CHECK_EQ(error, "deleteFiles must be a boolean form value");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseForceStartRequest("hashes=0123456789abcdef0123456789abcdef&value=wat", request, error));
	CHECK_EQ(error, "value must be a boolean form value");

	std::string manyHashes("hashes=");
	const char hexDigits[] = "0123456789abcdef";
	for (size_t i = 0; i <= WebServerQBitCompatSeams::kMaxHashMutationCount; ++i) {
		if (i > 0)
			manyHashes += "|";
		std::string hash("00000000000000000000000000000000");
		hash[30] = hexDigits[(i + 1) / 16];
		hash[31] = hexDigits[(i + 1) % 16];
		manyHashes += hash;
	}
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseDeleteRequest(manyHashes, request, error));
	CHECK_EQ(error, "hashes form field exceeds the supported item limit");

	CHECK_FALSE(WebServerQBitCompatSeams::TryParseSetCategoryRequest("hashes=0123456789abcdef0123456789abcdef", request, error));
	CHECK_EQ(error, "category form field is required");

	error.clear();
	CHECK_FALSE(WebServerQBitCompatSeams::TryParseSetCategoryRequest("hashes=0123456789abcdef0123456789abcdef&category=", request, error));
	CHECK_EQ(error, "category must not be empty");
}

TEST_CASE("Web API keeps native hashes strict while qBittorrent adapters normalize compatible hashes")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "hash must be a 32-character lowercase hex string");

	WebServerQBitCompatSeams::SQBitHashMutationRequest mutation;
	std::string error;
	CHECK(WebServerQBitCompatSeams::TryParseHashesOnlyRequest("hashes=0123456789ABCDEF0123456789ABCDEF", mutation, error));
	REQUIRE_EQ(mutation.hashes.size(), 1u);
	CHECK_EQ(mutation.hashes[0], "0123456789abcdef0123456789abcdef");
}

TEST_CASE("Web API builds representative REST routes and normalizes query parameters")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/app", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "app/version");
	CHECK(route.params.is_object());

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers?state=downloading&categoryId=3", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "transfers/list");
	CHECK_EQ(route.params["state"].get<std::string>(), "downloading");
	CHECK_EQ(route.params["categoryId"].get<uint64_t>(), 3u);
	CHECK(route.params["_items_envelope"].get<bool>());
	CHECK_FALSE(route.params.contains("_paged_items_envelope"));
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers?state=Downloading", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "state must be one of downloading, paused, queued, checking, completing, completed, error, missingfiles");

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/shared-files?offset=2&limit=25", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "shared/list");
	CHECK_EQ(route.params["_offset"].get<int>(), 2);
	CHECK_EQ(route.params["_limit"].get<int>(), 25);
	CHECK(route.params["_items_envelope"].get<bool>());
	CHECK(route.params["_paged_items_envelope"].get<bool>());

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/upload-queue?offset=3&limit=50", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "uploads/queue");
	CHECK_EQ(route.params["_offset"].get<int>(), 3);
	CHECK_EQ(route.params["_limit"].get<int>(), 50);
	CHECK(route.params["_items_envelope"].get<bool>());
	CHECK(route.params["_paged_items_envelope"].get<bool>());

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?limit=999999999999", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "limit is out of range");

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/categories", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "categories/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	CHECK_FALSE(route.params.contains("_paged_items_envelope"));

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/shared-directories", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "shared_directories/get");
}

TEST_CASE("Web API carries path identifiers and JSON bodies into mutation routes")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/transfers/0123456789abcdef0123456789abcdef",
		R"({"priority":"high"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "transfers/set_priority");
	CHECK_EQ(route.params["hash"].get<std::string>(), "0123456789abcdef0123456789abcdef");
	CHECK_EQ(route.params["priority"].get<std::string>(), "high");

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/transfers/0123456789abcdef0123456789abcdef",
		R"({"categoryName":"Default"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "transfers/set_category");
	CHECK_EQ(route.params["hash"].get<std::string>(), "0123456789abcdef0123456789abcdef");
	CHECK_EQ(route.params["categoryName"].get<std::string>(), "Default");

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"GET",
		"/api/v1/searches/123",
		"",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "search/results");
	CHECK_EQ(route.params["searchId"].get<std::string>(), "123");

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/transfers/0123456789abcdef0123456789abcdef",
		R"({"name":"renamed.bin"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "transfers/rename");
	CHECK_EQ(route.params["hash"].get<std::string>(), "0123456789abcdef0123456789abcdef");
	CHECK_EQ(route.params["name"].get<std::string>(), "renamed.bin");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/transfers/0123456789abcdef0123456789abcdef",
		R"({"priority":"high","name":"renamed.bin"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "transfer PATCH accepts only one mutation family");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/transfers/0123456789abcdef0123456789abcdef",
		R"({"priority":7})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be a string");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/transfers/0123456789abcdef0123456789abcdef",
		R"({"priority":"release"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be one of auto, verylow, low, normal, high, veryhigh");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/transfers/0123456789abcdef0123456789abcdef",
		R"({"name":"   "})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "name must not be empty");

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-files/0123456789abcdef0123456789abcdef",
		R"({"comment":"good release","rating":4})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "shared/set_rating_comment");
	CHECK_EQ(route.params["hash"].get<std::string>(), "0123456789abcdef0123456789abcdef");
	CHECK_EQ(route.params["comment"].get<std::string>(), "good release");
	CHECK_EQ(route.params["rating"].get<int>(), 4);

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-files/0123456789abcdef0123456789abcdef",
		R"({})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "shared-file PATCH requires priority, comment, or rating");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-files/0123456789abcdef0123456789abcdef",
		R"({"priority":7})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be a string");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-files/0123456789abcdef0123456789abcdef",
		R"({"priority":"very_high"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be one of auto, verylow, low, normal, high, release");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-files/0123456789abcdef0123456789abcdef",
		R"({"priority":"veryhigh"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be one of auto, verylow, low, normal, high, release");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-files/0123456789abcdef0123456789abcdef",
		R"({"comment":"good release"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "rating must be an integer between 0 and 5");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"POST",
		"/api/v1/shared-files",
		R"({"path":"   "})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "path must not be empty");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute(
		"POST",
		"/api/v1/shared-files",
		R"({"path":" C:\\share\\file.txt "})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "shared/add");
	CHECK_EQ(route.params["path"].get<std::string>(), "C:\\share\\file.txt");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-directories",
		R"({"confirmReplaceRoots":true,"roots":[{"path":"C:\\share","recursive":"yes"}]})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "recursive must be a boolean");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/shared-directories",
		R"({"confirmReplaceRoots":true,"roots":[{"path":"C:\\share","mode":"fast"}]})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown shared-directory root field: mode");
}

TEST_CASE("Web API exposes a strict route schema registry")
{
	const std::vector<WebServerJsonSeams::SApiRouteSpec> &specs = WebServerJsonSeams::GetApiRouteSpecs();
	CHECK(specs.size() > 50);
	CHECK(static_cast<bool>(WebServerJsonSeams::FindRouteSpec("GET", "/transfers") != NULL));
	CHECK(static_cast<bool>(WebServerJsonSeams::FindRouteSpec("PATCH", "/transfers/0123456789abcdef0123456789abcdef") != NULL));
	CHECK(static_cast<bool>(WebServerJsonSeams::FindRouteSpec("POST", "/transfers/0123456789abcdef0123456789abcdef/sources/fedcba9876543210fedcba9876543210/operations/ban") != NULL));
	CHECK(static_cast<bool>(WebServerJsonSeams::FindRouteSpecForAnyMethod("/app") != NULL));
	CHECK(static_cast<bool>(WebServerJsonSeams::FindRouteSpec("GET", "/app/version") == NULL));
	CHECK(static_cast<bool>(WebServerJsonSeams::FindRouteSpecForAnyMethod("/app/version") == NULL));
	CHECK(static_cast<bool>(WebServerJsonSeams::FindRouteSpec("PUT", "/app") == NULL));
}

TEST_CASE("Web API rejects unknown body fields and malformed query parameters before dispatch")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"priority":"high","legacy":true})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown JSON field: legacy");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers?categoryId=abc", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryId must be an unsigned number");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers?categoryId=+1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryId must be an unsigned number");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers?categoryId=4294967296", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryId is out of range");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers?limit=10", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: limit");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/uploads?offset=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: offset");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/servers?limit=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: limit");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/friends?offset=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: offset");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/categories?limit=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: limit");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources?limit=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: limit");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/shared-files/0123456789abcdef0123456789abcdef/comments?limit=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: limit");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?offset=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: offset");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?limit=0", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "limit is out of range");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?limit=10&limit=20", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "duplicate query parameter: limit");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?limit=10&legacy=1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown query parameter: legacy");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?limit=%2x", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "malformed percent escape");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs%2x?limit=10", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "malformed percent escape");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","categoryId":0,"categoryName":"Default"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryId and categoryName are mutually exclusive");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","categoryName":"  Default  "})", route, errorCode, errorMessage));
	CHECK_EQ(route.params["categoryName"].get<std::string>(), "Default");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","categoryName":7})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryName must be a string");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", "{\"link\":\"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/\",\"categoryName\":\"bad\\u0001name\"}", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryName must be valid UTF-8 without control characters");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","categoryId":-1})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryId must be an unsigned number");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches/123/results/0123456789abcdef0123456789abcdef/operations/download", R"({"categoryId":4294967296})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryId is out of range");
}

TEST_CASE("Web API requires JSON content type for native request bodies")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/app/preferences",
		R"({"safeServerConnect":true})",
		route,
		errorCode,
		errorMessage,
		"application/json; charset=utf-8"));
	CHECK_EQ(route.strCommand, "app/preferences/set");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/app/preferences",
		R"({"safeServerConnect":true})",
		route,
		errorCode,
		errorMessage,
		"text/plain"));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "Content-Type must be application/json for JSON request bodies");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/app", "", route, errorCode, errorMessage, ""));
	CHECK_EQ(route.strCommand, "app/version");
}

TEST_CASE("Web API requires explicit confirmation for broad native operations")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/app/shutdown", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "confirmShutdown must be true");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/app/shutdown", R"({"confirmShutdown":true})", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "app/shutdown");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/searches", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "confirm must be true");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/searches?confirm=true", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "search/clear");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/shared-directories", R"({"roots":[]})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "confirmReplaceRoots must be true");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/shared-directories", R"({"confirmReplaceRoots":true,"roots":[]})", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "shared_directories/set");
	CHECK(route.params["confirmReplaceRoots"].get<bool>());

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/shared-directories", R"({"confirmReplaceRoots":true,"roots":["  incoming  ",{"path":" recursive incoming ","recursive":true}]})", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "shared_directories/set");
	REQUIRE(route.params["roots"].is_array());
	REQUIRE_EQ(route.params["roots"].size(), 2u);
	CHECK_EQ(route.params["roots"][0].get<std::string>(), "incoming");
	CHECK_EQ(route.params["roots"][1]["path"].get<std::string>(), "recursive incoming");
	CHECK(route.params["roots"][1]["recursive"].get<bool>());

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/shared-directories", R"({"confirmReplaceRoots":true,"roots":["   "]})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "path must not be empty");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/shared-directories", R"({"confirmReplaceRoots":true,"roots":[{"path":"incoming","exists":true}]})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown shared-directory root field: exists");
}

TEST_CASE("Web API requires explicit confirmation for destructive native routes")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "DELETE request bodies are not supported");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "transfers/delete");
	CHECK_FALSE(route.params["deleteFiles"].get<bool>());

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef/files", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "confirm must be true");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef/files?confirm=false", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "confirm must be true");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef/files?confirm=true", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "transfers/delete");
	CHECK(route.params["deleteFiles"].get<bool>());

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers/operations/clear-completed", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "confirmClearCompleted must be true");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers/operations/clear-completed", R"({"confirmClearCompleted":false})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "confirmClearCompleted must be true");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/transfers/operations/clear-completed", R"({"confirmClearCompleted":true})", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "transfers/clear_completed");
	CHECK(route.params["confirmClearCompleted"].get<bool>());
}

TEST_CASE("Web API rejects malformed path identifiers before dispatch")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/servers/node+alpha.example:4661", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "servers/get");
	CHECK_EQ(route.params["addr"].get<std::string>(), "node+alpha.example");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);

	errorCode.clear();
	errorMessage.clear();

	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "hash must be a 32-character lowercase hex string");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/categories/+1", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "categoryId must be an unsigned decimal string");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/searches/4294967296", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "searchId is out of range");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/servers/192.0.2.1:0", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "serverId must use address:port with a port in the range 1..65535");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/servers/192.0.2.1:65536", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "serverId must use address:port with a port in the range 1..65535");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/servers/192.0.2.1:999999999999999999999", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "serverId must use address:port with a port in the range 1..65535");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/uploads/not-a-client/operations/remove", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "clientId must be a 32-character lowercase hex string or address:port");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/uploads/192.0.2.1:0/operations/remove", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "clientId must be a 32-character lowercase hex string or address:port");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/upload-queue/192.0.2.1:65536/operations/remove", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "clientId must be a 32-character lowercase hex string or address:port");
}

TEST_CASE("Web API maps every current REST route family to a command")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;
	const char *const pszHash = "0123456789abcdef0123456789abcdef";

	auto assertRoute = [&](const char *pszMethod, const char *pszTarget, const char *pszBody, const char *pszCommand)
	{
		errorCode.clear();
		errorMessage.clear();
		CHECK(WebServerJsonSeams::TryBuildRoute(pszMethod, pszTarget, pszBody, route, errorCode, errorMessage));
		CHECK_EQ(route.strCommand, pszCommand);
		const WebServerJsonSeams::ERestLifecyclePolicy policy = WebServerJsonSeams::GetLifecyclePolicyForCommand(route.strCommand);
		if (route.strMethod == "GET")
			CHECK(policy == WebServerJsonSeams::ERestLifecyclePolicy::Read);
		else if (route.strCommand == "app/shutdown")
			CHECK(policy == WebServerJsonSeams::ERestLifecyclePolicy::Shutdown);
		else if (route.strCommand == "app/capture_dump" || route.strCommand == "app/crash_test")
			CHECK(policy == WebServerJsonSeams::ERestLifecyclePolicy::DiagnosticUnsafe);
		else
			CHECK(policy == WebServerJsonSeams::ERestLifecyclePolicy::Mutation);
	};

	assertRoute("GET", "/api/v1/app", "", "app/version");
	assertRoute("GET", "/api/v1/app/preferences", "", "app/preferences/get");
	assertRoute("PATCH", "/api/v1/app/preferences", R"({"safeServerConnect":true,"autoBroadbandIo":false})", "app/preferences/set");
	CHECK(route.params.contains("prefs"));
	CHECK(route.params["prefs"].contains("safeServerConnect"));
	CHECK(route.params["prefs"].contains("autoBroadbandIo"));
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/app/preferences", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "preferences PATCH requires at least one preference");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/app/preferences", R"({"maxUploadSlots":0})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "maxUploadSlots must be an unsigned number in the range 1..32");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/app/preferences", R"({"safeServerConnect":"true"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "safeServerConnect must be a boolean");
	assertRoute("POST", "/api/v1/app/shutdown", R"({"confirmShutdown":true})", "app/shutdown");
	assertRoute("GET", "/api/v1/status", "", "status/get");
	assertRoute("GET", "/api/v1/stats", "", "stats/global");
	assertRoute("GET", "/api/v1/snapshot?limit=7", "", "snapshot/get");
	CHECK_EQ(route.params["limit"].get<int>(), 7);
	assertRoute("GET", "/api/v1/categories", "", "categories/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/categories", R"({"name":"Linux","path":"C:\\incoming\\linux","priority":"high","color":255})", "categories/create");
	CHECK_EQ(route.params["name"].get<std::string>(), "Linux");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/categories", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "name must be a non-empty string");
	assertRoute("GET", "/api/v1/categories/2", "", "categories/get");
	CHECK_EQ(route.params["id"].get<std::string>(), "2");
	assertRoute("PATCH", "/api/v1/categories/2", R"({"name":"ISOs","priority":"normal"})", "categories/update");
	CHECK_EQ(route.params["id"].get<std::string>(), "2");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/categories/2", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "category PATCH requires at least one field");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/categories/2", R"({"color":16777216})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "color must be null or an RGB integer");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/categories/2", R"({"priority":"auto"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be one of verylow, low, normal, high, veryhigh");
	assertRoute("DELETE", "/api/v1/categories/2", "", "categories/delete");
	CHECK_EQ(route.params["id"].get<std::string>(), "2");

	assertRoute("GET", "/api/v1/transfers?state=paused&categoryId=2", "", "transfers/list");
	CHECK_EQ(route.params["state"].get<std::string>(), "paused");
	CHECK_EQ(route.params["categoryId"].get<uint64_t>(), 2u);
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/","paused":true})", "transfers/add");
	CHECK(route.params["paused"].get<bool>());
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/pause", R"({})", "transfers/pause");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/resume", R"({})", "transfers/resume");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/stop", R"({})", "transfers/stop");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef", "", "transfers/delete");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	CHECK_FALSE(route.params["deleteFiles"].get<bool>());
	assertRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef/files?confirm=true", "", "transfers/delete");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	CHECK(route.params["deleteFiles"].get<bool>());
	assertRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef", "", "transfers/get");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/operations/clear-completed", R"({"confirmClearCompleted":true})", "transfers/clear_completed");
	CHECK(route.params["confirmClearCompleted"].get<bool>());
	assertRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef/details", "", "transfers/details");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources", "", "transfers/sources");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources/fedcba9876543210fedcba9876543210", "", "transfers/source");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["userHash"].get<std::string>(), "fedcba9876543210fedcba9876543210");
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources/fedcba9876543210fedcba9876543210/operations/browse", R"({})", "transfers/source_browse");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["userHash"].get<std::string>(), "fedcba9876543210fedcba9876543210");
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources/fedcba9876543210fedcba9876543210/operations/remove", R"({})", "peers/remove");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["userHash"].get<std::string>(), "fedcba9876543210fedcba9876543210");
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/recheck", R"({})", "transfers/recheck");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/preview", R"({})", "transfers/preview");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"priority":"high"})", "transfers/set_priority");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"categoryId":0})", "transfers/set_category");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"categoryName":"Default"})", "transfers/set_category");
	CHECK_EQ(route.params["categoryName"].get<std::string>(), "Default");
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"name":"renamed.bin"})", "transfers/rename");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["name"].get<std::string>(), "renamed.bin");

	assertRoute("GET", "/api/v1/uploads", "", "uploads/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("GET", "/api/v1/upload-queue", "", "uploads/queue");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("GET", "/api/v1/uploads/0123456789abcdef0123456789abcdef", "", "uploads/get");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("GET", "/api/v1/upload-queue/0123456789abcdef0123456789abcdef", "", "uploads/queue_get");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("DELETE", "/api/v1/uploads/0123456789abcdef0123456789abcdef", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "METHOD_NOT_ALLOWED");
	assertRoute("POST", "/api/v1/uploads/0123456789abcdef0123456789abcdef/operations/release-slot", R"({})", "uploads/release_slot");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/uploads/0123456789abcdef0123456789abcdef/operations/remove", R"({})", "uploads/remove");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/uploads/0123456789abcdef0123456789abcdef/operations/ban", R"({})", "peers/ban");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/upload-queue/0123456789abcdef0123456789abcdef/operations/unban", R"({})", "peers/unban");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/uploads/192.0.2.10:4662/operations/remove", R"({})", "uploads/remove");
	CHECK_EQ(route.params["ip"].get<std::string>(), "192.0.2.10");
	CHECK_EQ(route.params["port"].get<uint64_t>(), 4662u);
	assertRoute("POST", "/api/v1/upload-queue/192.0.2.11:4663/operations/release-slot", R"({})", "uploads/release_slot");
	CHECK_EQ(route.params["ip"].get<std::string>(), "192.0.2.11");
	CHECK_EQ(route.params["port"].get<uint64_t>(), 4663u);

	assertRoute("GET", "/api/v1/servers", "", "servers/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/servers", R"({"address":"1.2.3.4","port":4661,"name":"test"})", "servers/add");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers", R"({"address":"1.2.3.4","port":0})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "port must be in the range 1..65535");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers", R"({"address":"   ","port":4661})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "address must not be empty");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers", R"({"address":"1.2.3.4","port":4661,"connect":"yes"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "connect must be a boolean");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers", R"({"address":"1.2.3.4","port":4661,"priority":"veryhigh"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be one of low, normal, high");
	assertRoute("POST", "/api/v1/servers/operations/import-met-url", R"({"url":"https://example.invalid/server.met"})", "servers/import_met_url");
	CHECK_EQ(route.params["url"].get<std::string>(), "https://example.invalid/server.met");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers/operations/import-met-url", R"({"url":"   "})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "url must not be empty");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers/operations/import-met-url", R"({"url":"ftp://example.invalid/server.met"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "url must start with http:// or https://");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers/operations/import-met-url", R"({"url":"https:///server.met"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "url must include a host");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/servers/operations/import-met-url", R"({"url":"https://example.invalid/server met"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "url must not contain whitespace");
	assertRoute("POST", "/api/v1/servers/operations/connect", R"({})", "servers/connect");
	assertRoute("POST", "/api/v1/servers/operations/disconnect", R"({})", "servers/disconnect");
	assertRoute("PATCH", "/api/v1/servers/1.2.3.4:4661", R"({"name":"Pinned","priority":"high","static":true})", "servers/update");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);
	CHECK_EQ(route.params["name"].get<std::string>(), "Pinned");
	CHECK_EQ(route.params["priority"].get<std::string>(), "high");
	CHECK(route.params["static"].get<bool>());
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/servers/1.2.3.4:4661", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "server PATCH requires name, priority, or static");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/servers/1.2.3.4:4661", R"({"static":"yes"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "static must be a boolean");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PATCH", "/api/v1/servers/1.2.3.4:4661", R"({"priority":"veryhigh"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "priority must be one of low, normal, high");
	assertRoute("POST", "/api/v1/servers/1.2.3.4:4661/operations/connect", R"({})", "servers/connect");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);
	assertRoute("GET", "/api/v1/servers/1.2.3.4:4661", "", "servers/get");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);
	assertRoute("DELETE", "/api/v1/servers/1.2.3.4:4661", "", "servers/remove");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);

	assertRoute("GET", "/api/v1/kad", "", "kad/status");
	assertRoute("POST", "/api/v1/kad/operations/import-nodes-url", R"({"url":"https://example.invalid/nodes.dat"})", "kad/import_nodes_url");
	CHECK_EQ(route.params["url"].get<std::string>(), "https://example.invalid/nodes.dat");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/kad/operations/import-nodes-url", R"({"url":"http:///"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "url must include a host");
	assertRoute("POST", "/api/v1/kad/operations/start", R"({})", "kad/connect");
	assertRoute("POST", "/api/v1/kad/operations/bootstrap", R"({"address":"bootstrap.example.invalid","port":4672})", "kad/bootstrap");
	CHECK_EQ(route.params["address"].get<std::string>(), "bootstrap.example.invalid");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4672u);
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/kad/operations/bootstrap", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "address must be a non-empty string");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/kad/operations/bootstrap", R"({"address":"bootstrap.example.invalid","port":65536})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "port must be in the range 1..65535");
	assertRoute("POST", "/api/v1/kad/operations/stop", R"({})", "kad/disconnect");
	assertRoute("POST", "/api/v1/kad/operations/recheck-firewall", R"({})", "kad/recheck_firewall");

	assertRoute("GET", "/api/v1/shared-directories", "", "shared_directories/get");
	assertRoute("PATCH", "/api/v1/shared-directories", R"({"confirmReplaceRoots":true,"roots":[{"path":"C:\\share","recursive":true}]})", "shared_directories/set");
	CHECK(route.params["roots"][0]["recursive"].get<bool>());
	assertRoute("POST", "/api/v1/shared-directories/operations/reload", R"({})", "shared_directories/reload");

	assertRoute("GET", "/api/v1/shared-files", "", "shared/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/shared-files", R"({"path":"C:\\share\\file.txt"})", "shared/add");
	assertRoute("POST", "/api/v1/shared-files/operations/reload", R"({})", "shared_directories/reload");
	assertRoute("GET", "/api/v1/shared-files/0123456789abcdef0123456789abcdef", "", "shared/get");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/shared-files/0123456789abcdef0123456789abcdef", R"({"comment":"good release","rating":4})", "shared/set_rating_comment");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["comment"].get<std::string>(), "good release");
	CHECK_EQ(route.params["rating"].get<int>(), 4);
	assertRoute("PATCH", "/api/v1/shared-files/0123456789abcdef0123456789abcdef", R"({"priority":"release"})", "shared/set_rating_comment");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["priority"].get<std::string>(), "release");
	assertRoute("GET", "/api/v1/shared-files/0123456789abcdef0123456789abcdef/ed2k-link", "", "shared/ed2k_link");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("GET", "/api/v1/shared-files/0123456789abcdef0123456789abcdef/comments", "", "shared/comments");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("DELETE", "/api/v1/shared-files/0123456789abcdef0123456789abcdef", "", "shared/remove");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_FALSE(route.params["deleteFiles"].get<bool>());
	assertRoute("DELETE", "/api/v1/shared-files/0123456789abcdef0123456789abcdef/file?confirm=true", "", "shared/remove");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK(route.params["deleteFiles"].get<bool>());

	assertRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","method":"automatic","type":"pro"})", "search/start");
	assertRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","method":"automatic","type":"","minAvailability":5})", "search/start");
	CHECK_EQ(route.params["minAvailability"].get<int>(), 5);
	assertRoute("POST", "/api/v1/searches", R"({"query":"feature film","method":"global","type":"video"})", "search/start");
	CHECK_EQ(route.params["method"].get<std::string>(), "global");
	CHECK_EQ(route.params["type"].get<std::string>(), "video");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","method":"contentdb"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "method must be one of automatic, server, global, kad");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","type":"ebook"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "type is not supported");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","type":"Iso"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "type is not supported");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","minSizeBytes":4096,"maxSizeBytes":700})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "maxSizeBytes must be greater than or equal to minSizeBytes");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","clearExisting":1})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "unknown JSON field: clearExisting");
	assertRoute("GET", "/api/v1/searches", "", "search/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("GET", "/api/v1/searches/123", "", "search/results");
	CHECK_EQ(route.params["searchId"].get<std::string>(), "123");
	assertRoute("POST", "/api/v1/searches/123/results/0123456789abcdef0123456789abcdef/operations/download", R"({"paused":true,"categoryId":0})", "search/download_result");
	CHECK_EQ(route.params["searchId"].get<std::string>(), "123");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK(route.params["paused"].get<bool>());
	CHECK_EQ(route.params["categoryId"].get<int>(), 0);
	assertRoute("DELETE", "/api/v1/searches/123", "", "search/stop");
	CHECK_EQ(route.params["searchId"].get<std::string>(), "123");
	assertRoute("DELETE", "/api/v1/searches?confirm=true", "", "search/clear");
	assertRoute("GET", "/api/v1/friends", "", "friends/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/friends", R"({"userHash":"0123456789abcdef0123456789abcdef","name":"peer"})", "friends/add");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["name"].get<std::string>(), "peer");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/friends", R"({"userHash":"0123456789ABCDEF0123456789ABCDEF","name":"peer"})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "userHash must be a 32-character lowercase hex string");
	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/friends", R"({"userHash":"0123456789abcdef0123456789abcdef","name":7})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "name must be a string");
	assertRoute("DELETE", "/api/v1/friends/0123456789abcdef0123456789abcdef", "", "friends/remove");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("GET", "/api/v1/logs?limit=9", "", "log/get");
	CHECK_EQ(route.params["limit"].get<int>(), 9);
	CHECK(route.params["_items_envelope"].get<bool>());
}

TEST_CASE("Web API carries server and search payloads into live-capable routes")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"POST",
		"/api/v1/servers/1.2.3.4:4661/operations/connect",
		R"({})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "servers/connect");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<uint64_t>(), 4661u);

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"POST",
		"/api/v1/kad/operations/start",
		R"({})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "kad/connect");
	CHECK(route.params.is_object());

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"POST",
		"/api/v1/searches",
		R"({"query":"ubuntu","method":"automatic","type":"pro"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "search/start");
	CHECK_EQ(route.params["query"].get<std::string>(), "ubuntu");
	CHECK_EQ(route.params["method"].get<std::string>(), "automatic");
	CHECK_EQ(route.params["type"].get<std::string>(), "pro");

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"DELETE",
		"/api/v1/searches/123",
		"",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "search/stop");
	CHECK_EQ(route.params["searchId"].get<std::string>(), "123");
}

TEST_CASE("Web API rejects malformed JSON and non-object request bodies")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches", "{", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK(errorMessage.rfind("invalid JSON body:", 0) == 0);

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/searches", R"([])", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "JSON body must be an object");
}

TEST_CASE("Web API rejects unknown routes and unsupported HTTP methods")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/app/version", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "NOT_FOUND");
	CHECK_EQ(errorMessage, "API route not found");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/uploads/0123456789abcdef0123456789abcdef/operations/unsupported", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "NOT_FOUND");
	CHECK_EQ(errorMessage, "API route not found");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/upload-queue/0123456789abcdef0123456789abcdef/operations/unsupported", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "NOT_FOUND");
	CHECK_EQ(errorMessage, "API route not found");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("POST", "/api/v1/app", R"({})", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "METHOD_NOT_ALLOWED");
	CHECK_EQ(errorMessage, "HTTP method is not allowed for this API route");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PUT", "/api/v1/app", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "only GET, POST, PATCH, and DELETE are supported");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("get", "/api/v1/app", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "only GET, POST, PATCH, and DELETE are supported");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GETTING", "/api/v1/app", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "only GET, POST, PATCH, and DELETE are supported");

	errorCode.clear();
	errorMessage.clear();
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GETTINGTOOMUCH", "/api/v1/app", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "only GET, POST, PATCH, and DELETE are supported");
}

TEST_CASE("Web API classifies malformed version-root paths as native REST requests")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK(WebServerJsonSeams::IsApiRequestTarget("/api/v1%2x"));
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1%2x", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "malformed percent escape");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::IsApiRequestTarget("/API/V1%2Flogs"));
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/API/V1%2Flogs", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "path segment must not contain encoded slash");

	errorCode.clear();
	errorMessage.clear();
	CHECK(WebServerJsonSeams::IsApiRequestTarget("/api/v1%5Clogs"));
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1%5Clogs", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "path segment must not contain encoded slash");
}

TEST_CASE("Web API rejects malformed native REST requests before command dispatch")
{
	struct SMalformedCase
	{
		const char *pszMethod;
		const char *pszTarget;
		const char *pszBody;
		const char *pszContentType;
		const char *pszErrorCode;
		const char *pszErrorMessagePrefix;
	};

	const SMalformedCase cases[] = {
		{"POST", "/api/v1/searches", "{", "application/json", "INVALID_ARGUMENT", "invalid JSON body:"},
		{"POST", "/api/v1/searches", R"([])", "application/json", "INVALID_ARGUMENT", "JSON body must be an object"},
		{"POST", "/api/v1/searches", R"("linux")", "application/json", "INVALID_ARGUMENT", "JSON body must be an object"},
		{"POST", "/api/v1/searches", "7", "application/json", "INVALID_ARGUMENT", "JSON body must be an object"},
		{"PATCH", "/api/v1/app/preferences", R"({"safeServerConnect":true})", "text/plain", "INVALID_ARGUMENT", "Content-Type must be application/json for JSON request bodies"},
		{"PATCH", "/api/v1/app/preferences", R"({"safeServerConnect":true})", "", "INVALID_ARGUMENT", "Content-Type must be application/json for JSON request bodies"},
		{"GET", "/api/v1/logs?limit=%2x", "", "application/json", "INVALID_ARGUMENT", "malformed percent escape"},
		{"GET", "/api/v1/logs?limit=10&limit=20", "", "application/json", "INVALID_ARGUMENT", "duplicate query parameter: limit"},
		{"GET", "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF", "", "application/json", "INVALID_ARGUMENT", "hash must be a 32-character lowercase hex string"},
		{"GET", "/api/v1/categories/999999999999999999999", "", "application/json", "INVALID_ARGUMENT", "categoryId must be an unsigned decimal string"},
		{"GET", "/api/v1/unsupported", "", "application/json", "NOT_FOUND", "API route not found"},
	};

	for (const SMalformedCase &rCase : cases) {
		WebServerJsonSeams::SApiRoute route;
		std::string errorCode;
		std::string errorMessage;
		CAPTURE(rCase.pszMethod);
		CAPTURE(rCase.pszTarget);
		CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
			rCase.pszMethod,
			rCase.pszTarget,
			rCase.pszBody,
			route,
			errorCode,
			errorMessage,
			rCase.pszContentType));
		CHECK_EQ(errorCode, rCase.pszErrorCode);
		CHECK(errorMessage.rfind(rCase.pszErrorMessagePrefix, 0) == 0);
	}
}

TEST_CASE("Web API maps representative native REST route failures to status codes")
{
	struct SFailureCase
	{
		const char *pszMethod;
		const char *pszTarget;
		const char *pszBody;
		const char *pszContentType;
		const char *pszErrorCode;
		int iStatus;
	};

	const SFailureCase cases[] = {
		{"GET", "/api/v1/app/version", "", "application/json", "NOT_FOUND", 404},
		{"POST", "/api/v1/app", R"({})", "application/json", "METHOD_NOT_ALLOWED", 405},
		{"GET", "/api/v1/logs?limit=%2x", "", "application/json", "INVALID_ARGUMENT", 400},
		{"GET", "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF", "", "application/json", "INVALID_ARGUMENT", 400},
		{"POST", "/api/v1/searches", "{", "application/json", "INVALID_ARGUMENT", 400},
		{"POST", "/api/v1/searches", R"([])", "application/json", "INVALID_ARGUMENT", 400},
		{"PATCH", "/api/v1/app/preferences", R"({"safeServerConnect":true})", "text/plain", "INVALID_ARGUMENT", 400},
		{"PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"priority":"high","legacy":true})", "application/json", "INVALID_ARGUMENT", 400},
		{"DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({})", "application/json", "INVALID_ARGUMENT", 400},
	};

	for (const SFailureCase &failure : cases) {
		WebServerJsonSeams::SApiRoute route;
		std::string errorCode;
		std::string errorMessage;
		CAPTURE(failure.pszMethod);
		CAPTURE(failure.pszTarget);
		CHECK_FALSE(WebServerJsonSeams::TryBuildRoute(
			failure.pszMethod,
			failure.pszTarget,
			failure.pszBody,
			route,
			errorCode,
			errorMessage,
			failure.pszContentType));
		CHECK_EQ(errorCode, failure.pszErrorCode);
		CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError(errorCode), failure.iStatus);
	}
}

TEST_CASE("Web API maps stable error codes onto HTTP status codes")
{
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("INVALID_ARGUMENT"), 400);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("UNAUTHORIZED"), 401);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("METHOD_NOT_ALLOWED"), 405);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("NOT_FOUND"), 404);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("INVALID_STATE"), 409);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("EMULE_UNAVAILABLE"), 503);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("EMULE_ERROR"), 500);
}

TEST_CASE("Web API classifies native REST API key failures without exposing wrong keys")
{
	WebServerJsonSeams::SApiAuthResult auth = WebServerJsonSeams::ValidateApiKey("", "");
	CHECK_FALSE(auth.bAllowed);
	CHECK_EQ(auth.strErrorCode, "EMULE_UNAVAILABLE");
	CHECK_EQ(auth.strErrorMessage, "REST API key is not configured");
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError(auth.strErrorCode), 503);

	auth = WebServerJsonSeams::ValidateApiKey("secret", "");
	CHECK_FALSE(auth.bAllowed);
	CHECK_EQ(auth.strErrorCode, "UNAUTHORIZED");
	CHECK_EQ(auth.strErrorMessage, "missing or invalid X-API-Key");
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError(auth.strErrorCode), 401);

	auth = WebServerJsonSeams::ValidateApiKey("secret", "wrong");
	CHECK_FALSE(auth.bAllowed);
	CHECK_EQ(auth.strErrorCode, "UNAUTHORIZED");
	CHECK_EQ(auth.strErrorMessage, "missing or invalid X-API-Key");
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError(auth.strErrorCode), 401);

	auth = WebServerJsonSeams::ValidateApiKey("secret", "secret");
	CHECK(auth.bAllowed);
	CHECK(auth.strErrorCode.empty());
	CHECK(auth.strErrorMessage.empty());
}

TEST_CASE("Web API builds stable native REST error envelopes")
{
	const WebServerJsonSeams::json envelope =
		WebServerJsonSeams::BuildErrorEnvelopeJson("INVALID_ARGUMENT", "bad input");

	REQUIRE(envelope.contains("error"));
	const WebServerJsonSeams::json &error = envelope["error"];
	CHECK_EQ(error["code"].get<std::string>(), "INVALID_ARGUMENT");
	CHECK_EQ(error["message"].get<std::string>(), "bad input");
	CHECK(error["details"].is_object());
	CHECK(error["details"].empty());

	const WebServerJsonSeams::json details = WebServerJsonSeams::json{{"field", "limit"}};
	const WebServerJsonSeams::json fallback =
		WebServerJsonSeams::BuildErrorEnvelopeJson("", "failed", details);
	CHECK_EQ(fallback["error"]["code"].get<std::string>(), "EMULE_ERROR");
	CHECK_EQ(fallback["error"]["details"]["field"].get<std::string>(), "limit");

	const WebServerJsonSeams::json boundedDetails =
		WebServerJsonSeams::BuildErrorEnvelopeJson("EMULE_ERROR", "failed", WebServerJsonSeams::json::array());
	CHECK(boundedDetails["error"]["details"].is_object());
	CHECK(boundedDetails["error"]["details"].empty());
}

TEST_CASE("Web API envelopes representative runtime REST failures")
{
	struct SRuntimeErrorCase
	{
		const char *pszCode;
		const char *pszMessage;
		int iStatus;
	};

	const SRuntimeErrorCase cases[] = {
		{"NOT_FOUND", "transfer not found", 404},
		{"INVALID_STATE", "transfer source does not support shared-file browsing", 409},
		{"EMULE_UNAVAILABLE", "main window is not available", 503},
		{"EMULE_ERROR", "REST UI command failed", 500},
	};

	for (const SRuntimeErrorCase &rCase : cases) {
		const WebServerJsonSeams::json envelope =
			WebServerJsonSeams::BuildErrorEnvelopeJson(rCase.pszCode, rCase.pszMessage);
		CAPTURE(rCase.pszCode);
		CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError(rCase.pszCode), rCase.iStatus);
		REQUIRE(envelope.contains("error"));
		CHECK_EQ(envelope["error"]["code"].get<std::string>(), rCase.pszCode);
		CHECK_EQ(envelope["error"]["message"].get<std::string>(), rCase.pszMessage);
		CHECK(envelope["error"]["details"].is_object());
	}
}
