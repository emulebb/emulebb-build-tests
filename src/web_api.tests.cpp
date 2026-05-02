#include "../third_party/doctest/doctest.h"
#include <climits>
#include "WebApiCommandSeams.h"
#include "WebApiSurfaceSeams.h"
#include "WebServerAuthStateSeams.h"
#include "WebServerJsonSeams.h"
#include "WebServerStaticFileSeams.h"

TEST_SUITE_BEGIN("web_api");

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

TEST_CASE("Web API parses the final transfer priority vocabulary")
{
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("auto"), WebApiSurfaceSeams::ETransferPriority::Auto);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("very_low"), WebApiSurfaceSeams::ETransferPriority::VeryLow);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("low"), WebApiSurfaceSeams::ETransferPriority::Low);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("normal"), WebApiSurfaceSeams::ETransferPriority::Normal);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("high"), WebApiSurfaceSeams::ETransferPriority::High);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("very_high"), WebApiSurfaceSeams::ETransferPriority::VeryHigh);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName("invalid"), WebApiSurfaceSeams::ETransferPriority::Invalid);
	CHECK_EQ(WebApiSurfaceSeams::ParseTransferPriorityName(nullptr), WebApiSurfaceSeams::ETransferPriority::Invalid);
}

TEST_CASE("Web API parses the expanded mutable preference vocabulary")
{
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxUploadKiB"), WebApiSurfaceSeams::EMutablePreference::MaxUploadKiB);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxDownloadKiB"), WebApiSurfaceSeams::EMutablePreference::MaxDownloadKiB);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxConnections"), WebApiSurfaceSeams::EMutablePreference::MaxConnections);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("maxConPerFive"), WebApiSurfaceSeams::EMutablePreference::MaxConPerFive);
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
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName("unsupported"), WebApiSurfaceSeams::EMutablePreference::Invalid);
	CHECK_EQ(WebApiSurfaceSeams::ParseMutablePreferenceName(nullptr), WebApiSurfaceSeams::EMutablePreference::Invalid);
}

TEST_CASE("Web API normalizes search method and type names case-insensitively")
{
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName("AUTOMATIC"), WebApiCommandSeams::ESearchMethod::Automatic);
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName("gLoBaL"), WebApiCommandSeams::ESearchMethod::Global);
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName(""), WebApiCommandSeams::ESearchMethod::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchMethodName(nullptr), WebApiCommandSeams::ESearchMethod::Invalid);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("VIDEO"), WebApiCommandSeams::ESearchFileType::Video);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName("emulecollection"), WebApiCommandSeams::ESearchFileType::EmuleCollection);
	CHECK_EQ(WebApiCommandSeams::ParseSearchFileTypeName(nullptr), WebApiCommandSeams::ESearchFileType::Invalid);
}

TEST_CASE("Web API only allows shared-file removal for files that are shared and not mandatory")
{
	CHECK(WebApiSurfaceSeams::CanRemoveSharedFile(true, false));
	CHECK_FALSE(WebApiSurfaceSeams::CanRemoveSharedFile(false, false));
	CHECK_FALSE(WebApiSurfaceSeams::CanRemoveSharedFile(true, true));
}

TEST_CASE("Web API parses the search start command vocabulary and trims the query")
{
	WebApiCommandSeams::SSearchStartRequest request;
	std::string error;
	const WebApiCommandSeams::json params = {
		{"query", " 1080p "},
		{"method", "KaD"},
		{"type", "ISO"},
		{"ext", ".mkv"},
		{"min_size", 700u},
		{"max_size", 4096u}
	};

	CHECK(WebApiCommandSeams::TryParseSearchStartRequest(params, request, error));
	CHECK(error.empty());
	CHECK_EQ(request.strQuery, "1080p");
	CHECK_EQ(request.eMethod, WebApiCommandSeams::ESearchMethod::Kad);
	CHECK_EQ(request.eFileType, WebApiCommandSeams::ESearchFileType::CdImage);
	CHECK_EQ(request.strExtension, ".mkv");
	CHECK(request.bHasMinSize);
	CHECK(request.bHasMaxSize);
	CHECK_EQ(request.ullMinSize, 700u);
	CHECK_EQ(request.ullMaxSize, 4096u);
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
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"min_size", -1}}, request, error));
	CHECK_EQ(error, "min_size must be an unsigned number");

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
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"ext", 7}}, request, error));
	CHECK_EQ(error, "ext must be a string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchStartRequest(WebApiCommandSeams::json{{"query", "1080p"}, {"max_size", -1}}, request, error));
	CHECK_EQ(error, "max_size must be an unsigned number");
}

TEST_CASE("Web API parses search identifiers as decimal uint32 strings")
{
	uint32_t uSearchID = 0;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json("12345"), uSearchID, error));
	CHECK_EQ(uSearchID, 12345u);

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json(""), uSearchID, error));
	CHECK_EQ(error, "search_id must not be empty");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json("12x"), uSearchID, error));
	CHECK_EQ(error, "search_id must be a valid uint32 decimal string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json(7), uSearchID, error));
	CHECK_EQ(error, "search_id must be a decimal string");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseSearchId(WebApiCommandSeams::json("4294967296"), uSearchID, error));
	CHECK_EQ(error, "search_id must be a valid uint32 decimal string");
}

TEST_CASE("Web API parses transfer list filters and validates categories")
{
	WebApiCommandSeams::STransfersListRequest request;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransfersListRequest(WebApiCommandSeams::json{{"filter", "DoWnLoAdInG"}, {"category", 3}}, request, error));
	CHECK_EQ(request.strFilterLower, "downloading");
	CHECK(request.bHasCategory);
	CHECK_EQ(request.uCategory, 3u);

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransfersListRequest(WebApiCommandSeams::json{{"filter", 7}}, request, error));
	CHECK_EQ(error, "filter must be a string when provided");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransfersListRequest(WebApiCommandSeams::json{{"category", -1}}, request, error));
	CHECK_EQ(error, "category must be an unsigned number");
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

TEST_CASE("Web API parses bulk transfer mutations and the delete-files aliases")
{
	WebApiCommandSeams::STransferBulkMutationRequest request;
	std::string error;

	CHECK(WebApiCommandSeams::TryParseTransferBulkMutationRequest(
		WebApiCommandSeams::json{
			{"hashes", WebApiCommandSeams::json::array({"a", "b"})},
			{"delete_files", true}
		},
		request,
		error));
	CHECK_EQ(request.hashes.size(), 2u);
	CHECK(request.bDeleteFiles);
	CHECK_EQ(request.hashes[0].get<std::string>(), "a");
	CHECK_EQ(request.hashes[1].get<std::string>(), "b");

	error.clear();
	CHECK_FALSE(WebApiCommandSeams::TryParseTransferBulkMutationRequest(WebApiCommandSeams::json{{"hashes", "abc"}}, request, error));
	CHECK_EQ(error, "hashes must be a string array");
}

TEST_CASE("Web API accepts both delete-file aliases and rejects missing hash arrays")
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

TEST_CASE("Web API builds representative REST routes and normalizes query parameters")
{
	WebServerJsonSeams::SApiRoute route;
	std::string errorCode;
	std::string errorMessage;

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/app", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "app/version");
	CHECK(route.params.is_object());

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/transfers?filter=Downloading&category=3", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "transfers/list");
	CHECK_EQ(route.params["filter"].get<std::string>(), "Downloading");
	CHECK_EQ(route.params["category"].get<uint64_t>(), 3u);
	CHECK(route.params["_items_envelope"].get<bool>());

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/logs?limit=999999999999", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "log/get");
	CHECK_EQ(route.params["limit"].get<int>(), INT_MAX);
	CHECK(route.params["_items_envelope"].get<bool>());

	CHECK(WebServerJsonSeams::TryBuildRoute("GET", "/api/v1/categories", "", route, errorCode, errorMessage));
	CHECK_EQ(route.strCommand, "categories/list");
	CHECK(route.params["_items_envelope"].get<bool>());

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
	CHECK_EQ(route.params["search_id"].get<std::string>(), "123");

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
	};

	assertRoute("GET", "/api/v1/app", "", "app/version");
	assertRoute("GET", "/api/v1/app/preferences", "", "app/preferences/get");
	assertRoute("PATCH", "/api/v1/app/preferences", R"({"safeServerConnect":true})", "app/preferences/set");
	CHECK(route.params.contains("prefs"));
	CHECK(route.params["prefs"].contains("safeServerConnect"));
	assertRoute("POST", "/api/v1/app/shutdown", R"({})", "app/shutdown");
	assertRoute("GET", "/api/v1/status", "", "status/get");
	assertRoute("GET", "/api/v1/snapshot?limit=7", "", "snapshot/get");
	CHECK_EQ(route.params["limit"].get<int>(), 7);
	assertRoute("GET", "/api/v1/categories", "", "categories/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/categories", R"({"name":"Linux","path":"C:\\incoming\\linux","priority":"high","color":255})", "categories/create");
	CHECK_EQ(route.params["name"].get<std::string>(), "Linux");
	assertRoute("GET", "/api/v1/categories/2", "", "categories/get");
	CHECK_EQ(route.params["id"].get<std::string>(), "2");
	assertRoute("PATCH", "/api/v1/categories/2", R"({"name":"ISOs","priority":"normal"})", "categories/update");
	CHECK_EQ(route.params["id"].get<std::string>(), "2");
	assertRoute("DELETE", "/api/v1/categories/2", "", "categories/delete");
	CHECK_EQ(route.params["id"].get<std::string>(), "2");

	assertRoute("GET", "/api/v1/transfers?filter=paused&category=2", "", "transfers/list");
	CHECK_EQ(route.params["filter"].get<std::string>(), "paused");
	CHECK_EQ(route.params["category"].get<uint64_t>(), 2u);
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/transfers", R"({"link":"ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/"})", "transfers/add");
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"action":"pause"})", "transfers/pause");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/pause", R"({})", "transfers/pause");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"action":"resume"})", "transfers/resume");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/resume", R"({})", "transfers/resume");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"action":"stop"})", "transfers/stop");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/stop", R"({})", "transfers/stop");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("DELETE", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"delete_files":true})", "transfers/delete");
	CHECK_EQ(route.params["hashes"][0].get<std::string>(), pszHash);
	assertRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef", "", "transfers/get");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef/details", "", "transfers/details");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("GET", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources", "", "transfers/sources");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources/browse", R"({"userHash":"fedcba9876543210fedcba9876543210"})", "transfers/source_browse");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["userHash"].get<std::string>(), "fedcba9876543210fedcba9876543210");
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/sources/fedcba9876543210fedcba9876543210/operations/browse", R"({})", "transfers/source_browse");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	CHECK_EQ(route.params["userHash"].get<std::string>(), "fedcba9876543210fedcba9876543210");
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"action":"recheck"})", "transfers/recheck");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/recheck", R"({})", "transfers/recheck");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/transfers/0123456789abcdef0123456789abcdef/operations/preview", R"({})", "transfers/preview");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"priority":"high"})", "transfers/set_priority");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);
	assertRoute("PATCH", "/api/v1/transfers/0123456789abcdef0123456789abcdef", R"({"category":0})", "transfers/set_category");
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
	assertRoute("DELETE", "/api/v1/uploads/0123456789abcdef0123456789abcdef", R"({})", "uploads/remove");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/uploads/0123456789abcdef0123456789abcdef/release-slot", R"({})", "uploads/release_slot");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);
	assertRoute("POST", "/api/v1/uploads/0123456789abcdef0123456789abcdef/operations/release-slot", R"({})", "uploads/release_slot");
	CHECK_EQ(route.params["userHash"].get<std::string>(), pszHash);

	assertRoute("GET", "/api/v1/servers", "", "servers/list");
	CHECK(route.params["_items_envelope"].get<bool>());
	assertRoute("POST", "/api/v1/servers", R"({"addr":"1.2.3.4","port":4661,"name":"test"})", "servers/add");
	assertRoute("POST", "/api/v1/servers/met-url-imports", R"({"url":"https://example.invalid/server.met"})", "servers/import_met_url");
	CHECK_EQ(route.params["url"].get<std::string>(), "https://example.invalid/server.met");
	assertRoute("POST", "/api/v1/servers/operations/connect", R"({})", "servers/connect");
	assertRoute("POST", "/api/v1/servers/operations/disconnect", R"({})", "servers/disconnect");
	assertRoute("PATCH", "/api/v1/servers/1.2.3.4:4661", R"({"action":"connect"})", "servers/connect");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);
	assertRoute("PATCH", "/api/v1/servers/1.2.3.4:4661", R"({"name":"Pinned","priority":"high","static":true})", "servers/update");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);
	CHECK_EQ(route.params["name"].get<std::string>(), "Pinned");
	CHECK_EQ(route.params["priority"].get<std::string>(), "high");
	CHECK(route.params["static"].get<bool>());
	assertRoute("POST", "/api/v1/servers/1.2.3.4:4661/operations/connect", R"({})", "servers/connect");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);
	assertRoute("PATCH", "/api/v1/servers/current:1", R"({"action":"disconnect"})", "servers/disconnect");
	assertRoute("DELETE", "/api/v1/servers/1.2.3.4:4661", R"({})", "servers/remove");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4661u);

	assertRoute("GET", "/api/v1/kad", "", "kad/status");
	assertRoute("PATCH", "/api/v1/kad", R"({"action":"connect"})", "kad/connect");
	assertRoute("POST", "/api/v1/kad/operations/start", R"({})", "kad/connect");
	assertRoute("POST", "/api/v1/kad/operations/bootstrap", R"({"address":"bootstrap.example.invalid","port":4672})", "kad/bootstrap");
	CHECK_EQ(route.params["address"].get<std::string>(), "bootstrap.example.invalid");
	CHECK_EQ(route.params["port"].get<unsigned>(), 4672u);
	assertRoute("PATCH", "/api/v1/kad", R"({"action":"disconnect"})", "kad/disconnect");
	assertRoute("POST", "/api/v1/kad/operations/stop", R"({})", "kad/disconnect");
	assertRoute("PATCH", "/api/v1/kad", R"({"action":"recheck_firewall"})", "kad/recheck_firewall");
	assertRoute("POST", "/api/v1/kad/operations/recheck-firewall", R"({})", "kad/recheck_firewall");

	assertRoute("GET", "/api/v1/shared-directories", "", "shared_directories/get");
	assertRoute("PATCH", "/api/v1/shared-directories", R"({"roots":[{"path":"C:\\share","recursive":true}]})", "shared_directories/set");
	CHECK(route.params["roots"][0]["recursive"].get<bool>());
	assertRoute("POST", "/api/v1/shared-directories/reload", R"({})", "shared_directories/reload");
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
	assertRoute("DELETE", "/api/v1/shared-files/0123456789abcdef0123456789abcdef", R"({})", "shared/remove");
	CHECK_EQ(route.params["hash"].get<std::string>(), pszHash);

	assertRoute("POST", "/api/v1/searches", R"({"query":"ubuntu","method":"automatic","type":"program"})", "search/start");
	assertRoute("GET", "/api/v1/searches/123", "", "search/results");
	CHECK_EQ(route.params["search_id"].get<std::string>(), "123");
	assertRoute("DELETE", "/api/v1/searches/123", R"({})", "search/stop");
	CHECK_EQ(route.params["search_id"].get<std::string>(), "123");
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
		"PATCH",
		"/api/v1/servers/1.2.3.4:4661",
		R"({"action":"connect"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "servers/connect");
	CHECK_EQ(route.params["addr"].get<std::string>(), "1.2.3.4");
	CHECK_EQ(route.params["port"].get<uint64_t>(), 4661u);

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"PATCH",
		"/api/v1/kad",
		R"({"action":"connect"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "kad/connect");
	CHECK(route.params.is_object());

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"POST",
		"/api/v1/searches",
		R"({"query":"ubuntu","method":"automatic","type":"program"})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "search/start");
	CHECK_EQ(route.params["query"].get<std::string>(), "ubuntu");
	CHECK_EQ(route.params["method"].get<std::string>(), "automatic");
	CHECK_EQ(route.params["type"].get<std::string>(), "program");

	CHECK(WebServerJsonSeams::TryBuildRoute(
		"DELETE",
		"/api/v1/searches/123",
		R"({})",
		route,
		errorCode,
		errorMessage));
	CHECK_EQ(route.strCommand, "search/stop");
	CHECK_EQ(route.params["search_id"].get<std::string>(), "123");
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
	CHECK_FALSE(WebServerJsonSeams::TryBuildRoute("PUT", "/api/v1/app", "", route, errorCode, errorMessage));
	CHECK_EQ(errorCode, "INVALID_ARGUMENT");
	CHECK_EQ(errorMessage, "only GET, POST, PATCH, and DELETE are supported");
}

TEST_CASE("Web API maps stable error codes onto HTTP status codes")
{
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("INVALID_ARGUMENT"), 400);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("UNAUTHORIZED"), 401);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("NOT_FOUND"), 404);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("INVALID_STATE"), 409);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("EMULE_UNAVAILABLE"), 503);
	CHECK_EQ(WebServerJsonSeams::GetHttpStatusForError("EMULE_ERROR"), 500);
}
