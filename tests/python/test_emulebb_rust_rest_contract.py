from __future__ import annotations

import re
from pathlib import Path

import yaml

from emule_test_harness.paths import get_emule_workspace_root


ROUTE_SPEC_FUNCTION = "inline const std::vector<SApiRouteSpec> &GetApiRouteSpecs()"

# Per the /api/v1 contract split, the forward Rust client owns its own evolving
# contract and may expose routes the frozen MFC `0.7.3` contract never had. Rust
# must still implement every frozen-contract route; these are the documented
# forward-only additions it is allowed to carry on top.
FORWARD_ONLY_RUST_ROUTES = {("GET", "/api/v1/capabilities")}

# Maps each OpenAPI request-body schema to the Rust request struct that backs it.
# Guards the deny_unknown_fields class of bug where a documented optional field is
# missing from the Rust struct and every request carrying it is rejected with 400.
REQUEST_SCHEMA_TO_RUST_STRUCT = {
    "PreferencesPatch": "PreferencesUpdate",
    "ShutdownRequest": "ShutdownRequest",
    "DiagnosticDumpRequest": "DiagnosticDumpRequest",
    "DiagnosticCrashTestRequest": "DiagnosticCrashTestRequest",
    "CategoryCreateRequest": "CategoryCreate",
    "CategoryPatch": "CategoryUpdate",
    "TransferCreateRequest": "TransferCreate",
    "ClearCompletedTransfersRequest": "ClearCompletedTransfersRequest",
    "TransferPatch": "TransferUpdate",
    "SharedFileCreateRequest": "SharedFileCreateRequest",
    "SharedFilePatch": "SharedFileUpdate",
    "SharedDirectoryReplaceRequest": "SharedDirectoriesUpdate",
    "ServerCreateRequest": "ServerCreate",
    "UrlImportRequest": "UrlImportRequest",
    "ServerPatch": "ServerUpdate",
    "KadBootstrapRequest": "KadBootstrapRequest",
    "SearchCreateRequest": "SearchCreate",
    "SearchResultDownloadRequest": "SearchResultDownloadCreate",
    "FriendCreateRequest": "FriendCreate",
    "ClearLogsRequest": "LogsClearRequest",
}


def test_emulebb_rust_request_bodies_accept_contract_fields() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workspace_root = get_emule_workspace_root(repo_root)
    contract = yaml.safe_load(
        (
            workspace_root / "repos" / "emulebb-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
        ).read_text(encoding="utf-8")
    )
    schemas = contract["components"]["schemas"]
    rust_structs = rust_request_struct_fields(
        workspace_root / "repos" / "emulebb-rust" / "crates"
    )

    missing: dict[str, list[str]] = {}
    for schema_name, rust_name in REQUEST_SCHEMA_TO_RUST_STRUCT.items():
        contract_fields = set((schemas[schema_name].get("properties") or {}).keys())
        assert contract_fields, f"contract schema {schema_name} has no properties"
        assert rust_name in rust_structs, f"Rust request struct not found: {rust_name}"
        gap = sorted(contract_fields - rust_structs[rust_name])
        if gap:
            missing[f"{schema_name} -> {rust_name}"] = gap

    assert not missing, f"Rust request structs reject documented contract fields: {missing}"


def rust_request_struct_fields(crates_dir: Path) -> dict[str, set[str]]:
    structs: dict[str, set[str]] = {}
    for source in crates_dir.glob("**/src/**/*.rs"):
        if "/target/" in source.as_posix():
            continue
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?struct (\w+)\s*\{", line)
            if not match:
                continue
            context = "\n".join(lines[max(0, index - 4) : index])
            if "Deserialize" not in context:
                continue
            structs[match.group(1)] = rust_struct_field_names(lines, index + 1)
    return structs


def rust_struct_field_names(lines: list[str], start: int) -> set[str]:
    fields: set[str] = set()
    rename: str | None = None
    for line in lines[start:]:
        if re.match(r"\s*\}", line):
            break
        rename_match = re.search(r'rename\s*=\s*"([^"]+)"', line)
        if rename_match:
            rename = rename_match.group(1)
        field_match = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?(\w+|r#\w+)\s*:", line)
        if field_match:
            ident = field_match.group(1).replace("r#", "")
            fields.add(rename or snake_to_camel(ident))
            rename = None
    return fields


def snake_to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def test_emulebb_rust_routes_match_canonical_emulebb_rest_contract() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workspace_root = get_emule_workspace_root(repo_root)
    canonical_routes = canonical_emulebb_routes(
        workspace_root
        / "workspaces"
        / "workspace"
        / "app"
        / "emulebb-main"
        / "srchybrid"
        / "WebServerJsonSeams.h"
    )
    rust_routes = emulebb_rust_routes(
        workspace_root
        / "repos"
        / "emulebb-rust"
        / "crates"
        / "emulebb-rest"
        / "src"
    )

    assert canonical_routes
    assert rust_routes
    assert sorted(canonical_routes - rust_routes) == []
    assert sorted(rust_routes - canonical_routes) == sorted(FORWARD_ONLY_RUST_ROUTES)


def test_emulebb_rust_routes_match_openapi_contract() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workspace_root = get_emule_workspace_root(repo_root)
    openapi_routes = openapi_emulebb_routes(
        workspace_root
        / "repos"
        / "emulebb-tooling"
        / "docs"
        / "rest"
        / "REST-API-OPENAPI.yaml"
    )
    rust_routes = emulebb_rust_routes(
        workspace_root
        / "repos"
        / "emulebb-rust"
        / "crates"
        / "emulebb-rest"
        / "src"
    )

    assert openapi_routes
    assert rust_routes
    assert sorted(openapi_routes - rust_routes) == []
    assert sorted(rust_routes - openapi_routes) == sorted(FORWARD_ONLY_RUST_ROUTES)


def canonical_emulebb_routes(path: Path) -> set[tuple[str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    specs = route_spec_block(text)
    return {
        (method, normalize_route_path(f"/api/v1{route}"))
        for method, route in re.findall(r'\{\s*"([A-Z]+)"\s*,\s*"([^"]+)"', specs)
    }


def openapi_emulebb_routes(path: Path) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    current_path: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("components:"):
            break
        path_match = re.match(r"  (/[^:]+):\s*$", line)
        if path_match:
            current_path = normalize_route_path(f"/api/v1{path_match.group(1)}")
            continue
        method_match = re.match(r"    (get|post|patch|delete):\s*$", line)
        if method_match and current_path is not None:
            routes.add((method_match.group(1).upper(), current_path))
    return routes


def emulebb_rust_routes(path: Path) -> set[tuple[str, str]]:
    # `path` may be a single file or the crate `src` directory; the axum
    # `.route(...)` calls live wherever the router is wired (lib.rs historically,
    # now routes.rs after the REST module split), so scan the whole tree when
    # given a directory.
    if path.is_dir():
        text = "".join(
            source.read_text(encoding="utf-8", errors="replace")
            for source in sorted(path.glob("**/*.rs"))
        )
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
    routes: set[tuple[str, str]] = set()
    for call in rust_route_calls(text):
        path_match = re.search(r'"([^"]+)"', call)
        if path_match is None:
            continue
        route_path = normalize_route_path(path_match.group(1))
        for method in re.findall(r"\b(get|post|patch|delete)\s*\(", call):
            routes.add((method.upper(), route_path))
    return routes


def route_spec_block(text: str) -> str:
    start = text.index(ROUTE_SPEC_FUNCTION)
    end = text.index("return specs;", start)
    return text[start:end]


def normalize_route_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def rust_route_calls(text: str) -> list[str]:
    calls: list[str] = []
    offset = 0
    while True:
        route_index = text.find(".route(", offset)
        if route_index == -1:
            return calls
        open_paren_index = route_index + len(".route(") - 1
        close_paren_index = matching_paren_index(text, open_paren_index)
        calls.append(text[open_paren_index + 1 : close_paren_index])
        offset = close_paren_index + 1


def matching_paren_index(text: str, open_paren_index: int) -> int:
    depth = 0
    in_string = False
    escaped = False
    for index in range(open_paren_index, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError("unterminated Rust .route(...) call")


# Response fields the eMuleBB master emits and that the Rust client now implements.
# Guards the response-shape parity work (search items+pagination, transfer
# eta/parts/timestamps, upload scoreBreakdown, app build/platform, VPN guard)
# against regressions. Doc-only OpenAPI drift the master does NOT emit
# (generatedAt, elevated, webServer, shared-dir exists/monitored) is excluded.
ALIGNED_RESPONSE_FIELDS = [
    # search uses the shared paged shape (items + total/offset/limit)
    "items",
    "total",
    "offset",
    "limit",
    # transfer view
    "eta",
    "addedAt",
    "completedAt",
    "partsTotal",
    "partsObtained",
    "partsProgressText",
    "autoPriority",
    # upload score breakdown
    "scoreBreakdown",
    "baseScore",
    "effectiveScore",
    "coreScore",
    "creditRatio",
    "lowIdDivisor",
    "cooldownRemainingMs",
    # app metadata
    "build",
    "platform",
    # VPN guard
    "vpnGuard",
    "blockedByVpnGuard",
    "startupBlocked",
    "allowedPublicIpCidrs",
    # logs
    "debug",
]


def test_emulebb_rust_emits_aligned_response_fields() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workspace_root = get_emule_workspace_root(repo_root)
    crates_dir = workspace_root / "repos" / "emulebb-rust" / "crates"
    text = "".join(
        source.read_text(encoding="utf-8", errors="replace")
        for source in crates_dir.glob("**/src/**/*.rs")
    )

    def snake(name: str) -> str:
        return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()

    def present(field: str) -> bool:
        # camelCase json! literal, or the serde struct field in snake_case.
        return f'"{field}"' in text or re.search(rf"\b{snake(field)}\s*:", text) is not None

    missing = [field for field in ALIGNED_RESPONSE_FIELDS if not present(field)]
    assert not missing, f"Rust no longer emits aligned response fields: {missing}"
