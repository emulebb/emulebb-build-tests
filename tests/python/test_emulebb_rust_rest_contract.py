from __future__ import annotations

import re
from pathlib import Path

from emule_test_harness.paths import get_emule_workspace_root


ROUTE_SPEC_FUNCTION = "inline const std::vector<SApiRouteSpec> &GetApiRouteSpecs()"


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
        / "lib.rs"
    )

    assert canonical_routes
    assert rust_routes
    assert sorted(canonical_routes - rust_routes) == []
    assert sorted(rust_routes - canonical_routes) == []


def canonical_emulebb_routes(path: Path) -> set[tuple[str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    specs = route_spec_block(text)
    return {
        (method, normalize_route_path(f"/api/v1{route}"))
        for method, route in re.findall(r'\{\s*"([A-Z]+)"\s*,\s*"([^"]+)"', specs)
    }


def emulebb_rust_routes(path: Path) -> set[tuple[str, str]]:
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
