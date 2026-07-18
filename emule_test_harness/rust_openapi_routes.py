"""Static route inventory drift checks for emulebb-rust OpenAPI coverage."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .paths import get_required_emule_workspace_root

HTTP_METHODS = ("delete", "get", "patch", "post", "put")


@dataclass(frozen=True, order=True)
class Route:
    """One HTTP method/path pair in the native Rust REST contract."""

    method: str
    path: str


@dataclass(frozen=True)
class RouteDriftReport:
    """Route drift between the Rust router and OpenAPI path inventory."""

    implemented_missing_from_openapi: tuple[Route, ...]
    openapi_missing_from_implemented: tuple[Route, ...]

    @property
    def ok(self) -> bool:
        return not self.implemented_missing_from_openapi and not self.openapi_missing_from_implemented

    def as_json_dict(self) -> dict[str, list[dict[str, str]]]:
        return {
            "implementedMissingFromOpenapi": route_list_json(self.implemented_missing_from_openapi),
            "openapiMissingFromImplemented": route_list_json(self.openapi_missing_from_implemented),
        }


def route_list_json(routes: Iterable[Route]) -> list[dict[str, str]]:
    return [{"method": route.method, "path": route.path} for route in routes]


def rust_route_inventory(routes_rs: Path) -> set[Route]:
    """Returns route method/path pairs declared in `crates/emulebb-rest/src/routes.rs`."""

    text = routes_rs.read_text(encoding="utf-8")
    routes: set[Route] = set()
    for chunk in text.split(".route(")[1:]:
        path_match = re.search(r'"([^"]+)"', chunk)
        if path_match is None:
            continue
        full_path = path_match.group(1)
        if not full_path.startswith("/api/v1/") or "{*" in full_path:
            continue
        path = full_path.removeprefix("/api/v1")
        for method in HTTP_METHODS:
            if re.search(rf"\b{method}\s*\(", chunk):
                routes.add(Route(method.upper(), path))
    return routes


def openapi_route_inventory(openapi_yaml: Path) -> set[Route]:
    """Returns server-relative OpenAPI method/path pairs from the top-level `paths` map."""

    routes: set[Route] = set()
    current_path: str | None = None
    for line in openapi_yaml.read_text(encoding="utf-8").splitlines():
        path_match = re.match(r"^  (/[^:]+):\s*$", line)
        if path_match is not None:
            current_path = path_match.group(1)
            continue
        if current_path is None:
            continue
        method_match = re.match(r"^    (delete|get|patch|post|put):\s*$", line)
        if method_match is not None:
            routes.add(Route(method_match.group(1).upper(), current_path))
    return routes


def compare_route_inventory(routes_rs: Path, openapi_yaml: Path) -> RouteDriftReport:
    implemented = rust_route_inventory(routes_rs)
    documented = openapi_route_inventory(openapi_yaml)
    return RouteDriftReport(
        implemented_missing_from_openapi=tuple(sorted(implemented - documented)),
        openapi_missing_from_implemented=tuple(sorted(documented - implemented)),
    )


def default_routes_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "routes.rs"


def default_openapi_yaml(workspace_root: Path) -> Path:
    return (
        workspace_root
        / "repos"
        / "emulebb-tooling"
        / "docs"
        / "products"
        / "emulebb-rust"
        / "api"
        / "REST-API-OPENAPI.yaml"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check emulebb-rust router paths against the OpenAPI contract.")
    parser.add_argument("--rust-routes", type=Path, help="Path to crates/emulebb-rest/src/routes.rs.")
    parser.add_argument("--openapi", type=Path, help="Path to the emulebb-rust OpenAPI YAML artifact.")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report.")
    return parser


def run_cli(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    workspace_root = get_required_emule_workspace_root()
    routes_rs = args.rust_routes or default_routes_rs(workspace_root)
    openapi_yaml = args.openapi or default_openapi_yaml(workspace_root)
    report = compare_route_inventory(routes_rs, openapi_yaml)
    if args.json:
        print(json.dumps(report.as_json_dict(), indent=2, sort_keys=True))
    elif report.ok:
        print("emulebb-rust OpenAPI route inventory matches the router.")
    else:
        print_route_drift_report(report)
    return 0 if report.ok else 1


def print_route_drift_report(report: RouteDriftReport) -> None:
    if report.implemented_missing_from_openapi:
        print("Implemented routes missing from OpenAPI:")
        for route in report.implemented_missing_from_openapi:
            print(f"  {route.method} {route.path}")
    if report.openapi_missing_from_implemented:
        print("OpenAPI routes missing from the Rust router:")
        for route in report.openapi_missing_from_implemented:
            print(f"  {route.method} {route.path}")
