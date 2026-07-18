from __future__ import annotations

from pathlib import Path

from emule_test_harness.rust_openapi_routes import (
    QueryParameterDrift,
    Route,
    compare_route_contract,
    compare_route_inventory,
    openapi_query_parameter_inventory,
    openapi_route_inventory,
    rust_query_parameter_inventory,
    rust_route_inventory,
)


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_rust_route_inventory_reads_chained_axum_methods(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        '''
        Router::new()
            .route("/api/v1/app", get(app))
            .route(
                "/api/v1/categories/{categoryId}",
                get(category).patch(update_category).delete(delete_category),
            )
            .route("/api/v1/{*path}", any(fallback));
        ''',
    )

    assert rust_route_inventory(routes_rs) == {
        Route("GET", "/app"),
        Route("DELETE", "/categories/{categoryId}"),
        Route("GET", "/categories/{categoryId}"),
        Route("PATCH", "/categories/{categoryId}"),
    }


def test_openapi_route_inventory_reads_path_methods(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
openapi: 3.1.0
paths:
  /app:
    get:
      responses: {}
  /categories/{categoryId}:
    get:
      responses: {}
    patch:
      responses: {}
    delete:
      responses: {}
""",
    )

    assert openapi_route_inventory(openapi_yaml) == {
        Route("GET", "/app"),
        Route("DELETE", "/categories/{categoryId}"),
        Route("GET", "/categories/{categoryId}"),
        Route("PATCH", "/categories/{categoryId}"),
    }


def test_compare_route_inventory_reports_exact_placeholder_drift(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        'Router::new().route("/api/v1/searches/{search_id}", get(search));',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /searches/{searchId}:
    get:
      responses: {}
""",
    )

    report = compare_route_inventory(routes_rs, openapi_yaml)

    assert report.implemented_missing_from_openapi == (Route("GET", "/searches/{search_id}"),)
    assert report.openapi_missing_from_implemented == (Route("GET", "/searches/{searchId}"),)


def test_openapi_query_parameter_inventory_resolves_refs_and_inline_params(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /transfers:
    get:
      parameters:
        - $ref: "#/components/parameters/Limit"
        - name: state
          in: query
        - name: hash
          in: path
      responses: {}
components:
  parameters:
    Limit:
      name: limit
      in: query
""",
    )

    assert openapi_query_parameter_inventory(openapi_yaml) == {
        Route("GET", "/transfers"): ("limit", "state"),
    }


def test_rust_query_parameter_inventory_reads_exact_and_parameterized_allowlists(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        '''
        Router::new()
            .route("/api/v1/app", get(app))
            .route("/api/v1/snapshot", get(snapshot))
            .route("/api/v1/upload-queue", get(upload_queue))
            .route("/api/v1/searches/{searchId}", get(search))
            .route("/api/v1/transfers/{hash}/files", delete(transfer_delete_files));
        ''',
    )
    route_metadata_rs = write(
        tmp_path / "route_metadata.rs",
        '''
        fn route_query_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const NONE: &[&str] = &[];
            const SNAPSHOT: &[&str] = &["limit"];
            const CONFIRM: &[&str] = &["confirm"];
            const SEARCH: &[&str] = &["offset", "limit", "includeEvidence", "exactTotal"];
            const UPLOAD_QUEUE: &[&str] = &["offset", "limit", "includeScoreBreakdown"];
            match (method, path) {
                ("GET", "/api/v1/app")
                | ("GET", "/api/v1/upload-queue") => Some(match path {
                    "/api/v1/upload-queue" if method == "GET" => UPLOAD_QUEUE,
                    _ => NONE,
                }),
                ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
                _ => route_query_fields_for_parameterized(method, path),
            }
        }

        fn route_query_fields_for_parameterized(
            method: &str,
            path: &str,
        ) -> Option<&'static [&'static str]> {
            const NONE: &[&str] = &[];
            const CONFIRM: &[&str] = &["confirm"];
            const SEARCH: &[&str] = &["offset", "limit", "includeEvidence", "exactTotal"];
            let segments = path.strip_prefix("/api/v1/")?.split('/').collect::<Vec<_>>();
            match (method, segments.as_slice()) {
                ("GET", ["searches", _]) => Some(SEARCH),
                ("DELETE", ["transfers", _, "files"]) => Some(CONFIRM),
                _ => Some(NONE),
            }
        }
        ''',
    )

    assert rust_query_parameter_inventory(route_metadata_rs, routes_rs) == {
        Route("GET", "/app"): (),
        Route("GET", "/snapshot"): ("limit",),
        Route("GET", "/upload-queue"): ("includeScoreBreakdown", "limit", "offset"),
        Route("GET", "/searches/{searchId}"): ("exactTotal", "includeEvidence", "limit", "offset"),
        Route("DELETE", "/transfers/{hash}/files"): ("confirm",),
    }


def test_compare_route_contract_reports_query_parameter_drift(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        'Router::new().route("/api/v1/snapshot", get(snapshot));',
    )
    route_metadata_rs = write(
        tmp_path / "route_metadata.rs",
        '''
        fn route_query_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const SNAPSHOT: &[&str] = &["limit"];
            match (method, path) {
                ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
                _ => None,
            }
        }
        ''',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /snapshot:
    get:
      parameters:
        - name: since
          in: query
      responses: {}
""",
    )

    report = compare_route_contract(routes_rs, route_metadata_rs, openapi_yaml)

    assert report.query_parameter_drift == (
        QueryParameterDrift(
            route=Route("GET", "/snapshot"),
            rust_query_parameters=("limit",),
            openapi_query_parameters=("since",),
        ),
    )
