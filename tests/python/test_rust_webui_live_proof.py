from __future__ import annotations

import pytest

from emule_test_harness import rust_webui_live_proof


@pytest.mark.parametrize("wrong_source", [False, True])
@pytest.mark.parametrize("capture", [False, True])
@pytest.mark.parametrize("visible_key", [False, True])
def test_about_identity_requires_rendered_package_values_and_closes_details(tmp_path, wrong_source, capture, visible_key):
    expected = {"version": "0.1.0-beta.2", "channel": "nightly", "platform": "arm64",
                "build": "release", "sourceRevision": "a" * 40}
    labels = {"Version": "version", "Channel": "channel", "Architecture": "platform",
              "Build": "build", "Source commit": "sourceRevision"}
    clicks = []
    navigation = []
    image = tmp_path / "public.png" if capture else None

    class Field:
        def __init__(self, label):
            self.key = labels[label]

        def locator(self, selector):
            assert selector == "xpath=following-sibling::dd[1]"
            return self

        def wait_for(self, *, state):
            assert state == "visible"

        def inner_text(self):
            return "b" * 40 if wrong_source and self.key == "sourceRevision" else expected[self.key]

    class Details:
        def locator(self, selector):
            assert selector == "summary"
            return self

        def click(self):
            clicks.append("toggle")

        def get_by_text(self, label, *, exact):
            assert exact
            return Field(label)

    class Page:
        def get_by_label(self, label, *, exact):
            assert label == "About this build" and exact
            return Details()

        def set_viewport_size(self, viewport):
            assert viewport == {"width": 1280, "height": 720}

        def get_by_role(self, role, *, name, exact):
            assert exact and name == "Search" and role in {"link", "heading"}
            class Navigation:
                def count(self):
                    return 1

                def click(self, **kwargs):
                    navigation.append(name)

                def wait_for(self, **kwargs):
                    assert kwargs == {"state": "visible"}
            return Navigation()

        def get_by_placeholder(self, placeholder):
            assert placeholder == "X-API-Key"
            class Key:
                def is_visible(self):
                    return visible_key
            return Key()

        def screenshot(self, **kwargs):
            assert kwargs == {"path": str(image), "type": "png", "full_page": False,
                              "animations": "disabled", "caret": "hide"}
            image.write_bytes(b"synthetic screenshot bytes")

    if capture and visible_key:
        with pytest.raises(RuntimeError, match="authentication form"):
            rust_webui_live_proof.verify_about_build_identity(Page(), expected, public_capture_path=image)
    elif wrong_source:
        with pytest.raises(RuntimeError, match="Rendered About build identity"):
            rust_webui_live_proof.verify_about_build_identity(Page(), expected, public_capture_path=image)
    else:
        assert rust_webui_live_proof.verify_about_build_identity(Page(), expected, public_capture_path=image) == expected
    assert clicks == ([] if capture and visible_key else ["toggle", "toggle"])
    assert navigation == (["Search"] if capture else [])
    assert (tmp_path / "public.png").exists() == (capture and not visible_key and not wrong_source)


def test_generic_live_proof_cannot_enable_public_capture_without_package_identity(tmp_path):
    with pytest.raises(ValueError, match="strict synthetic native-package proof"):
        rust_webui_live_proof.run_webui_live_proof(
            base_url="http://127.0.0.1:1234", api_key="synthetic", report_path=tmp_path / "report.json",
            steady_seconds=1, tab_wait_seconds=0.1, timeout_seconds=1, max_main_thread_busy_ratio=1,
            public_capture_path=tmp_path / "public.png")
    assert not (tmp_path / "public.png").exists()


def test_browser_api_key_scripts_use_tab_scoped_storage() -> None:
    write_script = rust_webui_live_proof.browser_api_key_write_script('stale "key"')
    read_script = rust_webui_live_proof.browser_api_key_read_script()

    assert write_script == (
        'sessionStorage.setItem("emulebb.webui.apiKey", "stale \\"key\\"");'
    )
    assert read_script == '() => sessionStorage.getItem("emulebb.webui.apiKey")'
    assert "localStorage" not in write_script
    assert "localStorage" not in read_script


@pytest.mark.parametrize("failure", [None, "automatic", "cancel", "body", "size", "hash", "duplicate", "cleanup", "body-cleanup",
    "creation-200", "creation-id", "creation-hash"])
def test_file_link_confirmation_requires_real_request_shape_and_persisted_hash_size(monkeypatch, failure):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from urllib.parse import parse_qs, urlparse
    from emule_test_harness import rust_local_ed2k

    file_hash = "00112233445566778899aabbccddeeff"
    link = f"ed2k://|file|Android%20Intent%20Sample.bin|1|{file_hash}|/"
    baseline = [{"id": "7", "hash": "b" * 32, "sizeBytes": 262144, "state": "completed"}]
    items = list(baseline)
    calls, removals = [], []
    cleanup = {}

    class Page:
        authenticated = False
        value = ""
        observer = None
        confirmed = False

        def on(self, event, callback):
            assert event == "request"
            self.observer = callback

        def remove_listener(self, event, callback):
            assert event == "request" and callback is self.observer
            self.observer = None

        def post(self):
            body = {"source": {"type": "ed2k-link", "link": link}, "intent": "stopped"}
            if failure in {"body", "body-cleanup"}:
                body = {"source": {"type": "ed2k-link"}, "intent": "stopped"}
            self.observer(SimpleNamespace(method="POST", url="http://127.0.0.1:1234/api/v1/downloads",
                                          post_data_json=body))
            items.append({"id": "8", "hash": "c" * 32 if failure == "hash" else file_hash,
                          "sizeBytes": 2 if failure == "size" else 1, "intent": "stopped"})

        def goto(self, url, **kwargs):
            self.value = parse_qs(urlparse(url).fragment)["ed2k"][0]
            if failure == "automatic" or failure == "duplicate" and self.confirmed:
                self.post()

        def get_by_role(self, role, *, name, **kwargs):
            return self.control(name)

        def get_by_placeholder(self, name):
            assert name == "X-API-Key"
            return self.control("key")

        def get_by_label(self, name, **kwargs):
            assert name in {"eD2K links", "Stopped"}
            return self.control(name)

        def control(self, name):
            def click(**kwargs):
                calls.append(name)
                if name == "Connect":
                    self.authenticated = True
                elif name == "Cancel links":
                    self.value = ""
                    if failure == "cancel":
                        self.post()
                elif name == "Add links":
                    assert self.authenticated
                    self.confirmed = True
                    self.post()
            return SimpleNamespace(wait_for=lambda **kwargs: None, input_value=lambda: self.value,
                                   fill=lambda value: None, check=lambda **kwargs: None, click=click)

        def wait_for_function(self, value, **kwargs):
            assert value == "location.hash === ''"

        def wait_for_timeout(self, duration):
            assert duration == 1000

        @contextmanager
        def expect_response(self, predicate, **kwargs):
            response = SimpleNamespace(ok=True, status=200 if failure == "creation-200" else 201,
                                       request=SimpleNamespace(method="POST"),
                                       url="http://127.0.0.1:1234/api/v1/downloads",
                                       json=lambda: {"data": {"id": "0" if failure == "creation-id" else "8",
                                           "hash": "c" * 32 if failure == "creation-hash" else file_hash, "sizeBytes": 1}})
            assert predicate(response)
            yield SimpleNamespace(value=response)

    monkeypatch.setattr(rust_webui_live_proof, "api_document", lambda *args: {
        "data": list(items), "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}})

    def wait(description, timeout_seconds, probe):
        result = probe()
        if result is None:
            raise RuntimeError("confirmed file-link transfer was not persisted")
        return result

    def delete(base, method, path, key, body, *, expected_status):
        removals.append(body)
        assert method == "POST" and path == "/api/v1/downloads/remove"
        assert expected_status == 207
        assert body == {"ids": ["8"], "deleteData": True}
        if failure in {"cleanup", "body-cleanup"}:
            raise ValueError("synthetic-private-key-not-for-receipts")
        items[:] = [item for item in items if item["id"] != "8"]
        return {"data": [{"id": "8", "status": "accepted", "httpStatus": 200}]}

    monkeypatch.setattr(rust_webui_live_proof, "_wait_for_api", wait)
    monkeypatch.setattr(rust_local_ed2k, "request_json", delete)
    kwargs = dict(base_url="http://127.0.0.1:1234", api_key="synthetic-private-key-not-for-receipts",
                  link=link, file_hash=file_hash, size_bytes=1, cleanup_evidence=cleanup)
    if failure:
        with pytest.raises(RuntimeError, match={"automatic": "before authentication", "cancel": "cancellation",
            "body": "exact requested", "body-cleanup": "exact requested", "size": "not persisted", "hash": "not persisted",
            "duplicate": "automatically changed",
            "cleanup": "cleanup failed", "creation-200": "exact requested",
            "creation-id": "exact requested", "creation-hash": "exact requested"}[failure]):
            rust_webui_live_proof.file_link_confirmation(Page(), **kwargs)
    else:
        result = rust_webui_live_proof.file_link_confirmation(Page(), **kwargs)
        assert result["status"] == "passed" and result["downloadId"] == "8" and result["sizeBytes"] == 1
        from emule_test_harness.android_apk_lifecycle import FILE_LINK_BROWSER_REQUIRED_CHECKS
        assert FILE_LINK_BROWSER_REQUIRED_CHECKS == frozenset({
            "signInPreserved", "cancelWithoutEnqueue", "explicitConfirmation", "repeatedNavigationWithoutEnqueue"})
        assert all(result[name] is True for name in FILE_LINK_BROWSER_REQUIRED_CHECKS)
        assert calls == ["Connect", "Cancel links", "Add links", "Cancel links"]
    assert cleanup["status"] == ("failed" if failure in {"automatic", "cancel", "duplicate", "body", "cleanup", "body-cleanup",
        "creation-200", "creation-id", "creation-hash"} else "passed")
    if failure in {"automatic", "cancel", "body", "body-cleanup", "creation-200", "creation-id", "creation-hash"}:
        assert removals == [], "an unreceipted enqueue must not grant deletion authority"
    if failure not in {"automatic", "cancel", "duplicate", "body", "cleanup", "body-cleanup",
            "creation-200", "creation-id", "creation-hash"}:
        assert items == baseline


def test_file_link_browser_failure_receipt_never_contains_credentials(tmp_path, monkeypatch):
    import json
    import sys
    from types import SimpleNamespace

    key = "synthetic-private-key-not-for-receipts"
    identity = {"sourceRevision": "a" * 40, "version": "0.1.0-test", "channel": "development"}

    def fail():
        raise ValueError(key)

    monkeypatch.setitem(sys.modules, "playwright", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(sync_playwright=fail))
    monkeypatch.setattr(rust_webui_live_proof, "api_data", lambda *args: identity)
    report = tmp_path / "browser.json"
    with pytest.raises(RuntimeError, match="confirmation proof failed") as error:
        rust_webui_live_proof.run_file_link_browser_proof(base_url="http://127.0.0.1:1234", api_key=key,
            link="ed2k://|file|Sample.bin|1|" + "b" * 32 + "|/", file_hash="b" * 32, size_bytes=1,
            report_path=report, identity=identity)
    assert key not in report.read_text() and key not in str(error.value)
    assert json.loads(report.read_text())["errorType"] == "ValueError"


@pytest.mark.parametrize("installed", [False, True])
def test_file_link_browser_preflight_requires_offline_browser_bytes(tmp_path, monkeypatch, installed):
    from contextlib import contextmanager
    import sys
    from types import SimpleNamespace

    executable = tmp_path / "chromium"
    if installed:
        executable.write_bytes(b"synthetic browser executable")

    @contextmanager
    def playwright():
        yield SimpleNamespace(chromium=SimpleNamespace(executable_path=str(executable)))

    monkeypatch.setitem(sys.modules, "playwright", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "playwright.sync_api", SimpleNamespace(sync_playwright=playwright))
    if installed:
        rust_webui_live_proof.require_file_link_browser()
    else:
        with pytest.raises(RuntimeError, match="installed offline Playwright/Chromium"):
            rust_webui_live_proof.require_file_link_browser()


def test_select_filtered_live_pdf_enforces_safe_shape_and_prefers_sources() -> None:
    selected = rust_webui_live_proof.select_filtered_live_pdf(
        [
            {"name": "manual.pdf", "hash": "a" * 32, "sizeBytes": 4096, "sources": 2},
            {"name": "popular.PDF", "hash": "b" * 32, "sizeBytes": 2048, "sources": 4},
            {"name": "too-large.pdf", "hash": "c" * 32, "sizeBytes": 5001, "sources": 99},
            {"name": "archive.zip", "hash": "d" * 32, "sizeBytes": 1024, "sources": 99},
            {"name": "..\\unsafe.pdf", "hash": "e" * 32, "sizeBytes": 1024, "sources": 99},
            {"name": "no-sources.pdf", "hash": "f" * 32, "sizeBytes": 1024, "sources": 0},
        ],
        5000,
    )

    assert selected == {
        "name": "popular.PDF",
        "hash": "b" * 32,
        "sizeBytes": 2048,
        "sources": 4,
    }


def test_matched_shared_catalog_requires_exact_fixture_identity() -> None:
    fixtures = (
        rust_webui_live_proof.ConsumerSharedFixture(
            name="root.txt",
            relative_path="root.txt",
            size_bytes=32,
            sha256="1" * 64,
        ),
        rust_webui_live_proof.ConsumerSharedFixture(
            name="nested.bin",
            relative_path="nested/nested.bin",
            size_bytes=64,
            sha256="2" * 64,
        ),
    )
    matched = rust_webui_live_proof._matched_shared_catalog(
        [
                {
                    "displayName": "nested.bin",
                    "sizeBytes": 64,
                    "hash": "b" * 32,
                },
                {
                    "displayName": "root.txt",
                    "sizeBytes": 32,
                    "hash": "a" * 32,
                },
        ],
        fixtures,
        lambda file_hash: {"hash": file_hash, "ed2kLink": "ed2k://|file|fixture|1|" + file_hash + "|/"},
    )

    assert matched == [
        {
            "name": "nested.bin",
            "relativePath": "nested/nested.bin",
            "sizeBytes": 64,
            "sha256": "2" * 64,
            "ed2kHash": "b" * 32,
        },
        {
            "name": "root.txt",
            "relativePath": "root.txt",
            "sizeBytes": 32,
            "sha256": "1" * 64,
            "ed2kHash": "a" * 32,
        },
    ]
    assert rust_webui_live_proof._matched_shared_catalog(
        [{"displayName": "root.txt", "sizeBytes": 31}], fixtures,
        lambda _file_hash: pytest.fail("incomplete collection must not request details"),
    ) is None


def test_consumer_nat_status_requires_both_default_mappings(monkeypatch) -> None:
    monkeypatch.setattr(
        rust_webui_live_proof,
        "api_data",
        lambda *_args: {
            "enabled": True,
            "gatewayDiscovered": True,
            "backend": "upnp",
            "lastError": None,
            "mappings": [
                {"name": "ed2k_tcp", "protocol": "tcp", "localAddr": "192.0.2.1:20019"},
                {"name": "kad_udp", "protocol": "udp", "localAddr": "192.0.2.1:20020"},
            ],
        },
    )

    status = rust_webui_live_proof._consumer_nat_status("http://127.0.0.1", "key")

    assert status["ready"] is True
    assert status["requiredMappings"] == ["tcp:20019", "udp:20020"]
    assert status["mappingNames"] == ["ed2k_tcp", "kad_udp"]


def test_request_recorder_counts_only_same_origin_api_and_static_assets() -> None:
    recorder = rust_webui_live_proof.RequestRecorder("http://192.0.2.10:4731/")

    recorder.record_url("http://192.0.2.10:4731/api/v1/snapshot?limit=500")
    recorder.record_url("http://192.0.2.10:4731/api/v1/logs?limit=300")
    recorder.record_url("http://192.0.2.10:4731/api/v1/downloads/12/sources")
    recorder.record_url("http://192.0.2.10:4731/assets/index-test.js")
    recorder.record_url("http://example.invalid/api/v1/snapshot?limit=500")

    assert recorder.snapshot()["apiCounts"] == {
        "logs?limit=300": 1,
        "snapshot?limit=500": 1,
        "downloads/{id}/sources": 1,
    }
    assert recorder.snapshot()["staticAssets"] == {"/assets/index-test.js": 1}


@pytest.mark.parametrize("meta", [
    {"apiVersion": "v1", "hasMore": False},
    {"apiVersion": "v1", "hasMore": True, "nextCursor": "next"},
    {"apiVersion": "v1", "hasMore": False, "nextCursor": "next"},
])
def test_webui_download_inventory_requires_a_complete_native_page(monkeypatch, meta):
    monkeypatch.setattr(rust_webui_live_proof, "api_document", lambda *_args: {"data": [], "meta": meta})
    with pytest.raises(RuntimeError, match="complete bounded download page"):
        rust_webui_live_proof._download_rows("http://127.0.0.1:1234", "key")


def test_steady_request_load_allows_snapshot_and_bounded_download_preview() -> None:
    check = rust_webui_live_proof.steady_request_load_check(
        {
            "snapshot?limit=500": 6,
            "downloads?view=all&limit=12": 6,
            "app": 1,
            "capabilities": 1,
        }
    )

    assert check == {"ok": True, "repeatedSecondaryEndpoints": {}}


def test_steady_request_load_rejects_broad_secondary_polling() -> None:
    check = rust_webui_live_proof.steady_request_load_check(
        {
            "snapshot?limit=500": 6,
            "logs?limit=300": 6,
            "library/files?limit=200": 6,
            "uploads": 6,
            "downloads?view=all&limit=200": 6,
            "downloads?view=all&limit=12&cursor=sample": 6,
        }
    )

    assert check == {
        "ok": False,
        "repeatedSecondaryEndpoints": {
            "logs?limit=300": 6,
            "library/files?limit=200": 6,
            "uploads": 6,
            "downloads?view=all&limit=200": 6,
            "downloads?view=all&limit=12&cursor=sample": 6,
        },
    }


def test_transfer_workflow_check_requires_completed_full_progress_row() -> None:
    check = rust_webui_live_proof.transfer_workflow_check_from_cells(
        [
            {"state": "downloading", "progress": "38.3%"},
            {"state": "completed", "progress": "100.0%"},
        ],
        False,
    )

    assert check == {
        "ok": True,
        "rowCount": 2,
        "activeProgressRowCount": 1,
        "completedRowCount": 1,
        "completedFullProgressRowCount": 1,
        "emptyVisible": False,
    }


def test_transfer_workflow_check_rejects_fraction_rendered_as_percent() -> None:
    check = rust_webui_live_proof.transfer_workflow_check_from_cells(
        [{"state": "completed", "progress": "1.0%"}],
        False,
    )

    assert check == {
        "ok": False,
        "rowCount": 1,
        "activeProgressRowCount": 0,
        "completedRowCount": 1,
        "completedFullProgressRowCount": 0,
        "emptyVisible": False,
    }


def test_transfer_workflow_check_accepts_visible_download_progress() -> None:
    check = rust_webui_live_proof.transfer_workflow_check_from_cells(
        [
            {"state": "downloading", "progress": "0.0%"},
            {"state": "downloading", "progress": "94.9%"},
        ],
        False,
    )

    assert check == {
        "ok": True,
        "rowCount": 2,
        "activeProgressRowCount": 1,
        "completedRowCount": 0,
        "completedFullProgressRowCount": 0,
        "emptyVisible": False,
    }


def test_browser_performance_check_accepts_low_idle_main_thread_work() -> None:
    before = rust_webui_live_proof.performance_metric_map(
        {
            "metrics": [
                {"name": "TaskDuration", "value": 10.0},
                {"name": "ScriptDuration", "value": 2.0},
                {"name": "JSHeapUsedSize", "value": 1000},
            ]
        }
    )
    after = rust_webui_live_proof.performance_metric_map(
        {
            "metrics": [
                {"name": "TaskDuration", "value": 10.5},
                {"name": "ScriptDuration", "value": 2.1},
                {"name": "JSHeapUsedSize", "value": 1200},
            ]
        }
    )

    check = rust_webui_live_proof.browser_performance_check(
        before,
        after,
        elapsed_seconds=10.0,
        max_main_thread_busy_ratio=0.25,
    )

    assert check == {
        "ok": True,
        "missing": [],
        "elapsedSeconds": 10.0,
        "maxMainThreadBusyRatio": 0.25,
        "mainThreadBusyRatio": 0.05,
        "durationDeltas": {
            "TaskDuration": 0.5,
            "ScriptDuration": 0.1,
        },
        "absoluteAfter": {"JSHeapUsedSize": 1200},
    }


def test_browser_performance_check_rejects_busy_idle_main_thread() -> None:
    check = rust_webui_live_proof.browser_performance_check(
        {"TaskDuration": 10.0},
        {"TaskDuration": 14.0},
        elapsed_seconds=10.0,
        max_main_thread_busy_ratio=0.25,
    )

    assert check["ok"] is False
    assert check["mainThreadBusyRatio"] == 0.4


def test_browser_performance_check_requires_task_duration() -> None:
    check = rust_webui_live_proof.browser_performance_check(
        {},
        {},
        elapsed_seconds=10.0,
        max_main_thread_busy_ratio=0.25,
    )

    assert check["ok"] is False
    assert check["missing"] == ["TaskDuration"]


def test_parser_defaults_to_persisted_rust_webui() -> None:
    args = rust_webui_live_proof.build_parser().parse_args([])

    assert args.api_key == "converged-soak"
    assert args.max_main_thread_busy_ratio == 0.25
    assert args.navigation_only is False
    assert args.verify_stale_key_recovery is False
    assert str(args.report_path).endswith("reports\\rust-webui-live-proof\\rust-webui-live-proof.latest.json")


def test_parser_can_limit_live_proof_to_navigation() -> None:
    args = rust_webui_live_proof.build_parser().parse_args(["--navigation-only"])

    assert args.navigation_only is True


def test_parser_can_verify_stale_key_recovery() -> None:
    args = rust_webui_live_proof.build_parser().parse_args(["--verify-stale-key-recovery"])

    assert args.verify_stale_key_recovery is True


def test_profile_settings_api_key_reads_generated_secret(tmp_path) -> None:
    settings = tmp_path / "emulebb-rust-settings.toml"
    settings.write_text('[rest]\napi_key = "generated-key"\n', encoding="utf-8")

    assert rust_webui_live_proof.profile_settings_api_key(settings) == "generated-key"


def test_profile_settings_api_key_requires_a_string(tmp_path) -> None:
    settings = tmp_path / "emulebb-rust-settings.toml"
    settings.write_text('[rest]\napi_key = 42\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="REST API key is missing"):
        rust_webui_live_proof.profile_settings_api_key(settings)


@pytest.fixture
def native_settings_form():
    values = {"enabled": True, "limit": 123, "path": "sample", "list": ["one", "two"], "optional": None}
    fields = [{"key": "sample." + key} for key in values]
    snapshot = {"meta": {"settingsRevision": "9007199254740993"}, "data": {"saved": {"sample": {
        key: {"mode": "default" if key == "enabled" else "custom", "value": value}
        for key, value in values.items()}}}}
    rows = [{"key": "sample." + key, "default": key == "enabled", "unset": value is None,
             "text": "" if value is None else "\n".join(value) if isinstance(value, list)
             else str(value).lower() if isinstance(value, bool) else str(value)} for key, value in values.items()]
    return {"fields": fields}, snapshot, rows


def test_native_settings_form_requires_all_emitted_fields_and_saved_modes(native_settings_form):
    surface, snapshot, rows = native_settings_form
    assert rust_webui_live_proof._settings_form_check(surface, snapshot, list(reversed(rows))) == {
        "ok": True, "fieldCount": 5, "defaultCount": 1}


@pytest.mark.parametrize("fault", ["missing", "duplicate", "unexpected", "mode", "value", "null", "revision"])
def test_native_settings_form_rejects_incomplete_or_incorrect_rendering(native_settings_form, fault):
    surface, snapshot, rows = native_settings_form
    if fault == "missing":
        rows.pop()
    elif fault == "duplicate":
        rows.append(dict(rows[0]))
    elif fault == "unexpected":
        rows[0]["key"] = "sample.other"
    elif fault == "mode":
        rows[0]["default"] = False
    elif fault == "value":
        rows[1]["text"] = "124"
    elif fault == "null":
        rows[-1]["unset"] = False
    else:
        snapshot["meta"]["settingsRevision"] = 123
    with pytest.raises(RuntimeError):
        rust_webui_live_proof._settings_form_check(surface, snapshot, rows)


@pytest.mark.parametrize("fault", [None, "conflict", "duplicate", "wrong_body", "unchanged_revision"])
def test_native_settings_save_requires_one_confirmed_owned_write(fault):
    from types import SimpleNamespace

    body = {"expectedRevision": "9007199254740993", "reset": ["sample.limit"]}
    writes = []
    response = SimpleNamespace(status=409 if fault == "conflict" else 200,
                               request=SimpleNamespace(method="PATCH"),
                               url="http://127.0.0.1/api/v1/settings",
                               json=lambda: {"meta": {"settingsRevision": "9007199254740993"
                                             if fault == "unchanged_revision" else "9007199254740994"}})

    class Observed:
        value = response

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Page:
        listener = None

        def on(self, event, callback):
            assert event == "request"
            self.listener = callback

        def remove_listener(self, event, callback):
            assert event == "request" and self.listener == callback
            self.listener = None

        def expect_response(self, predicate, *, timeout):
            assert predicate(response) and timeout == 1000
            return Observed()

        def get_by_role(self, role, *, name, exact):
            assert (role, name, exact) == ("button", "Save", True)
            return self

        def click(self):
            writes.append("click")
            request = SimpleNamespace(method="PATCH", url=response.url,
                                      post_data_json={} if fault == "wrong_body" else body)
            self.listener(request)
            if fault == "duplicate":
                self.listener(request)

    page = Page()
    if fault is None:
        assert rust_webui_live_proof._save_settings_form(page, body, 1) == response.json()
    else:
        with pytest.raises(RuntimeError):
            rust_webui_live_proof._save_settings_form(page, body, 1)
    assert writes == ["click"]
    assert page.listener is None


@pytest.fixture
def browser_network_settings(monkeypatch):
    snapshot = {"meta": {"settingsRevision": "17"}, "data": {
        "saved": {"network": {"autoConnect": {"mode": "default", "value": True}, "nat": {
            "enabled": {"mode": "default", "value": True},
            "requireInitialMapping": {"mode": "default", "value": False}}}},
        "effective": {"network": {"autoConnect": True, "nat": {"enabled": True, "requireInitialMapping": False}}},
        "application": {"pendingRestart": [], "failed": []}}}
    monkeypatch.setattr(rust_webui_live_proof, "_read_settings_form", lambda *args, **kwargs: ({}, snapshot, {}))
    monkeypatch.setattr(rust_webui_live_proof, "_wait_for_settings_form", lambda *args: {"ok": True})
    return snapshot


@pytest.mark.parametrize("fault", [None, "custom", "pending", "failure", "effective"])
def test_zero_configuration_checks_saved_defaults_and_running_state(browser_network_settings, fault):
    snapshot = browser_network_settings
    if fault == "custom":
        snapshot["data"]["saved"]["network"]["autoConnect"]["mode"] = "custom"
    elif fault == "pending":
        snapshot["data"]["application"]["pendingRestart"] = ["network.autoConnect"]
    elif fault == "failure":
        snapshot["data"]["application"]["failed"] = [{"key": "network.autoConnect"}]
    elif fault == "effective":
        snapshot["data"]["effective"]["network"]["autoConnect"] = False
    if fault:
        with pytest.raises(RuntimeError):
            rust_webui_live_proof._assert_zero_configuration_defaults(None, base_url="local", api_key="key", timeout_seconds=1)
    else:
        assert rust_webui_live_proof._assert_zero_configuration_defaults(
            None, base_url="local", api_key="key", timeout_seconds=1) == {
                "autoConnect": True, "upnpEnabled": True, "requireInitialMapping": False,
                "verifiedThroughRenderedWebui": True}


@pytest.mark.parametrize("changed", [(), ("enabled",), ("enabled", "requireInitialMapping")])
@pytest.mark.parametrize("outcome", ["applied", "restart", "failure", "uncertain"])
def test_nat_form_saves_only_changed_values_once_and_reports_application(
        monkeypatch, browser_network_settings, changed, outcome):
    snapshot = browser_network_settings
    for name in changed:
        leaf = snapshot["data"]["saved"]["network"]["nat"][name]
        leaf.update(mode="custom", value=not leaf["value"])
    if outcome == "restart":
        snapshot["data"]["application"]["pendingRestart"] = ["network.nat.enabled"]
    elif outcome == "failure":
        snapshot["data"]["application"]["failed"] = [{"key": "network.nat.enabled"}]
    controls, writes = [], []

    class Editor:
        def __init__(self, key):
            self.key = key

        def locator(self, selector):
            return self

        @property
        def last(self):
            return self

        def uncheck(self):
            controls.append((self.key, "custom"))

        def set_checked(self, value):
            controls.append((self.key, value))

    def save(_page, body, timeout):
        writes.append(body)
        if outcome == "uncertain":
            raise RuntimeError("unconfirmed response")
        for name, value in body["set"]["network"]["nat"].items():
            snapshot["data"]["saved"]["network"]["nat"][name] = {"mode": "default", "value": value}
        return snapshot

    monkeypatch.setattr(rust_webui_live_proof, "_settings_editor", lambda page, key: Editor(key))
    monkeypatch.setattr(rust_webui_live_proof, "_save_settings_form", save)
    if outcome == "failure" or (outcome == "uncertain" and changed):
        with pytest.raises(RuntimeError):
            rust_webui_live_proof._configure_best_effort_upnp(None, base_url="local", api_key="key", timeout_seconds=1)
    else:
        assert rust_webui_live_proof._configure_best_effort_upnp(
            None, base_url="local", api_key="key", timeout_seconds=1) == {
                "enabled": True, "requireInitialMapping": False,
                "restartRequired": outcome == "restart", "writes": int(bool(changed)),
                "configuredThroughRenderedWebui": True}
    assert len(writes) == int(bool(changed))
    assert len(controls) == 2 * len(changed)
    if changed:
        assert writes == [{"expectedRevision": "17", "set": {"network": {"nat": {
            name: name == "enabled" for name in changed}}}}]


def test_sanitize_report_text_applies_runtime_redactions() -> None:
    text = rust_webui_live_proof.sanitize_report_text(
        "linux private.iso ABCDEF0123456789ABCDEF0123456789 C:\\profile\\file",
        ("linux", "private.iso"),
    )

    assert text == "{redacted} {redacted} {hash} {path}"


@pytest.mark.parametrize("counts", [{}, {"totalEntries": 1, "publishedEntries": 0},
    {"totalEntries": 0, "publishedEntries": 1}, {"totalEntries": False, "publishedEntries": 0}])
def test_sharing_publication_proof_requires_a_known_empty_baseline(counts):
    with pytest.raises(RuntimeError, match="empty baseline"):
        rust_webui_live_proof._require_empty_ed2k_catalog(counts)


@pytest.mark.parametrize("success", [0, 1_800_000_000])
def test_fresh_catalog_publication_is_proven_without_a_later_clock_tick(success):
    baseline = {"totalEntries": 0, "publishedEntries": 0, "lastSuccessAt": success}
    rust_webui_live_proof._require_empty_ed2k_catalog(baseline)
    current = {"totalEntries": 3, "publishedEntries": 3, "pendingEntries": 0,
               "lastError": None, "lastSuccessAt": success}
    assert rust_webui_live_proof._ed2k_fixture_published(current, 3)


@pytest.mark.parametrize("changes", [{"totalEntries": 4}, {"publishedEntries": 2},
    {"pendingEntries": 1}, {"lastSuccessAt": None}, {"lastSuccessAt": True},
    {"lastError": "synthetic failure"}])
def test_catalog_publication_requires_complete_successful_fixture_outcomes(changes):
    current = {"totalEntries": 3, "publishedEntries": 3, "pendingEntries": 0,
               "lastError": None, "lastSuccessAt": 10, **changes}
    assert not rust_webui_live_proof._ed2k_fixture_published(current, 3)
