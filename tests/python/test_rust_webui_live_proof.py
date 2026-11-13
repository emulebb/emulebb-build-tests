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


@pytest.mark.parametrize("failure", [None, "automatic", "cancel", "body", "size", "hash", "duplicate", "cleanup", "body-cleanup"])
def test_file_link_confirmation_requires_real_request_shape_and_persisted_hash_size(monkeypatch, failure):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from urllib.parse import parse_qs, urlparse
    from emule_test_harness import rust_local_ed2k

    file_hash = "00112233445566778899aabbccddeeff"
    link = f"ed2k://|file|Android%20Intent%20Sample.bin|1|{file_hash}|/"
    baseline = [{"hash": "b" * 32, "sizeBytes": 262144, "state": "completed"}]
    items = list(baseline)
    calls = []
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
            body = {"links": [link], "paused": True, "knownFilePolicy": "reject"}
            if failure in {"body", "body-cleanup"}:
                body = {"link": link, "paused": True}
            self.observer(SimpleNamespace(method="POST", url="http://127.0.0.1:1234/api/v1/transfers",
                                          post_data_json=body))
            items.append({"hash": "c" * 32 if failure == "hash" else file_hash,
                          "sizeBytes": 2 if failure == "size" else 1, "state": "paused"})

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
            assert name in {"eD2K links", "Paused"}
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
            response = SimpleNamespace(ok=True, request=SimpleNamespace(method="POST"),
                                       url="http://127.0.0.1:1234/api/v1/transfers")
            assert predicate(response)
            yield SimpleNamespace(value=response)

    monkeypatch.setattr(rust_webui_live_proof, "api_data", lambda *args: {"items": list(items)})

    def wait(description, timeout_seconds, probe):
        result = probe()
        if result is None:
            raise RuntimeError("confirmed file-link transfer was not persisted")
        return result

    def delete(base, method, path, key):
        assert method == "DELETE" and path == f"/api/v1/transfers/{file_hash}/files?confirm=true"
        if failure in {"cleanup", "body-cleanup"}:
            raise ValueError("synthetic-private-key-not-for-receipts")
        items[:] = [item for item in items if item["hash"] != file_hash]

    monkeypatch.setattr(rust_webui_live_proof, "_wait_for_api", wait)
    monkeypatch.setattr(rust_local_ed2k, "request_json", delete)
    kwargs = dict(base_url="http://127.0.0.1:1234", api_key="synthetic-private-key-not-for-receipts",
                  link=link, file_hash=file_hash, size_bytes=1, cleanup_evidence=cleanup)
    if failure:
        with pytest.raises(RuntimeError, match={"automatic": "before authentication", "cancel": "cancellation",
            "body": "exact requested", "body-cleanup": "exact requested", "size": "not persisted", "hash": "not persisted",
            "duplicate": "automatically changed",
            "cleanup": "cleanup failed"}[failure]):
            rust_webui_live_proof.file_link_confirmation(Page(), **kwargs)
    else:
        result = rust_webui_live_proof.file_link_confirmation(Page(), **kwargs)
        assert result["status"] == "passed" and result["transferHash"] == file_hash and result["sizeBytes"] == 1
        from emule_test_harness.android_apk_lifecycle import FILE_LINK_BROWSER_REQUIRED_CHECKS
        assert FILE_LINK_BROWSER_REQUIRED_CHECKS == frozenset({
            "signInPreserved", "cancelWithoutEnqueue", "explicitConfirmation", "repeatedNavigationWithoutEnqueue"})
        assert all(result[name] is True for name in FILE_LINK_BROWSER_REQUIRED_CHECKS)
        assert calls == ["Connect", "Cancel links", "Add links", "Cancel links"]
    assert cleanup["status"] == ("failed" if failure in {"cleanup", "body-cleanup", "hash"} else "passed")
    if failure not in {"cleanup", "body-cleanup", "hash"}:
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
        {
            "items": [
                {
                    "name": "nested.bin",
                    "sizeBytes": 64,
                    "hash": "b" * 32,
                    "ed2kLink": "ed2k://|file|nested.bin|64|" + "b" * 32 + "|/",
                },
                {
                    "name": "root.txt",
                    "sizeBytes": 32,
                    "hash": "a" * 32,
                    "ed2kLink": "ed2k://|file|root.txt|32|" + "a" * 32 + "|/",
                },
            ]
        },
        fixtures,
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
        {"items": [{"name": "root.txt", "sizeBytes": 31}]}, fixtures
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
    recorder.record_url("http://192.0.2.10:4731/api/v1/transfers/abcdef0123456789abcdef0123456789/sources")
    recorder.record_url("http://192.0.2.10:4731/assets/index-test.js")
    recorder.record_url("http://example.invalid/api/v1/snapshot?limit=500")

    assert recorder.snapshot()["apiCounts"] == {
        "logs?limit=300": 1,
        "snapshot?limit=500": 1,
        "transfers/{hash}/sources": 1,
    }
    assert recorder.snapshot()["staticAssets"] == {"/assets/index-test.js": 1}


def test_steady_request_load_allows_snapshot_polling_only() -> None:
    check = rust_webui_live_proof.steady_request_load_check(
        {
            "snapshot?limit=500": 6,
            "app": 1,
            "capabilities": 1,
        }
    )

    assert check == {"ok": True, "repeatedSecondaryEndpoints": {}}


def test_steady_request_load_rejects_stale_bundle_secondary_polling() -> None:
    check = rust_webui_live_proof.steady_request_load_check(
        {
            "snapshot?limit=500": 6,
            "logs?limit=300": 6,
            "shared-files?limit=500": 6,
            "uploads": 6,
        }
    )

    assert check == {
        "ok": False,
        "repeatedSecondaryEndpoints": {
            "logs?limit=300": 6,
            "shared-files?limit=500": 6,
            "uploads": 6,
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


def test_profile_settings_api_key_rejects_retired_bootstrap_spelling(tmp_path) -> None:
    settings = tmp_path / "emulebb-rust-settings.toml"
    settings.write_text('[rest]\napiKey = "synthetic-retired-key"\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="REST API key is missing"):
        rust_webui_live_proof.profile_settings_api_key(settings)


def test_sanitize_report_text_applies_runtime_redactions() -> None:
    text = rust_webui_live_proof.sanitize_report_text(
        "linux private.iso ABCDEF0123456789ABCDEF0123456789 C:\\profile\\file",
        ("linux", "private.iso"),
    )

    assert text == "{redacted} {redacted} {hash} {path}"
