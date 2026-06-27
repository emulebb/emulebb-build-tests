from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "export-mfc-shared-files-inventory.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("export_mfc_shared_files_inventory", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_export_inventory_pages_shared_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _load_script()
    calls: list[str] = []

    def fake_request_json(base_url: str, path: str, api_key: str, *, timeout_seconds: float) -> dict[str, object]:
        calls.append(path)
        assert base_url == "http://mfc"
        assert api_key == "key"
        assert timeout_seconds == 9.0
        if "offset=0" in path:
            return {"data": {"items": [{"hash": "a" * 32, "path": "C:/one", "sizeBytes": 1}], "total": 2}}
        return {"data": {"items": [{"hash": "b" * 32, "path": "C:/two", "sizeBytes": 2}], "total": 2}}

    monkeypatch.setattr(script, "request_json", fake_request_json)
    output = tmp_path / "inventory.json"

    result = script.export_inventory(
        base_url="http://mfc",
        api_key="key",
        output_path=output,
        page_size=1,
        timeout_seconds=9.0,
        sleep_seconds=0.0,
    )

    assert calls == [
        "/api/v1/shared-files?offset=0&limit=1",
        "/api/v1/shared-files?offset=1&limit=1",
    ]
    assert result == {"outputPath": str(output), "total": 2, "count": 2}
    artifact = json.loads(output.read_text(encoding="utf-8"))
    assert artifact["schema"] == "mfc_shared_files_inventory_v1"
    assert artifact["total"] == 2
    assert artifact["count"] == 2
    assert [row["hash"] for row in artifact["items"]] == ["a" * 32, "b" * 32]
