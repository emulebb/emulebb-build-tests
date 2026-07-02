from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from emule_test_harness import live_wire_inputs


def payload() -> dict[str, object]:
    """Returns one complete valid live-wire input payload."""

    return {
        "schema": live_wire_inputs.SCHEMA,
        "search_terms": {
            "generic_open": [" linux ", "ubuntu"],
            "documents": ["debian"],
            "radarr_movies": ["public domain movie"],
            "sonarr_series": ["public domain series"],
        },
        "auto_browse": {
            "bootstrap_transfer_hashes": ["28EAB1A0AB1B9416AAF534E27A234941"],
            "direct_bootstrap_transfers": [
                {
                    "hash": "0031c9cba65c50dd2015c184b2ca2c88",
                    "name": "ubuntu.iso",
                    "size": 42,
                    "method": "direct_ed2k",
                }
            ],
        },
        "media_corpus": {
            "video_roots": ["C:\\media\\movies", "D:\\samples"],
        },
    }


def test_parse_live_wire_inputs_normalizes_runtime_values() -> None:
    inputs = live_wire_inputs.parse_live_wire_inputs(payload(), path=Path("inputs.json"))

    assert inputs.generic_open_terms == ("linux", "ubuntu")
    assert inputs.document_terms == ("debian",)
    assert inputs.radarr_movie_terms == ("public domain movie",)
    assert inputs.sonarr_series_terms == ("public domain series",)
    assert tuple(str(path) for path in inputs.video_roots) == (str(Path("C:\\media\\movies").resolve()), str(Path("D:\\samples").resolve()))
    assert inputs.bootstrap_transfer_hashes == ("28EAB1A0AB1B9416AAF534E27A234941",)
    assert inputs.direct_bootstrap_transfers[0]["name"] == "ubuntu.iso"
    assert live_wire_inputs.summarize_terms(inputs.generic_open_terms) == {"count": 2}
    assert live_wire_inputs.summarize_direct_transfers(inputs.direct_bootstrap_transfers) == {
        "count": 1,
        "methods": ["direct_ed2k"],
        "sizes": [42],
    }
    assert live_wire_inputs.summarize_paths(inputs.video_roots) == {"count": 2}


def test_parse_live_wire_inputs_rejects_missing_or_invalid_fields() -> None:
    bad_payload = payload()
    bad_payload["schema"] = "wrong"

    with pytest.raises(RuntimeError, match="schema"):
        live_wire_inputs.parse_live_wire_inputs(bad_payload)

    bad_hash = payload()
    auto_browse = bad_hash["auto_browse"]
    assert isinstance(auto_browse, dict)
    auto_browse["bootstrap_transfer_hashes"] = ["not-a-hash"]

    with pytest.raises(RuntimeError, match="32-character hex hash"):
        live_wire_inputs.parse_live_wire_inputs(bad_hash)


def test_parse_live_wire_inputs_keeps_sonarr_terms_backward_compatible() -> None:
    old_payload = payload()
    search_terms = old_payload["search_terms"]
    assert isinstance(search_terms, dict)
    del search_terms["sonarr_series"]

    inputs = live_wire_inputs.parse_live_wire_inputs(old_payload)

    assert inputs.sonarr_series_terms == inputs.radarr_movie_terms


def test_parse_live_wire_inputs_keeps_media_corpus_optional() -> None:
    old_payload = payload()
    del old_payload["media_corpus"]

    inputs = live_wire_inputs.parse_live_wire_inputs(old_payload)

    assert inputs.video_roots == ()


def test_parse_live_wire_inputs_keeps_mfc_profile_optional() -> None:
    inputs = live_wire_inputs.parse_live_wire_inputs(payload())

    assert inputs.mfc_profile_dir is None


def test_parse_live_wire_inputs_reads_optional_mfc_profile_dir() -> None:
    with_profile = payload()
    with_profile["mfc_profile"] = {"profile_dir": " f:\\M\\H06T01\\dldz\\EMULE_BIN "}

    inputs = live_wire_inputs.parse_live_wire_inputs(with_profile)

    assert inputs.mfc_profile_dir == Path("f:\\M\\H06T01\\dldz\\EMULE_BIN").expanduser()


def test_parse_live_wire_inputs_rejects_blank_mfc_profile_dir() -> None:
    bad_profile = payload()
    bad_profile["mfc_profile"] = {"profile_dir": "   "}

    with pytest.raises(RuntimeError, match="profile_dir"):
        live_wire_inputs.parse_live_wire_inputs(bad_profile)


def test_parse_live_wire_inputs_accepts_legacy_schema_for_local_operator_files() -> None:
    old_payload = payload()
    old_payload["schema"] = live_wire_inputs.LEGACY_SCHEMAS[0]

    inputs = live_wire_inputs.parse_live_wire_inputs(old_payload)

    assert inputs.generic_open_terms == ("linux", "ubuntu")


def test_select_daily_and_redaction_are_deterministic() -> None:
    items = ("a", "b", "c")
    index, selected = live_wire_inputs.select_daily(items, today=dt.date(2026, 5, 4))

    assert selected == items[index]
    assert live_wire_inputs.redact_term_selection(index, items, source="documents") == {
        "source": "documents",
        "count": 3,
        "selected_index": index,
    }


def test_update_live_wire_bootstrap_inputs_replaces_placeholders(tmp_path: Path) -> None:
    update_payload = payload()
    auto_browse = update_payload["auto_browse"]
    assert isinstance(auto_browse, dict)
    auto_browse["bootstrap_transfer_hashes"] = [live_wire_inputs.PLACEHOLDER_HASH]
    auto_browse["direct_bootstrap_transfers"] = [
        {
            "hash": live_wire_inputs.PLACEHOLDER_HASH,
            "name": "placeholder.iso",
            "size": 1,
            "method": "direct_ed2k",
        }
    ]
    path = tmp_path / "live-wire-inputs.local.json"
    path.write_text(json.dumps(update_payload, indent=2) + "\n", encoding="utf-8")

    summary = live_wire_inputs.update_live_wire_bootstrap_inputs(
        path,
        {
            "hash": "ABCDEF0123456789ABCDEF0123456789",
            "name": "Linux ISO.iso",
            "sizeBytes": 123456789,
        },
    )
    updated = json.loads(path.read_text(encoding="utf-8"))

    assert summary == {
        "updated": True,
        "hash_present": True,
        "bootstrap_hash_count": 1,
        "direct_row_count": 1,
    }
    assert updated["schema"] == live_wire_inputs.SCHEMA
    assert updated["search_terms"] == update_payload["search_terms"]
    assert updated["auto_browse"]["bootstrap_transfer_hashes"] == ["abcdef0123456789abcdef0123456789"]
    assert updated["auto_browse"]["direct_bootstrap_transfers"] == [
        {
            "hash": "abcdef0123456789abcdef0123456789",
            "name": "Linux ISO.iso",
            "size": 123456789,
            "method": "direct_ed2k",
        }
    ]


def test_update_live_wire_bootstrap_inputs_prepends_and_deduplicates(tmp_path: Path) -> None:
    update_payload = payload()
    path = tmp_path / "live-wire-inputs.local.json"
    path.write_text(json.dumps(update_payload, indent=2) + "\n", encoding="utf-8")

    live_wire_inputs.update_live_wire_bootstrap_inputs(
        path,
        {
            "hash": "0031c9cba65c50dd2015c184b2ca2c88",
            "name": "updated.iso",
            "size": 84,
        },
    )
    live_wire_inputs.update_live_wire_bootstrap_inputs(
        path,
        {
            "hash": "11111111111111111111111111111111",
            "name": "new.iso",
            "size": 168,
        },
    )
    updated = json.loads(path.read_text(encoding="utf-8"))

    assert updated["auto_browse"]["bootstrap_transfer_hashes"] == [
        "11111111111111111111111111111111",
        "0031c9cba65c50dd2015c184b2ca2c88",
        "28eab1a0ab1b9416aaf534e27a234941",
    ]
    assert [row["hash"] for row in updated["auto_browse"]["direct_bootstrap_transfers"]] == [
        "11111111111111111111111111111111",
        "0031c9cba65c50dd2015c184b2ca2c88",
    ]


def test_build_direct_bootstrap_transfer_rejects_incomplete_rows() -> None:
    with pytest.raises(RuntimeError, match="hash"):
        live_wire_inputs.build_direct_bootstrap_transfer({"name": "bad.iso", "size": 1})
    with pytest.raises(RuntimeError, match="name"):
        live_wire_inputs.build_direct_bootstrap_transfer({"hash": "0" * 32, "size": 1})
    with pytest.raises(RuntimeError, match="size"):
        live_wire_inputs.build_direct_bootstrap_transfer({"hash": "0" * 32, "name": "bad.iso", "size": 0})
