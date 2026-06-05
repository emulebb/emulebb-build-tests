from __future__ import annotations

import json
from pathlib import Path

from emule_test_harness import live_wire_inputs, local_swarm_media


def test_local_swarm_media_payload_is_live_wire_compatible() -> None:
    payload = local_swarm_media.build_local_swarm_live_wire_payload()

    parsed = live_wire_inputs.parse_live_wire_inputs(payload, path=Path("generated.json"))

    assert parsed.radarr_movie_terms == (local_swarm_media.DEFAULT_RADARR_MOVIE_TITLE,)
    assert parsed.sonarr_series_terms == (local_swarm_media.DEFAULT_SONARR_SERIES_TITLE,)
    assert payload["local_swarm_media_fixture"] == {
        "schema": local_swarm_media.SCHEMA,
        "radarr_movie": {
            "title": local_swarm_media.DEFAULT_RADARR_MOVIE_TITLE,
            "public_domain": True,
        },
        "sonarr_series": {
            "title": local_swarm_media.DEFAULT_SONARR_SERIES_TITLE,
            "year": local_swarm_media.DEFAULT_SONARR_SERIES_YEAR,
        },
    }


def test_write_generated_local_swarm_inputs_preserves_local_install_only(tmp_path: Path) -> None:
    output_path = local_swarm_media.write_generated_local_swarm_inputs(
        tmp_path / "inputs.json",
        local_package_install={
            "dependency_manifest": "suite-dependencies.json",
        },
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["schema"] == live_wire_inputs.SCHEMA
    assert payload["local_package_install"] == {"dependency_manifest": "suite-dependencies.json"}
    assert payload["search_terms"]["radarr_movies"] == [local_swarm_media.DEFAULT_RADARR_MOVIE_TITLE]
    assert payload["search_terms"]["sonarr_series"] == [local_swarm_media.DEFAULT_SONARR_SERIES_TITLE]
