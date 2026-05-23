from __future__ import annotations

import hashlib
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

EMULE_SECURITY_HOME_URL = "https://emule-security.org/"
EMULE_SECURITY_SERVER_MET_URL = "https://upd.emule-security.org/server.met"
EMULE_SECURITY_NODES_DAT_URL = "https://upd.emule-security.org/nodes.dat"


@dataclass(frozen=True)
class LiveSeedSource:
    """Describes one live eD2K/Kad bootstrap file used by networked harness runs."""

    name: str
    url: str
    file_name: str
    minimum_bytes: int


def default_seed_sources() -> tuple[LiveSeedSource, ...]:
    """Returns the eMule Security bootstrap files used by live-wire tests."""

    return (
        LiveSeedSource(
            name="server_met",
            url=EMULE_SECURITY_SERVER_MET_URL,
            file_name="server.met",
            minimum_bytes=64,
        ),
        LiveSeedSource(
            name="nodes_dat",
            url=EMULE_SECURITY_NODES_DAT_URL,
            file_name="nodes.dat",
            minimum_bytes=64,
        ),
    )


def fetch_url_bytes(url: str, timeout_seconds: float) -> bytes:
    """Downloads one URL using a stable harness user agent."""

    request = urllib.request.Request(url, headers={"User-Agent": "emulebb-build-tests/1.0"})
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


def fetch_seed_payload_with_retries(
    source: LiveSeedSource,
    *,
    timeout_seconds: float,
    max_attempts: int = 3,
    retry_delay_seconds: float = 2.0,
    fetch_bytes: Callable[[str, float], bytes] = fetch_url_bytes,
    sleep_seconds: Callable[[float], None] = time.sleep,
) -> tuple[bytes, list[dict[str, object]]]:
    """Downloads and validates one seed file with bounded transient-failure retries."""

    attempt_count = max(1, max_attempts)
    attempts: list[dict[str, object]] = []
    last_error: Exception | None = None
    for attempt in range(1, attempt_count + 1):
        try:
            payload = fetch_bytes(source.url, timeout_seconds)
            if len(payload) < source.minimum_bytes:
                raise RuntimeError(
                    f"Downloaded {source.name} from {source.url} was too small: "
                    f"{len(payload)} bytes, expected at least {source.minimum_bytes}."
                )
            attempts.append(
                {
                    "attempt": attempt,
                    "ok": True,
                    "bytes": len(payload),
                }
            )
            return payload, attempts
        except Exception as exc:
            last_error = exc
            attempts.append(
                {
                    "attempt": attempt,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            if attempt < attempt_count and retry_delay_seconds > 0:
                sleep_seconds(retry_delay_seconds)

    raise RuntimeError(
        f"Failed to download {source.name} from {source.url} after {attempt_count} "
        f"attempt(s); last error: {last_error}"
    ) from last_error


def refresh_seed_files(
    config_dir: Path,
    *,
    timeout_seconds: float = 30.0,
    max_attempts: int = 3,
    retry_delay_seconds: float = 2.0,
    sources: tuple[LiveSeedSource, ...] | None = None,
    fetch_bytes: Callable[[str, float], bytes] = fetch_url_bytes,
    sleep_seconds: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Downloads current server/node seed files into one isolated live profile."""

    resolved_config_dir = config_dir.resolve()
    resolved_config_dir.mkdir(parents=True, exist_ok=True)
    refreshed: list[dict[str, object]] = []

    for source in sources or default_seed_sources():
        payload, attempts = fetch_seed_payload_with_retries(
            source,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
            retry_delay_seconds=retry_delay_seconds,
            fetch_bytes=fetch_bytes,
            sleep_seconds=sleep_seconds,
        )

        target_path = resolved_config_dir / source.file_name
        with tempfile.NamedTemporaryFile(dir=resolved_config_dir, delete=False) as temp_file:
            temp_file.write(payload)
            temp_path = Path(temp_file.name)
        temp_path.replace(target_path)

        refreshed.append(
            {
                "name": source.name,
                "url": source.url,
                "file_name": source.file_name,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "attempts": attempts,
            }
        )

    return {
        "source_home_url": EMULE_SECURITY_HOME_URL,
        "files": refreshed,
    }
