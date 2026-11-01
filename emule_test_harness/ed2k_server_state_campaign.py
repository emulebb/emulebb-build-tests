"""Deterministic upstream-server login, publish, search, source, and withdrawal campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import ed2k_server, ed2k_wire
from .paths import get_required_emule_workspace_root, get_workspace_output_root


SCHEMA = "emulebb-build-tests.ed2k-server-state-campaign"
FILE_HASH = bytes.fromhex("9E4A68E9DFE56C2E7C2CBB9D62E0C04F")
FILE_NAME = "emulebb protocol parity fixture.bin"
FILE_SIZE = 12_345
PUBLISHER_HASH = bytes.fromhex("1021324354650E8798A9BACBDCED6F0F")
OBSERVER_HASH = bytes.fromhex("FFEEDDCCBBAA0E887766554433226F00")


class StateCampaignFailure(RuntimeError):
    """Carries partial causal evidence when the state machine fails."""

    def __init__(self, cause: Exception, evidence: dict[str, object]) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.evidence = evidence


def sha256_file(path: Path) -> str:
    """Returns a lowercase SHA-256 for one executable."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(repo: Path, revision: str = "HEAD") -> str:
    """Returns one exact Git revision or fails the campaign preflight."""

    completed = subprocess.run(
        ["git", "rev-parse", revision],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or len(value) != 40:
        raise RuntimeError(
            f"Cannot resolve {revision!r} in {repo}: {completed.stderr.strip()}"
        )
    return value


def choose_server_ports() -> tuple[int, int]:
    """Chooses a TCP port whose upstream-derived UDP companions are free."""

    for _ in range(300):
        tcp_port = random.randrange(20_000, 44_000)
        admin_port = random.randrange(44_100, 59_000)
        sockets: list[socket.socket] = []
        try:
            for port in (tcp_port, admin_port):
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                probe.bind(("127.0.0.1", port))
                sockets.append(probe)
            for offset in (4, 8, 12, 14):
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe.bind(("127.0.0.1", tcp_port + offset))
                sockets.append(probe)
            return tcp_port, admin_port
        except OSError:
            pass
        finally:
            for probe in sockets:
                probe.close()
    raise RuntimeError(
        "Could not reserve an ED2K server port set for the deterministic campaign."
    )


def wait_for(
    description: str,
    timeout_seconds: float,
    probe: Callable[[], Any | None],
) -> Any:
    """Polls one bounded deterministic state transition."""

    deadline = time.monotonic() + timeout_seconds
    while True:
        value = probe()
        if value is not None:
            return value
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out waiting for {description}.")
        time.sleep(0.1)


def exact_search_row(rows: list[dict[str, object]]) -> dict[str, object] | None:
    """Returns the exact campaign fixture row from one search page."""

    expected_hash = FILE_HASH.hex().upper()
    return next((row for row in rows if row.get("hash") == expected_hash), None)


def assert_published_row(row: dict[str, object]) -> dict[str, object]:
    """Requires the exact indexed file and aggregate source state."""

    expected = {
        "hash": FILE_HASH.hex().upper(),
        "name": FILE_NAME,
        "size": FILE_SIZE,
        "sources": 1,
        "complete_sources": 1,
    }
    actual = {key: row.get(key) for key in expected}
    if actual != expected:
        raise RuntimeError(
            f"Indexed fixture differs from the published file: expected={expected!r} actual={actual!r}"
        )
    return row


def assert_single_lowid_source(
    result: dict[str, object],
    *,
    publisher_port: int,
    require_user_hash: bool,
) -> dict[str, object]:
    """Requires one callback-reachable LowID publisher without inventing an endpoint IP."""

    sources = result.get("sources")
    if (
        not isinstance(sources, list)
        or len(sources) != 1
        or not isinstance(sources[0], dict)
    ):
        raise RuntimeError(f"Expected one source record, got: {result!r}")
    source = dict(sources[0])
    if source.get("kind") != "low-id" or int(source.get("port") or 0) != publisher_port:
        raise RuntimeError(
            f"Expected the synthetic LowID publisher on port {publisher_port}: {source!r}"
        )
    if require_user_hash and source.get("user_hash") != PUBLISHER_HASH.hex().upper():
        raise RuntimeError(
            f"Obfuscated source reply omitted or changed the publisher hash: {source!r}"
        )
    return source


def execute_state_machine(
    *,
    host: str,
    port: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Executes the isolated server lifecycle and returns causal wire evidence."""

    publisher_port = 41_662
    observer_port = 41_663
    publisher = ed2k_wire.Ed2kWireClient(host, port, timeout_seconds)
    observer = ed2k_wire.Ed2kWireClient(host, port, timeout_seconds)
    evidence: dict[str, object] = {
        "networkMode": "stock-lowid-with-nat-callback-capability",
        "states": ["disconnected"],
        "checks": {},
        "transcripts": {
            "publisher": publisher.transcript,
            "observer": observer.transcript,
        },
    }
    states = evidence["states"]
    checks = evidence["checks"]
    assert isinstance(states, list)
    assert isinstance(checks, dict)
    try:
        publisher.connect()
        observer.connect()
        publisher_login = publisher.login(
            user_hash=PUBLISHER_HASH,
            tcp_port=publisher_port,
            nickname="emulebb-harness-publisher",
        )
        observer_login = observer.login(
            user_hash=OBSERVER_HASH,
            tcp_port=observer_port,
            nickname="emulebb-harness-observer",
        )
        if (
            publisher_login["id_kind"] != "low-id"
            or observer_login["id_kind"] != "low-id"
        ):
            raise RuntimeError(
                "The local server campaign must exercise stock LowID behavior; "
                f"publisher={publisher_login!r} observer={observer_login!r}"
            )
        checks["publisherLogin"] = publisher_login
        checks["observerLogin"] = observer_login
        states.append("publisher-and-observer-authenticated-lowid")

        publisher.offer_file(file_hash=FILE_HASH, name=FILE_NAME, size=FILE_SIZE)
        published = wait_for(
            "exact file publication",
            timeout_seconds,
            lambda: (
                row
                if (row := exact_search_row(observer.search_hash(FILE_HASH)))
                is not None
                else None
            ),
        )
        published = assert_published_row(published)
        checks["published"] = published
        states.extend(["file-published", "hash-search-replied"])

        keyword_rows = observer.search_term("protocol parity fixture")
        keyword_row = exact_search_row(keyword_rows)
        if keyword_row is None:
            raise RuntimeError(
                f"Keyword search did not return the published fixture: {keyword_rows!r}"
            )
        assert_published_row(keyword_row)
        checks["keywordSearch"] = keyword_row
        states.append("keyword-search-replied")

        plain_sources = observer.get_sources(
            file_hash=FILE_HASH, size=FILE_SIZE, obfuscated=False
        )
        plain_source = assert_single_lowid_source(
            plain_sources,
            publisher_port=publisher_port,
            require_user_hash=False,
        )
        checks["plainSource"] = plain_source
        states.append("plain-source-replied")
        obfuscated_sources = observer.get_sources(
            file_hash=FILE_HASH, size=FILE_SIZE, obfuscated=True
        )
        obfuscated_source = assert_single_lowid_source(
            obfuscated_sources,
            publisher_port=publisher_port,
            require_user_hash=True,
        )
        checks["obfuscatedSource"] = obfuscated_source
        states.append("obfuscated-source-replied")

        publisher.close()
        states.append("publisher-disconnected")
        withdrawn_search = wait_for(
            "file withdrawal after publisher disconnect",
            timeout_seconds,
            lambda: (
                {"absent": True}
                if exact_search_row(observer.search_hash(FILE_HASH)) is None
                else None
            ),
        )
        checks["withdrawnSearch"] = withdrawn_search
        withdrawn_sources = wait_for(
            "source withdrawal after publisher disconnect",
            timeout_seconds,
            lambda: (
                current
                if int(
                    (
                        current := observer.get_sources(
                            file_hash=FILE_HASH, size=FILE_SIZE
                        )
                    )["source_count"]
                )
                == 0
                else None
            ),
        )
        checks["withdrawnSources"] = withdrawn_sources
        states.append("file-and-source-withdrawn")
        return evidence
    except Exception as exc:
        evidence["failure"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
        raise StateCampaignFailure(exc, evidence) from exc
    finally:
        publisher.close()
        observer.close()


def default_report_path(output_root: Path, run_id: str) -> Path:
    """Returns the canonical external report path."""

    return (
        output_root / "reports" / "ed2k-server-state-campaign" / run_id / "report.json"
    )


def run_campaign(args: argparse.Namespace) -> tuple[dict[str, object], Path]:
    """Launches the managed upstream server and writes one deterministic receipt."""

    workspace_root = get_required_emule_workspace_root()
    output_root = get_workspace_output_root()
    tests_repo = Path(__file__).resolve().parents[1]
    server_repo = (
        Path(args.ed2k_server_repo).resolve()
        if args.ed2k_server_repo
        else workspace_root / "repos" / "ed2k-server"
    )
    if not server_repo.is_dir():
        raise RuntimeError(f"Managed ed2k-server repository is missing: {server_repo}")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = (
        Path(args.report).resolve()
        if args.report
        else default_report_path(output_root, run_id)
    )
    server_dir = (
        output_root / "artifacts" / "ed2k-server-state-campaign" / run_id / "server"
    )
    tcp_port, admin_port = choose_server_ports()
    launch = None
    report: dict[str, object] = {
        "schema": SCHEMA,
        "runId": run_id,
        "status": "failed",
        "scope": "test-infrastructure-only",
        "runnerRevision": git_revision(tests_repo),
        "serverForkRevision": git_revision(server_repo),
        "serverUpstreamRevision": git_revision(server_repo, "upstream/master"),
    }
    try:
        launch = ed2k_server.launch_ed2k_server(
            workspace_root=workspace_root,
            server_dir=server_dir,
            ed2k_port=tcp_port,
            admin_port=admin_port,
            token="unused-local-test-token",
            admin_address="127.0.0.1",
            ed2k_address="127.0.0.1",
            repo_override=str(server_repo),
            exe_override=args.ed2k_server_exe,
            protocol_obfuscation=True,
            health_timeout_seconds=args.timeout_seconds,
        )
        report["serverExecutable"] = str(launch.server_exe)
        report["serverExecutableSha256"] = sha256_file(launch.server_exe)
        report["serverBuild"] = launch.build
        report["serverHealth"] = launch.health
        report["stateMachine"] = execute_state_machine(
            host=launch.ed2k_host,
            port=launch.ed2k_port,
            timeout_seconds=args.timeout_seconds,
        )
        report["status"] = "passed"
    except StateCampaignFailure as exc:
        report["stateMachine"] = exc.evidence
        report["error"] = {
            "type": type(exc.cause).__name__,
            "message": str(exc.cause),
        }
        raise
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if launch is not None:
            ed2k_server.stop_process(launch.process)
            report["serverExitCode"] = launch.process.poll()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return report, report_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone campaign arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--report")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    return args


def main(argv: list[str] | None = None) -> int:
    """Runs the campaign and prints its receipt path."""

    _report, report_path = run_campaign(parse_args(argv))
    print(report_path)
    return 0
