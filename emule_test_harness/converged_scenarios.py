"""Pure scenario-matrix logic for the converged live-wire packet-diff harness.

The converged orchestrator (``scripts/converged-live-wire-diff.py``) drives the
eMuleBB Rust client and the eMuleBB MFC diagnostics client over the same gentle
live exchange and diffs their ``ed2k_packet_v1`` packet dumps. This module holds
the side-effect-free knobs that select WHICH exchange runs, so the matrix of
scenario variants can be unit-tested without launching a client, binding
hide.me, or touching the live network.

Each :class:`ConvergedScenario` is one gentle single-pass variant:

* ``search_method`` -- ``"server"`` (eD2K Lugdunum search), ``"kad"`` (Kademlia
  search), or ``"automatic"`` (the client picks);
* ``obfuscation`` -- protocol obfuscation ON or OFF (rust ``obfuscationEnabled``
  / MFC ``CryptLayerRequested``+``CryptLayerSupported``);
* ``compression_fixture`` -- the shared seed fixture pattern, ``"compressible"``
  vs ``"low-compressibility"`` (the patterns the parity audit references), or
  ``None`` to keep the tiny default seed;
* ``source_exchange`` -- whether to summarize / assert the SX2 source-exchange
  leg (REQUESTSOURCES2 / ANSWERSOURCES2, opcodes 0x83 / 0x84);
* ``low_id`` -- force a firewalled / LowID identity (no UPnP port-forward) vs the
  HighID default.

GENTLE LIVE DISCIPLINE: the orchestrator runs ONE pass per selected scenario.
This module only decides the knobs; it never loops or contacts the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Shared seed fixture patterns (mirrors local-ed2k-protocol-combinations.py):
# "compressible" packs a repeating block so the protocol's zlib path engages;
# "low-compressibility" is high-entropy so compression is a no-op. ``None`` keeps
# the tiny default text seed.
COMPRESSIBLE = "compressible"
LOW_COMPRESSIBILITY = "low-compressibility"
VALID_COMPRESSION_FIXTURES = frozenset({COMPRESSIBLE, LOW_COMPRESSIBILITY})

# Search methods accepted by both clients' POST /api/v1/searches.
SEARCH_SERVER = "server"
SEARCH_KAD = "kad"
SEARCH_AUTOMATIC = "automatic"
VALID_SEARCH_METHODS = frozenset({SEARCH_SERVER, SEARCH_KAD, SEARCH_AUTOMATIC})


@dataclass(frozen=True)
class ConvergedScenario:
    """One gentle single-pass converged rust-vs-MFC live-wire variant."""

    name: str
    search_method: str = SEARCH_AUTOMATIC
    obfuscation: bool = True
    compression_fixture: str | None = None
    source_exchange: bool = False
    low_id: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("Scenario name must be a non-empty string.")
        if self.search_method not in VALID_SEARCH_METHODS:
            raise ValueError(
                f"Unsupported search method {self.search_method!r}; "
                f"expected one of {sorted(VALID_SEARCH_METHODS)}."
            )
        if self.compression_fixture is not None and self.compression_fixture not in VALID_COMPRESSION_FIXTURES:
            raise ValueError(
                f"Unsupported compression fixture {self.compression_fixture!r}; "
                f"expected one of {sorted(VALID_COMPRESSION_FIXTURES)} or None."
            )

    def search_payload_method(self) -> str:
        """Returns the ``method`` value for the shared POST /api/v1/searches body."""

        return self.search_method

    def expects_high_id(self) -> bool:
        """Reports whether this scenario should reach HighID (False when LowID-forced)."""

        return not self.low_id

    def summary(self) -> dict[str, Any]:
        """Returns a compact JSON-friendly description of this scenario's knobs."""

        return {
            "name": self.name,
            "searchMethod": self.search_method,
            "obfuscation": self.obfuscation,
            "compressionFixture": self.compression_fixture,
            "sourceExchange": self.source_exchange,
            "lowId": self.low_id,
            "description": self.description,
        }


# The default gentle matrix. ``default-automatic`` is the baseline single pass;
# the rest toggle exactly one axis so a per-scenario diff isolates that behavior.
DEFAULT_SCENARIOS: tuple[ConvergedScenario, ...] = (
    ConvergedScenario(
        name="ed2k-server-search",
        search_method=SEARCH_SERVER,
        obfuscation=True,
        description="eD2K (Lugdunum) server keyword search, obfuscation ON, HighID.",
    ),
    ConvergedScenario(
        name="kad-search",
        search_method=SEARCH_KAD,
        obfuscation=True,
        description="Kademlia keyword search, obfuscation ON, HighID.",
    ),
    ConvergedScenario(
        name="obfuscation-on",
        search_method=SEARCH_AUTOMATIC,
        obfuscation=True,
        description="Automatic search with protocol obfuscation ON.",
    ),
    ConvergedScenario(
        name="obfuscation-off",
        search_method=SEARCH_AUTOMATIC,
        obfuscation=False,
        description="Automatic search with protocol obfuscation OFF.",
    ),
    ConvergedScenario(
        name="compression-compressible",
        search_method=SEARCH_AUTOMATIC,
        obfuscation=True,
        compression_fixture=COMPRESSIBLE,
        description="Compressible shared fixture so the zlib packet path engages.",
    ),
    ConvergedScenario(
        name="compression-low",
        search_method=SEARCH_AUTOMATIC,
        obfuscation=True,
        compression_fixture=LOW_COMPRESSIBILITY,
        description="High-entropy shared fixture so compression is a no-op.",
    ),
    ConvergedScenario(
        name="source-exchange-sx2",
        search_method=SEARCH_AUTOMATIC,
        obfuscation=True,
        source_exchange=True,
        description="Assert the SX2 source-exchange leg (REQUESTSOURCES2/ANSWERSOURCES2).",
    ),
    ConvergedScenario(
        name="firewalled-lowid",
        search_method=SEARCH_AUTOMATIC,
        obfuscation=True,
        low_id=True,
        description="Force a firewalled / LowID identity (no UPnP port-forward).",
    ),
)


def scenario_catalog() -> dict[str, ConvergedScenario]:
    """Returns the default scenario matrix keyed by name (stable order)."""

    catalog: dict[str, ConvergedScenario] = {}
    for scenario in DEFAULT_SCENARIOS:
        if scenario.name in catalog:
            raise ValueError(f"Duplicate scenario name in the default matrix: {scenario.name!r}.")
        catalog[scenario.name] = scenario
    return catalog


def list_scenario_names() -> list[str]:
    """Returns the default scenario names in declaration order."""

    return [scenario.name for scenario in DEFAULT_SCENARIOS]


def select_scenarios(names: list[str] | None) -> list[ConvergedScenario]:
    """Selects scenarios by name (preserving the requested order).

    ``None`` or an empty list selects only the baseline single pass
    (``ed2k-server-search``) to honor the gentle default: one deliberate pass.
    Unknown names raise with the list of valid names so the operator can correct
    the flag without a live run.
    """

    catalog = scenario_catalog()
    if not names:
        return [catalog["ed2k-server-search"]]
    unknown = [name for name in names if name not in catalog]
    if unknown:
        raise ValueError(
            "Unknown scenario name(s): "
            + ", ".join(sorted(set(unknown)))
            + f". Valid names: {', '.join(catalog)}."
        )
    # Preserve request order, de-duplicate while keeping the first occurrence.
    selected: list[ConvergedScenario] = []
    seen: set[str] = set()
    for name in names:
        if name not in seen:
            seen.add(name)
            selected.append(catalog[name])
    return selected


def parse_scenarios_arg(raw: str | None) -> list[str] | None:
    """Parses a comma-separated ``--scenarios`` value into a name list.

    ``"all"`` expands to the full matrix; ``None`` / empty returns ``None`` (the
    gentle baseline). Whitespace around names is stripped and blanks dropped.
    """

    if raw is None:
        return None
    tokens = [token.strip() for token in raw.split(",")]
    names = [token for token in tokens if token]
    if not names:
        return None
    if any(token.lower() == "all" for token in names):
        return list_scenario_names()
    return names


@dataclass
class ScenarioResult:
    """One scenario's connectivity facts plus the rust-vs-MFC diff verdicts."""

    scenario: ConvergedScenario
    rust_connected: bool = False
    rust_high_id: bool = False
    mfc_connected: bool = False
    mfc_high_id: bool = False
    rust_result_count: int = 0
    mfc_result_count: int = 0
    packet_diff: dict[str, Any] | None = None
    diag_diff: dict[str, Any] | None = None
    both_traces_captured: bool = False
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def packet_verdict(self) -> str:
        """Returns a coarse packet-diff verdict for this scenario."""

        if self.error is not None:
            return "error"
        if not self.both_traces_captured:
            return "missing-trace"
        if self.packet_diff is None:
            return "no-diff"
        return "matched" if self.packet_diff.get("ok") else "diff"

    def low_id_observed_as_expected(self) -> bool:
        """Reports whether the observed HighID/LowID matches the scenario intent.

        For a LowID-forced scenario both clients should NOT reach HighID; for a
        HighID scenario both should. Connectivity failures are reported via
        ``error`` / ``*_connected`` rather than here.
        """

        if self.scenario.low_id:
            return not self.rust_high_id and not self.mfc_high_id
        return self.rust_high_id and self.mfc_high_id

    def summary(self) -> dict[str, Any]:
        """Returns the per-scenario row for the combined parity summary."""

        return {
            "scenario": self.scenario.summary(),
            "rust": {
                "connected": self.rust_connected,
                "highId": self.rust_high_id,
                "resultCount": self.rust_result_count,
            },
            "mfc": {
                "connected": self.mfc_connected,
                "highId": self.mfc_high_id,
                "resultCount": self.mfc_result_count,
            },
            "packetVerdict": self.packet_verdict(),
            "packetDiff": self.packet_diff,
            "diagDiff": self.diag_diff,
            "bothTracesCaptured": self.both_traces_captured,
            "idExpectationMet": self.low_id_observed_as_expected(),
            "error": self.error,
            "extra": self.extra,
        }


def aggregate_scenario_summary(results: list[ScenarioResult]) -> dict[str, Any]:
    """Builds the combined per-scenario parity summary from scenario results.

    ``ok`` is true only when every selected scenario captured both traces, its
    packet diff matched, and its HighID/LowID intent was observed.
    """

    rows = [result.summary() for result in results]
    all_ok = bool(results) and all(
        result.error is None
        and result.both_traces_captured
        and result.packet_verdict() == "matched"
        and result.low_id_observed_as_expected()
        for result in results
    )
    verdict_counts: dict[str, int] = {}
    for result in results:
        verdict = result.packet_verdict()
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
    return {
        "ok": all_ok,
        "scenarioCount": len(results),
        "verdictCounts": dict(sorted(verdict_counts.items())),
        "scenarios": rows,
    }
