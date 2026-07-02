# Converged long-soak parity runbook (rust vs MFC)

A long-lived, human-driven companion to the single-pass
`scripts/converged-live-wire-diff.py`. Both diagnostics builds run side by side on
**persistent, isolated** profiles, connected to the **same** operator eD2K server,
bootstrapped from the **same** nodes.dat, sharing the **same** library roots. A
human drives interactive searches/downloads through each client's own UI; the
harness observes both `/api/v1` surfaces, correlates the same action across
clients, and diffs the `ed2k_packet_v1` / `diag_event_v1` capture for each action's
time window.

See also: `emule_test_harness/soak_action_diff.py` (the action engine),
`docs/diagnostics/diag-event-v1-schema.md` (the diag schema).

## 1. Prerequisites

Environment (read-only — never override these):

- `X_LOCAL_IP` — the LAN IP the REST control plane binds on both clients.
- `EMULEBB_WORKSPACE_OUTPUT_ROOT` — all builds, profiles, and reports live here.

Diagnostics builds (both must emit the converged dumps):

- **Rust** — build the diagnostics daemon: `python -m emule_workspace build clients
  --client emulebb-rust --diagnostics`. This compiles the `packet-diagnostics` Cargo
  feature and stages it under the distinct name **`emulebb-rust-diagnostics.exe`**
  (so it is never confused with the plain release `emulebb-rust.exe`). The
  `ed2k_packet_v1` / `diag_event_v1` dumps are written to `EMULEBB_RUST_LOG_DIR`
  (pointed at the persistent `rust-runtime/packet-dump/`).
- **MFC** — build the `diagnostics` flavor (`main/x64/Release/diagnostics`) so
  `emulebb-diagnostics.exe` is compiled with `EMULEBB_ENABLE_PACKET_DIAGNOSTICS`.
  It writes `emulebb-diagnostics-packet.log` / `-diag.log` into its profile log dir.

Inputs: a `live-wire-inputs.local.json` with `shared_directories.roots` (the real
library both clients will share) and `search_terms` (operator-owned, gitignored).

## 2. Profile layout (persistent + isolated)

Created/reused under `$EMULEBB_WORKSPACE_OUTPUT_ROOT/soak/`:

```
soak/
  rust-runtime/        emulebb-rust.toml, sqlite metadata, daemon.out, packet-dump/
  mfc-profile/         config/ (preferences, server.met, nodes.dat, known.met cache),
                       logs/ (packet + diag dumps), Incoming/
  reports/<campaign>/  summary.json, actions/<seq>-<kind>-<key>.json, checkpoints/
```

Profiles are **reused** across campaigns (not timestamped), so the MD4/AICH hash
caches survive and the shared library is hashed once, not on every launch. They
are isolated from any production eMule install.

## 3. Launch

**Simple path — just stand up the environment and drive by hand:**

```
uv run python scripts/launch-soak.py
```

`launch-soak.py` brings up emulebb-rust + the MFC diagnostics GUI on the persistent
profiles, auto-starts TrackMuleBB pointed at rust, prints the endpoints, and idles
until Ctrl-C. It does NO diffing — dumps just accumulate under `soak/` for later
analysis. Flags: `--inputs` (default: repo-root `live-wire-inputs.local.json`),
`--no-mfc`, `--no-trackmulebb`, `--no-obfuscation`, `--rust-rest-port` /
`--mfc-rest-port`, `--mfc-variant/-arch/-configuration`, `--nodes-url`. Drive rust
via the TrackMuleBB UI it prints (`http://<X_LOCAL_IP>:8770`) and MFC via its GUI
window. When done, tell the maintainer to analyze (see §6/§7).

**Observer path — live per-action capture (optional):** the same bring-up plus a
live correlate-and-diff loop:

```
uv run python scripts/converged-soak-live.py \
  --inputs live-wire-inputs.local.json \
  --duration 2h
```

Useful flags: `--duration 0` (run until you type `quit`), `--poll-interval`,
`--checkpoint-interval`, `--correlation-window` (max gap to pair the same action
across clients), `--settle-seconds` / `--lead-seconds` (window padding),
`--no-obfuscation`, `--rust-rest-port` / `--mfc-rest-port`,
`--mfc-variant/-arch/-configuration`, `--trackmulebb-cmd "<cmd>"`.

On start it: ensures the hide.me split tunnel, fetches the Kad bootstrap, brings up
the rust daemon and the **MFC GUI window**, connects both to the operator server,
starts Kad, applies the shared roots, then prints the two REST endpoints and enters
the observe loop.

## 4. Drive the soak (human)

- **MFC** — use the eMule GUI window the orchestrator opened (search, download,
  share) exactly as normal.
- **emulebb-rust** — point **TrackMuleBB** at the printed rust REST endpoint
  (`http://<X_LOCAL_IP>:4731`, header `X-API-Key: converged-soak`) and drive
  searches/downloads from there. Pass `--trackmulebb-cmd` to have the orchestrator
  launch it for you, or start it yourself.

For a clean auto-correlated diff, do the **same** action on both clients close in
time (same search term, or download the **same** ed2k file). The observer pairs
them by lower-cased query / ed2k hash within `--correlation-window` and, once the
settle window elapses, writes `reports/<campaign>/actions/<seq>-…json`.

## 5. Manual marker (fallback)

When the auto-correlator can't pair an action (e.g. different terms per client, or
a one-sided action), bracket it by hand in the orchestrator's console:

```
begin my-label      # right before you perform the action on BOTH clients
end                 # right after — diffs the [begin, end] window across both
```

Other console commands: `status` (print running totals), `quit` (wind down).

## 6. Reports

- `reports/<campaign>/actions/<seq>-<kind>-<key>.json` — per-action diff. Key
  fields: `verdict` (`coverage-parity` / `divergence` / `one-sided` /
  `no-traffic` / `unpaired`), `coverageOk`, `byteMatch`, plus the full
  `packetDiff` (incl. `opcodeCoverage`) and `diagDiff`.
- `reports/<campaign>/summary.json` — rolling campaign totals + per-action index.
- `reports/<campaign>/checkpoints/<time>.json` — periodic stability snapshot:
  process alive + CPU/memory samples, packet-record counts (growth), and any
  error-log hits (`panic`/`assert`/`fatal`/`exception`).

**Reading verdicts:** two independent live clients never byte-match (different
peers, payloads, timing), so `byteMatch` is informational. The live parity signal
is `verdict == coverage-parity`: the same protocol opcodes/families were exercised
on both sides for that action. A `divergence` means one client used an opcode (or
diverged on a diag family) the other did not — the real parity lead to investigate.

## 7. Verification

1. Unit: `uv run pytest tests/python/test_soak_action_diff.py -m unit`.
2. Bring-up smoke: `--duration 10m`; confirm both reach the operator server and
   Kad, both packet dumps grow, and identical shared roots are advertised.
3. One synchronized action: run the same search on the MFC GUI and TrackMuleBB;
   confirm an `actions/…json` report appears with a verdict.
4. Short soak: confirm checkpoints show stable CPU/memory, no crashes, clean error
   scan, and accumulating opcode/family coverage.
