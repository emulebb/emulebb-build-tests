# eMule Shared Tests

This repository is the shared test harness for the canonical eMuleBB workspace rooted at `EMULEBB_WORKSPACE_ROOT`.

This repo assumes the canonical workspace created by
`python -m emule_workspace materialize` from `repos\emulebb-build`.

Minimum expected roots:

- `EMULEBB_WORKSPACE_ROOT\repos\emulebb-build`
- `EMULEBB_WORKSPACE_ROOT\repos\emulebb-build-tests`
- `EMULEBB_WORKSPACE_ROOT\workspaces\workspace`

Use `repos\emulebb-build\README.md` for the full workspace topology and
materialization contract.

It owns:

- the standalone `emule-tests.vcxproj` project
- shared doctest sources and support headers
- parity and divergence suites for live workspace-to-workspace comparison
- workspace-level build and live-diff scripts
- fixture, manifest, and workspace-state report helpers for future protocol coverage
- the deterministic live-profile seed used by the live REST E2E lane and live UI regressions

The project is built against the canonical app checkout resolved from the invoking workspace manifest. It is intentionally not a runtime dependency like the `eMule-*` third-party dependencies, and it is no longer embedded as a `tests/` submodule inside each workspace.

Test responsibility boundary:

- this repo owns shared eMule profile seeds, UTF-16 INI helpers, profile materialization, preference overlays, release evidence helpers, and common Python harness utilities
- `repos\emulebb-build` owns supported orchestration entrypoints such as `python -m emule_workspace`, not reusable test-profile logic
- p2p-overlord repos own their scenario catalogs, Rust/Node product tests, runtime launchers, and product-specific agent or coordinator config generation
- cross-product code should depend on this repo's shared helpers by workspace `deps.json` resolution instead of copying profile writers into product repos
- generated eMule profiles are throw-away runtime state by default; keep them only through explicit debug or artifact-retention flags

The harness also supports an explicit `-AppRoot` override when validating a cleanroom rebuild before promotion.

Supported branch:

- `main`

Workspace branch roles are owned by
`EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`. Do not
infer release status from branch names. Baseline workspaces may be edited only
when the change is strictly to enable tests, seams, logging, tracing, or
debugging; they are not feature-development branches.

Current suite model:

- `parity`: cases that must pass in both selected workspaces
- `divergence`: cases that are expected to differ between two explicitly chosen workspace roots
- focused comparison suites may be added when a specific branch-to-branch audit needs a tighter signal than the repo-wide `divergence` bucket

Community core comparison workflow:

- `scripts\run-community-core-coverage.py` is the operator-facing wrapper for the canonical `main` vs `baseline/community-0.72a` comparison
- it runs native coverage for `app\emulebb-main` with `parity` and `community-core-divergence`
- it runs the focused `community-core-divergence` suite for main-only queue-scoring and persistence behavior
- it runs native coverage for `app\emulebb-community-baseline` with `parity`
- it runs `scripts\run-live-diff.py` against those two app roots and keeps the suite-level pass/fail split explicit
- the wrapper writes a combined summary under
  `EMULEBB_WORKSPACE_ROOT\workspaces\workspace\state\test-reports\community-core-coverage`

Current critical comparison slices:

- upload queue entry access parity: `src\upload_queue.tests.cpp`
- upload queue/scoring divergence and FEAT-023 consumer helpers: `src\community_core_divergence.tests.cpp`, `src\upload_score.tests.cpp`
- protocol receive replay parity with fragmented temp-file streams: `src\protocol_receive_flow.tests.cpp`
- long-path and part/met persistence IO: `src\long_path_fs_parity.tests.cpp`, `src\part_file_persistence.tests.cpp`
- R1 REST/WebServer contract and boundary seams: `src\web_api.tests.cpp`
- core socket IO guards: `src\socket_io.tests.cpp`, `src\emsocket_send.tests.cpp`, `src\async_socket_ex.tests.cpp`

Release coverage ownership:

- `manifests\release-coverage\ownership.v1.json` is the release-owned weak-area
  map for the shared harness
- each blocking release-owned area must map to a campaign scenario in
  `manifests\release-campaigns\emulebb-0.7.3.v1.json`
- planned and deferred areas stay visible in that manifest instead of living in
  loose notes
- deterministic file-format goldens live in
  `src\release_file_format_goldens.tests.cpp` and run through the existing
  native `parity` suite when native tests are executed
- deterministic dialog/update seams now own friend/source input parsing,
  direct-download link tokenization, server update URL validation, and IP-filter
  archive member policy without requiring live UI automation
- scheduler policy and comment/Kad-note seams own deterministic coverage for
  scheduler activation, action values, comment filters, and note-search gating

Script inventory:

- Python 3 is the canonical runtime for live/UI harnesses in this repo
- `python -m pip install -e .[dev]` installs the fast pytest harness dependencies
- `python -m pip install -e .[dev,live]` also installs the Win32 live/UI automation dependencies
- default pytest collection is intentionally fast and excludes `native` and `live` marked tests
- Python 3 is the only tracked script runtime in this repo
- operator-facing Python script filenames are hyphenated; importable Python implementation modules stay under `emule_test_harness` with normal snake_case names
- canonical Python entrypoints are documented below; old PowerShell implementations and old underscore script names are not kept as compatibility shims

| Path | Role | Status | Notes |
| --- | --- | --- | --- |
| `scripts\build-emule-tests.py` | operator-facing build wrapper | maintained | builds `emule-tests.exe`, optional run |
| `scripts\guard-tracked-files.py` | operator-facing guard | maintained | privacy/path leak gate before builds, implemented by `repos\emulebb-tooling\ci\policy_guards.py` |
| `scripts\run-native-coverage.py` | operator-facing Python coverage runner | maintained | OpenCppCoverage orchestration |
| `scripts\run-live-diff.py` | operator-facing Python parity runner | maintained | Python-first live-diff implementation |
| `scripts\run-community-core-coverage.py` | operator-facing Python comparison runner | maintained | canonical `main` vs `community` pass |
| `scripts\validate-protocol-goldens.py` | protocol parity guard | maintained | validates compact Kad/eD2K oracle goldens and redaction rules |
| `scripts\normalize-protocol-oracle.py` | protocol evidence normalizer | maintained | normalizes tracing-harness UDP/eD2K JSONL dumps into candidate goldens |
| `scripts\compare-protocol-oracle.py` | protocol evidence comparator | maintained | compares normalized protocol oracle manifests |
| `scripts\protocol-pcap-capture.py` | optional capture helper | maintained | wraps passive `dumpcap` capture when available; raw pcap stays under workspace test reports |
| `scripts\multi-client-p2p-matrix.py` | operator-facing Windows P2P matrix | maintained | runs the deterministic eMuleBB versus tracing-harness transfer and records optional eMuleAI/aMule client readiness |
| `scripts\run-live-e2e-suite.py` | operator-facing aggregate E2E runner | maintained | sequential UI, REST, and live-wire coverage lane |
| `scripts\publish-harness-summary.py` | shared report publisher | maintained | combines coverage, parity, and optional live status |
| `scripts\harness-cli-common.py` | internal Python helper | maintained | canonical app/report/profile-seed resolution for Python-first live/UI harnesses |
| `scripts\emule-live-profile-common.py` | internal Python helper | maintained | compatibility facade for live-profile launch and trace helpers |
| `scripts\rest-api-smoke.py` | operator-facing Python E2E | maintained | canonical isolated REST live E2E lane |
| `scripts\fake-kad-trust-soak.py` | operator-facing live soak | maintained | long-running Kad search soak for fake-file risk and Kad trust telemetry |
| `scripts\rest-cold-start-dump-stress.py` | operator-facing Python diagnostic E2E | maintained | cold-start REST search/download stress with Sysinternals dump evidence |
| `scripts\live-process-monitor.py` | operator-facing Python diagnostic E2E | maintained | long real-profile CPU/memory monitor with ProcDump, CDB, and optional UMDH evidence |
| `scripts\auto-browse-live.py` | operator-facing Python E2E | maintained | isolated live auto-browse validation with `hide.me` bind and P2P UPnP |
| `scripts\amutorrent-local-ed2k-ui-live.py` | operator-facing local aMuTorrent coexistence E2E | maintained | throwaway local ED2K server, eMuleBB profile, aMule profile, aMuTorrent profile, browser profile, and capability matrix for both ED2K clients |
| `scripts\preference-ui-e2e.py` | operator-facing Python E2E | maintained | real Preferences dialog coverage for WebServer fields and Tweaks tree controls |
| `scripts\config-stability-ui-e2e.py` | operator-facing Python E2E | maintained | long `-c` config path, settings save, relaunch, and stability regression |
| `scripts\shared-files-ui-e2e.py` | operator-facing Python E2E | maintained | real Win32 Shared Files regression |
| `scripts\startup-profile-scenarios.py` | operator-facing Python E2E | maintained | Chrome Trace startup-profile scenarios |
| `scripts\create-long-paths-tree.py` | fixture generator | maintained | deterministic long-path tree materialization |
| `scripts\diag-hash-launch.py` | targeted diagnostic | maintained | seeded profile + procdump launcher for hash stall investigations |
| `scripts\parse-dump.py` | targeted diagnostic | maintained | parses `diag-hash-launch` dumps, defaults to `diag-hash-launch\latest` |
| `scripts\resolve-rva.py` | targeted diagnostic | maintained | resolves caller-provided RVAs against a selected debug build |

Workspace quick reference:

- default canonical workspace: `EMULEBB_WORKSPACE_ROOT\workspaces\workspace`
- canonical target app paths are `app\emulebb-main`, `app\emulebb-community-baseline`, and `app\emulebb-community-tracing-harness`
- workspace orchestration commands use variant keys, not folder names:
  `main` maps to `app\emulebb-main`, `community` maps to
  `app\emulebb-community-baseline`, and `tracing-harness` maps to
  `app\emulebb-community-tracing-harness`
- for live-diff runs, point `-TestRunWorkspaceRoot` and `-BaselineWorkspaceRoot` at the two workspace roots you want to compare
- for cleanroom validation, pass both `-WorkspaceRoot` and `-AppRoot` explicitly so reports and build tags stay tied to the selected workspace root

Harness output roots:

- published reports live under
  `EMULEBB_WORKSPACE_ROOT\workspaces\workspace\state\test-reports`
- each suite publishes timestamped UTC `YYYYMMDDTHHMMSSZ` run folders plus a
  stable `<suite>\latest` snapshot
- suite result leaves use `<suite>-result.json`; partial result leaves use
  `<suite>-result.partial.json`; suite summary leaves use
  `<suite>-summary.json`
- scratch artifacts, live profiles, VHD images, admin mount working folders,
  CPU/heap traces, browser data directories, dumps, and child-suite scratch live
  under `EMULEBB_WORKSPACE_ROOT\workspaces\workspace\state\test-artifacts`
- explicit artifact, profile, mount, or report paths below `%TEMP%`, `%TMP%`,
  or `%LOCALAPPDATA%\Temp` are rejected; test outcomes must be predictable and
  workspace-owned
- older repo-local `repos\emulebb-build-tests\reports` and
  `workspaces\workspace\state\live-e2e-artifacts` paths are legacy evidence
  locations only and are not used for new runs

The default seam-enabled baseline for 0.72a comparisons is materialized as
`app\emulebb-community-baseline`. It is test-only and should stay
behavior-preserving during normal app execution. The tracing-harness workspace
is reserved for explicit variant-client parity work and is not the default
regression baseline.

Standalone probe mode:

- `build\<tag>\x64\Debug\emule-tests.exe --hash-probe "<full file path>"` runs an isolated non-UI file scan
- by default it executes a buffered scan first and then the shared `MappedFileReader` path
- use `--reader buffered`, `--reader mapped`, or `--reader both` to narrow the probe
- use `--byte-limit <N>` to cap the scan length and `--progress-mib <N>` to control progress output
- `build\<tag>\x64\Debug\emule-tests.exe --full-hash-probe "<full file path>"` runs the offline MD4 plus AICH hashing pipeline without launching `emulebb.exe`
- the full-hash mode also supports `--reader buffered|mapped|both` and `--progress-mib <N>`
- use the full-hash mode when you need to separate raw file access from higher-level `CKnownFile::CreateFromFile` work such as metadata extraction, known-file registration, or UI progress handling

Deterministic live-profile seed:

- `manifests\live-profile-seed\config` stores the canonical test-only profile inputs for live REST E2E and live named-pipe runs
- the seed is intentionally minimal and vendors only the config files the live harness truly depends on: `preferences.ini`, `preferences.dat`, `nodes.dat`, and `server.met`
- the harness validates that exact file allowlist before copying the seed; runtime files such as logs, `shareddir.dat`, caches, and history files belong only in per-run artifacts
- `preferences.ini` is an initialized UTF-16LE-with-BOM profile seed; it must already carry the startup-silencing keys needed to avoid first-run UI such as the language prompt and runtime wizard
- `preferences.dat` carries the deterministic maximized main-window placement used by the live UI and startup-profile harnesses
- importable profile generation lives in `emule_test_harness.live_profiles`; scenario scripts should use that module's typed profile and WebServer specs instead of open-coded `preferences.ini` patch loops
- product-family private/local eMule harness profiles should also use `emule_test_harness.live_profiles`; the shared builder owns UTF-16 `preferences.ini` writing, identity-file preservation, transient cleanup, and private harness defaults
- the builder injects only runtime-specific transport, logging, bind, temp, working-folder, WebServer, and shared-directory settings per run
- runtime working folders are copied from that seed and then expanded with per-run logs, temp files, and other mutable state
- use `--profile-seed-dir <path>` on live harness entrypoints when diagnosing against an alternate seed

Live Arr environment:

- Prowlarr-only live checks require `PROWLARR_URL` and `PROWLARR_API_KEY`
- Radarr/Sonarr live-wire checks additionally require `RADARR_URL`, `RADARR_API_KEY`, `SONARR_URL`, and `SONARR_API_KEY`
- live scripts load process environment variables first, then fall back to an ignored dotenv file selected by `--env-file`; the default fallback is `.env.local`
- `.env.local`, `.env`, and `.env.*` are ignored; do not commit real API keys
- `.env.example` is the tracked redacted template for live Arr/Prowlarr variables
- live-wire runtime search terms, Radarr movie terms, Sonarr series terms, bootstrap hashes, and direct ED2K bootstrap rows live only in an ignored JSON file selected by `--live-wire-inputs-file`; the default is `live-wire-inputs.local.json`
- real-profile process-monitor inputs live only in ignored `live-process-monitor.local.json`; copy `live-process-monitor.example.json` and set `profileDir` locally instead of committing operator paths
- local package install inputs live only in the ignored live-wire JSON under `local_package_install`; use `python -m emule_workspace install-local-package --live-wire-inputs-file repos\emulebb-build-tests\live-wire-inputs.local.json` to rebuild the installer-created full-suite profile under the target install root; `import_profile_dir` bootstraps from an existing profile root only when the suite profile does not already exist, and retired `profile_dir` / `procdump_path` keys are rejected
- do not commit operator-owned live search terms, live transfer hashes, live magnets, or direct ED2K bootstrap rows to tracked files; tracked fixtures and docs must use placeholders or redacted summaries
- `live-wire-inputs.example.json` is the tracked schema example; copy its shape into the ignored local file and replace the placeholder values with operator-owned current inputs
- auto-browse live fallback automatically refreshes the ignored live-wire JSON when it discovers a safe live search result with usable hash, name, size, and source metadata
- persisted live reports redact exact runtime terms, movie titles, magnets, and real transfer hashes, keeping counts, indexes, sizes, and presence flags instead
- all launched live eMule profiles apply the workspace live-network policy: P2P `BindInterface=hide.me`, empty P2P `BindAddr`, and main P2P `UPnP` enabled

Terminology:

- live profile seed: the tracked deterministic eMule config baseline under `manifests\live-profile-seed\config`
- startup profile: runtime Chrome Trace output named `startup-profile.trace.json`
- REST coverage/stress budget: a test-budget preset selected with `--rest-coverage-budget` or `--rest-stress-budget`

Canonical live REST E2E lane:

- `scripts\rest-api-smoke.py` is the operator-facing entrypoint for the canonical isolated REST live E2E lane
- the Python runner is intentionally strict pass/fail and owns app resolution, report publication, and latest-report mirroring directly
- the lane launches `emulebb.exe` with explicit `-ignoreinstances -c <profile-base>` and enables WebServer REST against one per-run localhost port
- the default REST coverage budget is `contract`, which records safe coverage
  for the broadband `/api/v1` contract; `--rest-coverage-budget smoke` keeps
  the older lighter pass, while `contract-stress` also enables stress unless a
  stress budget is supplied explicitly
- contract coverage is OpenAPI-driven and records safe route counts, method
  counts, success/error outcomes, skipped unsafe operations, and per-family
  coverage in the run report
- `--rest-stress-budget smoke` runs the bounded release-gate stress pass used
  by the aggregate live E2E lane; it mixes read routes with safe no-op mutation
  routes for preferences, missing transfers, source browse, Kad recheck, and
  search start/stop validation; `off` disables stress and `soak` is reserved
  for longer operator-driven runs with explicit duration/concurrency knobs
- each run refreshes `server.met` and `nodes.dat` in the isolated profile from `https://emule-security.org/` / `https://upd.emule-security.org/` before launch, and records file sizes plus SHA-256 hashes in the report; `--skip-live-seed-refresh` keeps the checked-in seed files for offline diagnosis
- the lane requires real server-connect activity, Kad running state, network readiness, and one or more real live search lifecycles through the requested network paths; configured live-wire searches use REST `type=any` so operator-owned open terms are not incorrectly constrained to program-only results
- `--server-search-count <N>` and `--kad-search-count <N>` cycle through the `search_terms.generic_open` values from the live-wire input file for exact per-network live search counts
- `-KeepRunning` leaves the launched isolated eMule instance alive after a passing run and forces artifact retention so the profile can be inspected afterward
- failure artifacts include the failing phase plus the last observed server/Kad state so live-network regressions are diagnosable

Cold-start REST dump stress lane:

- `scripts\rest-cold-start-dump-stress.py` launches a fresh isolated profile,
  drives phased live REST search/download stress, and captures baseline, peak,
  and post-drain diagnostics for memory leak triage
- the lane uses Sysinternals `procdump64`, `handle64`, and `listdlls64` plus
  Windows SDK `cdb` when available; `--enable-umdh` additionally enables
  `gflags` UST before launch, captures UMDH snapshots, and restores the image
  flag before exit
- reports are written under
  `state\test-reports\rest-cold-start-dump-stress\...`; scratch profiles,
  dump files, CDB transcripts, handle snapshots, module inventory, CPU traces,
  and optional UMDH diffs are kept under the matching
  `state\test-artifacts` run tree before publication
- live download triggers actively start safe real downloads and allow archive,
  audio, and video candidates while still blocking executable/script payloads;
  if the live network does not expose enough safe candidates, the lane returns
  inconclusive instead of failing the build
- run it explicitly with `python -m emule_workspace test live-e2e --suite
  rest-cold-start-dump-stress`; it is not part of the default aggregate suite
  because it captures full process dumps

Real-profile process monitor:

- `scripts\live-process-monitor.py` launches the selected `emulebb.exe` with
  `-ignoreinstances -c <profileDir>` and samples CPU, private bytes, working
  set, handles, REST `/api/v1/status` counters when `baseUrl` and `apiKey` are
  configured, ETW/xperf CPU samples by default, delayed spike dumps, and an
  optional final full-memory dump
- runs are intentionally long; `durationSeconds` and `--duration-seconds` must
  be at least 1800 seconds so memory trends are not confused with startup
  transients
- CPU diagnosis should use the default ETW/xperf sampling run first; full spike
  dumps now default to at most two captures after the initial startup delay
- optional `--enable-umdh` wraps the run with `gflags /i emulebb.exe +ust`,
  captures baseline/final UMDH snapshots, diffs them, and disables UST during
  cleanup; UMDH is rejected when combined with ETW CPU profiling or full
  ProcDump captures so heap runs stay separate from CPU runs
- run it directly with `python scripts\live-process-monitor.py --configuration
  Release`, or through the aggregate runner with
  `--suite live-process-monitor`

Fake/Kad trust soak lane:

- run it through the workspace wrapper with
  `python -m emule_workspace test fake-kad-trust-soak`
- the default duration is 10,800 seconds (3 hours), with one Kad search at a
  time and cleanup after every cycle
- the report focuses on fake-file risk invariants, canonical name divergence,
  ignored release-noise tokens, Kad publish-info buckets, result volume,
  failed/zero-result cycles, and process resource/CPU samples
- reports are written under `state\test-reports\fake-kad-trust-soak\...` and
  mirrored to `state\test-reports\fake-kad-trust-soak\latest`

Aggregate live E2E lane:

- `scripts\run-live-e2e-suite.py` is the operator-facing aggregate runner for the maintained UI, REST API, and live-wire scenarios
- the default run sequences Preferences UI, Shared Files UI, config-stability UI, shared-hash UI, startup-profile scenarios, REST live smoke, and auto-browse live coverage
- `--profile release-expanded` is the bounded weak-path release gate: it runs
  Preferences with directory-tree stress, Shared Files, shared-hash shutdown,
  Search UI, shared-directories REST, REST API adversity, cold-start telemetry,
  local dump/crash smoke, and aMuTorrent browser smoke
- `--profile multi-client-p2p` includes the local aMuTorrent coexistence lane:
  one throwaway run launches eMuleBB and aMule behind aMuTorrent, adds the same
  local ED2K fixture through both configured clients, exercises snapshot,
  config, history, metrics, logs, server, shared-directory, pause/resume/stop,
  category, delete/move preflight, qBittorrent-compatible app/torrent/category
  facade, and refresh surfaces, then verifies both completed files against the
  fixture hash
- `--profile release-expanded-quick`, `--profile stabilization-stress-quick`,
  and `--profile cpu-heavy-quick` are the first-pass failure triage gates; they
  keep the same fixture classes and live-profile isolation but reduce REST
  budgets and run the 1k Shared Files tree-refresh scenario instead of the full
  50k tree
- full stress profiles run Shared Files tree-refresh in two stages: the 1k
  smoke fixture (`tree-refresh-smoke-1k`) runs first to catch setup and cache
  regressions quickly, then `tree-refresh-stress-50k` runs as the overnight/full
  capacity check
- `release-expanded` requires 50 server searches plus 50 Kad searches and
  100 successful paused download triggers; success means REST accepted the
  download and the transfer materialized in the queue, not that the download
  completed
- `--profile ui-resource-depth` is the release resource gate for language and
  UI shell coverage: it runs `resource-ui-smoke` across the canonical stock
  language manifest, hard-fails missing release language DLLs, then runs the
  Preferences UI roundtrip
- Shared Files UI is always expanded to include `fixture-three-files`, `generated-robustness-recursive`, and `duplicate-startup-reuse`; config-stability and startup-profile scenarios are also passed explicitly
- REST live smoke defaults to six server searches and six Kad searches using the configured live-wire open-term list, and enables UPnP in the isolated profile so current NAT-mapping behavior is exercised through the live lane
- aggregate reports mark whether REST contract completeness was expected and
  which Arr/Prowlarr live-wire suites were included; expanded/stress reports
  also include a `weak_path_matrix` with adversity, queued-download, UI, and
  integration coverage targets
- aggregate reports classify inconclusive live-network child suites separately
  from blocking harness/app inconclusive states; UI/resource failures are hard
  failures, not accepted inconclusive results
- REST live smoke is invoked with `--rest-coverage-budget contract` and
  `--rest-stress-budget smoke` by default; use the aggregate runner's REST
  budget flags to reduce or expand that budget for a specific run
- REST and auto-browse child runs refresh `server.met` and `nodes.dat` from `https://emule-security.org/` / `https://upd.emule-security.org/` unless `--skip-live-seed-refresh` is supplied
- the aggregate runner continues after child-suite failures by default to expose multiple breaking points in one pass; use `--fail-fast` only when a short diagnostic run is needed
- each child suite keeps its normal report directory, while the aggregate run
  also writes `state\test-reports\live-e2e-suite\...\live-e2e-suite-result.json`
  and refreshes `state\test-reports\live-e2e-suite\latest`

Canonical live auto-browse lane:

- `scripts\auto-browse-live.py` is the operator-facing entrypoint for the isolated remote-share auto-browse validation
- the scenario enables `AutoBrowseRemoteShares=1`, keeps REST on one per-run localhost port, and writes the P2P `BindInterface` preference directly as `hide.me`
- the default P2P bind target is the `hide.me` interface and the scenario always enables the main P2P `UPnP` setting
- the scenario relies on `Autoconnect=1` in the isolated profile and intentionally does not issue overlapping REST connect requests for eD2K or Kad
- the scenario first waits for real browse-capable clients to accumulate naturally after server+Kad autoconnect; transfer/source bootstrap is only a fallback if natural auto-browse never starts succeeding
- the transfer bootstrap path tries configured `auto_browse.bootstrap_transfer_hashes` first, then falls back through the configured open-term list, and refuses `.exe` candidates when selecting a downloadable result
- when the fallback search path finds a safe sourced result, it automatically updates the ignored live-wire input file so future runs can bootstrap from the discovered hash/direct ED2K row
- like the REST smoke lane, each run refreshes `server.met` and `nodes.dat` in the isolated profile from eMule Security unless `--skip-live-seed-refresh` is supplied
- the lane requires:
  - real eD2K server connectivity
  - Kad running state
  - acquisition of one live transfer with sources
  - at least one successful automatic remote-share browse that logs success and persists `.browsecache` output
- `--keep-running` leaves the launched isolated eMule instance alive after a passing run and forces artifact retention so the profile can be inspected afterward
- artifacts are published under `state\test-reports\auto-browse-live\...` with
  the same latest-report mirroring as the other Python-first live harnesses

Shared Files live UI regression:

- `scripts\shared-files-ui-e2e.py` is the operator-facing entrypoint for the real Win32 Shared Files regression
- it launches `emulebb.exe` with explicit `-ignoreinstances -c <profile-base>` so the run stays isolated from local user sessions
- the checked-in seed profile must stay initialized; the Python harness validates the seed keys, writes deterministic maximized window placement, and patches only per-run incoming, temp, and shared-directory paths
- the default UI run now covers two scenarios: the original three-file deterministic smoke case plus a generated recursive robustness tree under the configured long-path shared root
- the regression asserts that the main window starts maximized and exercises exact default-name ordering, size ascending and descending sorts, name ascending and descending sorts after reload, selection-detail updates, reload preservation of the active descending size sort, and large-tree row-count/set/prefix checks driven by the generated manifest
- `--scenario` can be repeated on the Python entrypoint to run only `fixture-three-files` or only `generated-robustness-recursive`
- each run publishes artifacts and `shared-files-ui-e2e-summary.json` under
  `state\test-reports\shared-files-ui-e2e\...` and refreshes
  `state\test-reports\shared-files-ui-e2e\latest`
- the shared `state\test-reports\harness-summary-result.json` now includes a
  `live_ui` section when that regression is run

Config-stability live UI regression:

- `scripts\config-stability-ui-e2e.py` is the operator-facing entrypoint for long `-c` config-path startup, settings-save, and relaunch-stability coverage
- it launches `emulebb.exe` with explicit `-ignoreinstances -c <profile-base>` under a deliberately deep profile root so `profile-base\config\preferences.ini` exceeds normal Win32 path limits
- the default run covers `long-config-settings-roundtrip` and `long-config-shared-stress`
- the roundtrip scenario edits the real Preferences dialog, saves `OnlineSignature`, verifies `preferences.ini`, relaunches the same long-path profile, and confirms persisted UI state
- the stress scenario repeats launch, Preferences save, Shared Files activation, and clean shutdown across multiple cycles while recursively sharing the generated robustness tree under the configured long-path shared root
- each run publishes artifacts and `config-stability-ui-e2e-summary.json` under
  `state\test-reports\config-stability-ui-e2e\...` and refreshes
  `state\test-reports\config-stability-ui-e2e\latest`

Preferences live UI regression:

- `scripts\preference-ui-e2e.py` is the operator-facing entrypoint for the real Preferences dialog regression
- it launches an isolated profile, opens Preferences, drives the WebServer page fields for max upload size and allowed IPs, then drives the Tweaks advanced tree through real tree selection, checkbox/radio activation, and in-place edit controls
- the scenario saves through the dialog and asserts `preferences.ini` persistence for crash dumps, log size/buffer/format, performance logging, text editor command, preview small-block policy, chat/session limits, WebServer max upload, and WebServer allowed IPs
- each run publishes `preference-ui-e2e-summary.json` under
  `state\test-reports\preference-ui-e2e\...` and refreshes
  `state\test-reports\preference-ui-e2e\latest`

Startup-profile scenarios:

- `scripts\startup-profile-scenarios.py` builds deterministic Chrome Trace `startup-profile.trace.json` artifacts for multiple live-profile scenarios without changing app behavior
- the trace includes stable readiness, Shared Files hashing, Statistics dialog, and broadband lifecycle phase ids so Perfetto and the JSON summaries can separate startup, UI setup, queue wait, worker-thread bring-up costs, and final shared-hash drain time
- the default run covers `baseline-no-shares`, `fixture-three-files`, `long-paths-root-only`, `long-paths-recursive`, `long-path-output-root-only`, `long-path-output-recursive`, `long-path-emule-fixture-root-only`, `long-path-emule-fixture-recursive`, `shared-files-robustness-root-only`, and `shared-files-robustness-recursive`
- `--scenario` can be repeated on the Python entrypoint to run only the scenarios you want
- `scripts\create-long-paths-tree.py` now lives in this repo and materializes the generated long-path fixture trees plus `generated-fixture-manifest.json` under the configured long-path shared root
- the long-path scenarios target the configured long-path shared root by default, regenerate the repo-owned fixture tree as needed, and expand `shareddir.dat` deterministically in the recursive cases
- each scenario summary now also records shareddir payload metrics plus tree-shape metrics such as depth, longest paths, and counts beyond the Windows path thresholds
- each scenario summary includes highlighted timings, normalized derived timings, and the top slowest startup phases, and the combined summary adds direct delta comparisons between the main long-path, generated output, and Shared Files robustness root-only vs recursive variants
- each run publishes scenario artifacts plus
  `startup-profile-scenarios-result.json` and
  `startup-profile-scenarios-summary.json` under
  `state\test-reports\startup-profile-scenarios\...` and refreshes
  `state\test-reports\startup-profile-scenarios\latest`
- the shared `state\test-reports\harness-summary-result.json` now includes a
  `startup_profiles` section when that runner is used

Tracked-file privacy guard:

- `scripts\guard-tracked-files.py` fails when tracked files contain local user-home paths or personal-identifier filename leaks derived from the current environment or an untracked local override file
- the guard implementation is owned by `repos\emulebb-tooling\ci\policy_guards.py`; this repo keeps only a compatibility import facade and operator wrapper
- `scripts\build-emule-tests.py` runs that guard by default before building
- the same guard is enforced in GitHub Actions for pushes and pull requests

Native seam coverage and shared reports:

- `scripts\run-native-coverage.py` builds `emule-tests.exe`, runs the requested doctest suites under OpenCppCoverage, and writes Cobertura plus summary outputs under `state\test-reports\native-coverage`
- `scripts\run-community-core-coverage.py` chains the canonical `main` and `community` native-coverage runs with the workspace live-diff pass and writes a combined summary under `state\test-reports\community-core-coverage`
- Python OpenCppCoverage resolution uses an explicit install root when provided, otherwise discovers `OpenCppCoverage.exe` from `PATH`, and finally falls back to a repo-managed pinned install under `tools\OpenCppCoverage`
- `scripts\run-live-diff.py` writes both text and JSON parity/divergence summaries under `state\test-reports`
- `scripts\publish-harness-summary.py` combines native coverage, parity, optional live-harness manifest data, optional live UI status, and optional startup-profile scenario status into one shared summary under `state\test-reports`
