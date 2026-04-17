# eMule Shared Tests

This repository is the shared test harness for the canonical 0.72a workspace rooted at `EMULE_WORKSPACE_ROOT`.

This repo assumes the canonical workspace created by `eMulebb-setup`.

Minimum expected roots:

- `EMULE_WORKSPACE_ROOT\repos\eMule-build`
- `EMULE_WORKSPACE_ROOT\repos\eMule-build-tests`
- `EMULE_WORKSPACE_ROOT\repos\eMule-remote`
- `EMULE_WORKSPACE_ROOT\workspaces\v0.72a`

Use `eMulebb-setup\README.md` for the full workspace topology and materialization
contract.

It owns:

- the standalone `emule-tests.vcxproj` project
- shared doctest sources and support headers
- parity and divergence suites for live workspace-to-workspace comparison
- workspace-level build and live-diff scripts
- fixture, manifest, and report directories for future protocol coverage
- the deterministic live-profile seed used by the named-pipe live harness and live UI regressions

The project is built against the canonical app checkout resolved from the invoking workspace manifest. It is intentionally not a runtime dependency like the `eMule-*` third-party dependencies, and it is no longer embedded as a `tests/` submodule inside each workspace.

The harness also supports an explicit `-AppRoot` override when validating a cleanroom rebuild before promotion.

Supported branch:

- `main`

Oracle workspaces may be edited when the change is strictly to enable tests, seams, logging, tracing, or debugging. They are not feature-development branches.

Current suite model:

- `parity`: cases that must pass in both selected workspaces
- `divergence`: cases that are expected to differ between two explicitly chosen workspace roots
- focused comparison suites may be added when a specific branch-to-branch audit needs a tighter signal than the repo-wide `divergence` bucket

Bugfix core comparison workflow:

- `scripts\run-bugfix-core-coverage.ps1` is the operator-facing wrapper for the canonical `main` vs `release/v0.72a-bugfix` comparison
- it runs native coverage for `app\eMule-main` with `parity` and `bugfix-core-divergence`
- it runs the focused `bugfix-core-divergence` suite for main-only queue-scoring and persistence behavior
- it runs native coverage for `app\eMule-v0.72a-bugfix` with `parity`
- it runs `scripts\run-live-diff.ps1` against those two app roots and keeps the suite-level pass/fail split explicit
- the wrapper writes a combined summary under `reports\bugfix-core-coverage`

Current critical comparison slices:

- upload queue entry access parity: `src\upload_queue.tests.cpp`
- upload queue/scoring divergence and FEAT-023 consumer helpers: `src\bugfix_core_divergence.tests.cpp`, `src\upload_score.tests.cpp`
- protocol receive replay parity with fragmented temp-file streams: `src\protocol_receive_flow.tests.cpp`
- long-path and part/met persistence IO: `src\long_path_fs_parity.tests.cpp`, `src\part_file_persistence.tests.cpp`
- core socket IO guards: `src\socket_io.tests.cpp`, `src\emsocket_send.tests.cpp`, `src\async_socket_ex.tests.cpp`

Workspace quick reference:

- default canonical workspace: `EMULE_WORKSPACE_ROOT\workspaces\v0.72a`
- canonical target app paths are `app\eMule-main`, `app\eMule-v0.72a-oracle`, `app\eMule-v0.72a-build`, and `app\eMule-v0.72a-bugfix`
- for live-diff runs, point `-DevWorkspaceRoot` and `-OracleWorkspaceRoot` at the two workspace roots you want to compare
- for cleanroom validation, pass both `-WorkspaceRoot` and `-AppRoot` explicitly so reports and build tags stay tied to the selected workspace root

The sanctioned seam-enabled oracle baseline for 0.72a comparisons is
`oracle/v0.72a-build`, materialized as `app\eMule-v0.72a-oracle`. It should
stay behavior-preserving relative to `release/v0.72a-build` during normal app
execution and may accept only test-enablement changes.

Standalone probe mode:

- `build\<tag>\x64\Debug\emule-tests.exe --hash-probe "<full file path>"` runs an isolated non-UI file scan
- by default it executes a buffered scan first and then the shared `MappedFileReader` path
- use `--reader buffered`, `--reader mapped`, or `--reader both` to narrow the probe
- use `--byte-limit <N>` to cap the scan length and `--progress-mib <N>` to control progress output
- `build\<tag>\x64\Debug\emule-tests.exe --full-hash-probe "<full file path>"` runs the offline MD4 plus AICH hashing pipeline without launching `emule.exe`
- the full-hash mode also supports `--reader buffered|mapped|both` and `--progress-mib <N>`
- use the full-hash mode when you need to separate raw file access from higher-level `CKnownFile::CreateFromFile` work such as metadata extraction, known-file registration, or UI progress handling

Deterministic live-profile seed:

- `manifests\live-profile-seed\config` stores the canonical test-only profile inputs for live named-pipe runs
- the seed is intentionally minimal and vendors only the config files the live harness truly depends on: `preferences.ini`, `preferences.dat`, `nodes.dat`, and `server.met`
- `preferences.ini` is an initialized profile seed; it must already carry the startup-silencing keys needed to avoid first-run UI such as the language prompt and runtime wizard
- `preferences.dat` carries the deterministic maximized main-window placement used by the live UI and startup-profile harnesses
- the helper injects only runtime-specific transport, logging, bind, temp, working-folder, and shared-directory settings per run
- runtime working folders are copied from that seed and then expanded with per-run logs, temp files, and other mutable state

Canonical live harness:

- `scripts\run-pipe-live-matrix.ps1` is the operator-facing entrypoint for launch-only and full live named-pipe harness runs
- the harness stages a renamed binary copy, `eMule_v072_harness.exe`, beside the debug build output and launches that copy so processes, dumps, and cleanup are easier to identify
- the machine-readable session manifest can be requested through the shared wrapper with `-SessionManifestPath`
- normal runs retry targeted teardown and fail if any harness-launched process remains afterward; `-KeepRunning` is the only supported opt-out

Shared Files live UI regression:

- `scripts\run-shared-files-ui-e2e.ps1` is the operator-facing entrypoint for the real Win32 Shared Files regression
- it launches `emule.exe` with explicit `-ignoreinstances -c <profile-base>` so the run stays isolated from local user sessions
- the checked-in seed profile must stay initialized; the Python harness validates the seed keys, writes deterministic maximized window placement, and patches only per-run incoming, temp, and shared-directory paths
- the default UI run now covers two scenarios: the original three-file deterministic smoke case plus a generated recursive robustness tree under `C:\tmp\00_long_paths\shared_files_robustness`
- the regression asserts that the main window starts maximized and exercises exact default-name ordering, size ascending and descending sorts, name ascending and descending sorts after reload, selection-detail updates, reload preservation of the active descending size sort, and large-tree row-count/set/prefix checks driven by the generated manifest
- `-Scenario` can be repeated on the PowerShell wrapper to run only `fixture-three-files` or only `generated-robustness-recursive`
- each run publishes artifacts and `ui-summary.json` under `reports\shared-files-ui-e2e\...` and refreshes `reports\shared-files-ui-e2e-latest`
- the shared `reports\harness-summary.json` now includes a `live_ui` section when that regression is run

Startup-profile scenarios:

- `scripts\run-startup-profile-scenarios.ps1` builds deterministic Chrome Trace `startup-profile.trace.json` artifacts for multiple live-profile scenarios without changing app behavior
- the trace includes stable readiness, Shared Files hashing, Statistics dialog, and broadband lifecycle phase ids so Perfetto and the JSON summaries can separate startup, UI setup, queue wait, and worker-thread bring-up costs
- the default run covers `baseline-no-shares`, `fixture-three-files`, `long-paths-root-only`, `long-paths-recursive`, `long-path-output-root-only`, `long-path-output-recursive`, `long-path-emule-fixture-root-only`, `long-path-emule-fixture-recursive`, `shared-files-robustness-root-only`, and `shared-files-robustness-recursive`
- `-Scenario` can be repeated on the PowerShell wrapper to run only the scenarios you want
- `scripts\test_create_long_paths_tree.py` now lives in this repo and materializes the generated long-path fixture trees plus `generated-fixture-manifest.json` under `C:\tmp\00_long_paths`
- the long-path scenarios target `C:\tmp\00_long_paths` by default, regenerate the repo-owned fixture tree as needed, and expand `shareddir.dat` deterministically in the recursive cases
- each scenario summary now also records shareddir payload metrics plus tree-shape metrics such as depth, longest paths, and counts beyond the Windows path thresholds
- each scenario summary includes highlighted timings, normalized derived timings, and the top slowest startup phases, and the combined summary adds direct delta comparisons between the main long-path, generated output, and Shared Files robustness root-only vs recursive variants
- each run publishes scenario artifacts plus `startup-profiles-summary.json` and `startup-profiles-wrapper-summary.json` under `reports\startup-profile-scenarios\...` and refreshes `reports\startup-profile-scenarios-latest`
- the shared `reports\harness-summary.json` now includes a `startup_profiles` section when that runner is used

Tracked-file privacy guard:

- `scripts\guard-tracked-files.ps1` fails when tracked files contain local user-home paths or personal-identifier filename leaks derived from the current environment or an untracked local override file
- `scripts\build-emule-tests.ps1` runs that guard by default before building
- the same guard is enforced in GitHub Actions for pushes and pull requests

Native seam coverage and shared reports:

- `scripts\run-native-coverage.ps1` builds `emule-tests.exe`, runs the requested doctest suites under OpenCppCoverage, and writes Cobertura plus summary outputs under `reports\native-coverage`
- `scripts\run-bugfix-core-coverage.ps1` chains the canonical `main` and `bugfix` native-coverage runs with the workspace live-diff pass and writes a combined summary under `reports\bugfix-core-coverage`
- `helpers\helper-opencppcoverage-bootstrap.ps1` uses an explicit install root when provided, otherwise discovers `OpenCppCoverage.exe` from `PATH`, and finally falls back to a repo-managed pinned install under `tools\OpenCppCoverage`
- `scripts\run-live-diff.ps1` now writes both text and JSON parity/divergence summaries under `reports`
- `scripts\publish-harness-summary.ps1` combines native coverage, parity, optional live-harness manifest data, optional live UI status, and optional startup-profile scenario status into one shared summary under `reports`
