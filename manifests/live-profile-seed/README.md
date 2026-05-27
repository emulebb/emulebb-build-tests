# Live Profile Seed

This directory stores the deterministic test-only profile baseline for live REST E2E, live named-pipe, and live UI runs.

The `config` subtree is shaped like an eMule profile so the live harness can copy it directly into a fresh working folder.

The seed is intentionally minimal:

- `preferences.ini`
- `preferences.dat`
- `nodes.dat`
- `server.met`

The live harness validates this exact allowlist before copying the seed. Adding
logs, caches, `shareddir.dat`, downloaded state, or diagnostic leftovers here is
a test setup error; those files belong in per-run artifacts.

The seeded `preferences.ini` must stay UTF-16LE with BOM, matching eMule's
profile-file write path, and limited to the non-default settings that the live
harness truly needs before runtime overrides are applied.

Runtime overrides belong in `emule_test_harness.live_profiles`, not in
scenario-local INI patch loops or expanded seed files. The profile builder
copies this seed into a fresh per-run profile, then applies typed Python specs
for mutable directories, shared-directory lists, live network policy, and
WebServer/REST settings.

Required initialized `preferences.ini` keys are enforced by
`emule_test_harness.live_profile_seed` so first-run UI prompts do not leak into
live automation.

The seeded `preferences.dat` carries the deterministic maximized main-window
placement used by the live UI and startup-profile harnesses. Profile builders
rewrite it per scenario with a stable deterministic client hash so forced
restart tests keep the same eMule identity across kill/relaunch cycles.

Mutable runtime state such as logs, temp files, downloads, and rolling history files must not be committed here.

Live Arr credentials are intentionally not stored beside this seed. Put local
Prowlarr/Radarr/Sonarr values in process environment variables or an ignored
`.env.local` selected with `--env-file`. The tracked root `.env.example` file is
the redacted template for those local values.
