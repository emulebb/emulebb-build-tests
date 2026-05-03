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

The seeded `preferences.ini` must stay limited to the non-default settings that the live harness truly needs before runtime overrides are applied.

Required initialized `preferences.ini` keys are enforced by
`emule_test_harness.live_profile_seed` so first-run UI prompts do not leak into
live automation.

The seeded `preferences.dat` carries the deterministic maximized main-window placement used by the live UI and startup-profile harnesses.

Mutable runtime state such as logs, temp files, downloads, and rolling history files must not be committed here.

Live Arr credentials are intentionally not stored beside this seed. Put local
Prowlarr/Radarr/Sonarr values in process environment variables or an ignored
`.env.local` selected with `--env-file`.

```dotenv
PROWLARR_URL=http://127.0.0.1:9696
PROWLARR_API_KEY=<redacted>
PROWLARR_EMULEBB_INDEXER_NAME=eMule BB Local
RADARR_URL=http://127.0.0.1:7878
RADARR_API_KEY=<redacted>
SONARR_URL=http://127.0.0.1:8989
SONARR_API_KEY=<redacted>
```
