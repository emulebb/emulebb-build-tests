# Rules

- Read
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`
  first.
- For work in this repo, also read the routed
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\reference\HARNESS-LIVE-POLICY.md`
  annex. Read the Rust product annex as well only when product/schema behavior
  is involved.

Everything below is this repo's local delta only.

- Python is the canonical runtime for live, UI, and harness automation.
  Operator scripts use hyphenated filenames; importable implementation modules
  live under `emule_test_harness` with snake_case names.
- Reusable helpers need succinct docstrings or comments where behavior is not
  obvious.
- Rust metadata schema-evolution helpers are internal infrastructure for known
  persisted test and soak schemas only. Keep them explicit, bounded, and
  backup-first. Never present them as end-user migration or recovery paths.
- For Rust public-network tests, prefer WSL2 plus Docker with the plain OpenVPN
  lane in `scripts/smoke-rust-openvpn.py`. Use Gluetun or Windows hide.me only
  when the scenario requires that topology. Keep VPN inputs outside the
  workspace and mount them read-only.

## Survey Before Adding A Helper

This repo already has a large `scripts` and `emule_test_harness` surface.
Before creating a file:

1. Search both trees with `rg -il "<capability keywords>" scripts
   emule_test_harness` and skim matching module docstrings.
2. Prefer, in order: call an existing module; extend the closest script; add a
   reusable snake_case module plus a thin hyphenated wrapper. Add a standalone
   script only when no owner fits.
3. Reuse `diag_event_diff`, `packet_trace_diff`, `diagnostic_logs`,
   `soak_report_summary`, `soak_action_diff`, and `soak_launch` rather than
   re-parsing or re-launching inline.
4. If a new file is still required, state what was searched and why no existing
   helper fit in the commit message.

Never leave a reusable helper in a session scratchpad or generated output root.
