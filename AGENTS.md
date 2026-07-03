# Rules

- Read `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`
  first; it is authoritative for workspace-wide rules.
- Start from
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\reference\AGENT-CHECKLIST.md`
  for the repeatable operating path.

Everything below is this repo's local deltas only:

- Python is the canonical runtime for live, UI, and harness scripts in this
  repo.
- Operator-facing Python script filenames are hyphenated; importable Python
  implementation modules stay under `emule_test_harness` with snake_case names.
- New reusable harness helpers should include succinct docstrings or comments
  when their behavior is not obvious.

## Survey before adding a script or helper (avoid duplicates)

This repo has ~95 `scripts/*.py` and ~64 `emule_test_harness/*.py` modules, so
ad-hoc helpers routinely duplicate one that already exists. Before creating ANY
new file (and never leave a reusable helper in a session scratchpad or under the
build output root — it will vanish and get re-created):

1. Search both trees for the capability and skim the top docstring of each hit —
   every helper documents its purpose on the first line or two:
   `rg -il "<capability keywords>" scripts emule_test_harness`
   (a one-line capability index: `for f in scripts/*.py emule_test_harness/*.py; do sed -n '1{s/^"""//;s/"""$//;p}' "$f" | sed "s#^#$f: #"; done`).
2. Prefer, in order: (a) call an existing `emule_test_harness` module; (b) add a
   flag/branch to the closest existing script; (c) add a snake_case module under
   `emule_test_harness` + a thin hyphenated `scripts/` wrapper. Only add a
   standalone script when nothing fits.
3. Reuse the shared analysis/soak modules instead of re-parsing or re-launching
   inline: `diag_event_diff`, `packet_trace_diff`, `diagnostic_logs`,
   `soak_report_summary`, `soak_action_diff`, `soak_launch`.
4. If you still add a new file, state in the commit message what you searched for
   and why no existing helper fit.
