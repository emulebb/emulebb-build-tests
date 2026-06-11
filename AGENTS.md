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
