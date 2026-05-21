# Rules

- Read `EMULE_WORKSPACE_ROOT\repos\eMule-tooling\docs\WORKSPACE-POLICY.md`
  before test-harness work; it is authoritative for workspace-wide rules.
- This file contains test-repo local deltas only. Do not duplicate branch,
  worktree, setup, dependency, or app-source policy here.
- Python is the canonical runtime for live, UI, and harness scripts in this
  repo.
- Operator-facing Python script filenames are hyphenated; importable Python
  implementation modules stay under `emule_test_harness` with snake_case names.
- New reusable harness helpers should include succinct docstrings or comments
  when their behavior is not obvious.
