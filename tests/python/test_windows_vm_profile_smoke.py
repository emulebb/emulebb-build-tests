from __future__ import annotations

from emule_test_harness import windows_vm_profile_smoke


def test_local_swarm_contract_records_selected_tier() -> None:
    check = windows_vm_profile_smoke.local_swarm_contract_check("search-ui-local-swarm-vm", 3)

    assert check["status"] == "passed"
    assert check["details"]["selectedSwarmTier"] == 3
    assert check["details"]["swarmTiers"] == [1, 2, 3]
    assert check["details"]["vmProfile"] == "search-ui-local-swarm-vm"
    assert check["details"]["localSuites"] == ["local-ed2k-search-soak", "local-kad-swarm"]


def test_profile_smoke_parser_accepts_swarm_tier() -> None:
    args = windows_vm_profile_smoke.build_parser().parse_args(
        [
            "--profile",
            "search-ui-local-swarm-vm",
            "--root",
            "C:/tmp/root",
            "--target",
            "win10",
            "--package-zip",
            "C:/tmp/package.zip",
            "--username",
            "emulebbtest",
            "--password",
            "a",
            "--swarm-tier",
            "2",
            "--harness-root",
            "C:/tmp/harness",
        ]
    )

    assert args.swarm_tier == 2
    assert str(args.harness_root).replace("\\", "/").endswith("C:/tmp/harness")


def test_local_swarm_payload_check_accepts_staged_harness(tmp_path) -> None:
    harness_root = tmp_path / "harness"
    (harness_root / "emule_test_harness").mkdir(parents=True)
    (harness_root / "emule_test_harness" / "live_e2e_suite.py").write_text("", encoding="utf-8")
    scripts = harness_root / "scripts"
    scripts.mkdir()
    for name in (
        "godzilla-local-swarm.py",
        "local-ed2k-search-soak.py",
        "local-kad-swarm.py",
        "amutorrent-local-ed2k-ui-live.py",
    ):
        (scripts / name).write_text("", encoding="utf-8")

    check = windows_vm_profile_smoke.local_swarm_payload_check(harness_root)

    assert check["status"] == "passed"


def test_local_swarm_payload_check_reports_missing_harness() -> None:
    check = windows_vm_profile_smoke.local_swarm_payload_check(None)

    assert check["status"] == "failed"
