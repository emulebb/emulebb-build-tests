from __future__ import annotations

from pathlib import Path

from emule_test_harness import release_campaigns, release_coverage


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def campaign_scenario_ids() -> set[str]:
    campaign = release_campaigns.load_release_campaign(repo_root(), "emule-bb-0.7.3")
    return {
        scenario["id"]
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }


def test_release_coverage_manifest_validates_against_campaign() -> None:
    manifest = release_coverage.load_release_coverage_manifest(repo_root())
    validation = release_coverage.validate_release_coverage_manifest(
        manifest,
        campaign_scenario_ids=campaign_scenario_ids(),
    )

    assert validation.errors == ()


def test_release_coverage_manifest_keeps_required_weak_areas_owned() -> None:
    manifest = release_coverage.load_release_coverage_manifest(repo_root())

    assert release_coverage.release_candidate_area_ids(manifest) >= {
        "protocol-tags-kad-ed2k",
        "kad-ed2k-persistence-files",
        "profile-preferences-formats",
        "ed2k-links-collections",
        "friend-source-dialog-inputs",
        "direct-download-dialog-inputs",
        "category-scheduler-dialog-inputs",
        "controller-rest-arr-amutorrent",
        "live-profile-policy",
        "server-ipfilter-update-flows",
        "irc-chat-friends",
        "archive-preview-comment-diagnostics",
        "packaging-provenance",
    }


def test_release_coverage_manifest_rejects_blocking_area_without_campaign_owner() -> None:
    manifest = release_coverage.clone_manifest(release_coverage.load_release_coverage_manifest(repo_root()))
    manifest["areas"][0]["campaignScenarioIds"] = []

    validation = release_coverage.validate_release_coverage_manifest(manifest)

    assert "protocol-tags-kad-ed2k: blocking areas must map to a campaign scenario." in validation.errors


def test_release_coverage_manifest_rejects_deferred_blocking_area() -> None:
    manifest = release_coverage.clone_manifest(release_coverage.load_release_coverage_manifest(repo_root()))
    for area in manifest["areas"]:
        if area["id"] == "irc-chat-friends":
            area["blocking"] = True
            break

    validation = release_coverage.validate_release_coverage_manifest(manifest)

    assert "irc-chat-friends: deferred areas cannot be blocking release gates." in validation.errors
