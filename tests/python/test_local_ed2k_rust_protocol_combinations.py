from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from emule_test_harness import rust_metadata


def _rust_repo() -> Path:
    return Path(__file__).resolve().parents[3] / "emulebb-rust"


def load_suite_module():
    """Loads the hyphenated Rust protocol-combination script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "local-ed2k-rust-protocol-combinations.py"
    spec = importlib.util.spec_from_file_location("local_ed2k_rust_protocol_combinations_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_rust_server_entry_advertises_obfuscated_tcp_without_udp_for_no_udp_case() -> None:
    module = load_suite_module()
    case = module.protocol_matrix.PROTOCOL_CASE_MAP["obfuscated-required-no-server-udp-compressible"]

    entry = module.rust_server_entry(case, "192.0.2.10", 4661)

    assert entry["host"] == "192.0.2.10"
    assert entry["port"] == 4661
    assert entry["obfuscationPortTcp"] == 4661
    assert entry["obfuscationPortUdp"] == 0
    assert entry["udpKey"] == 0
    assert entry["udpFlags"] & module.SERVER_UDP_FLAG_TCPOBFUSCATION
    assert not entry["udpFlags"] & module.SERVER_UDP_FLAG_UDPOBFUSCATION


def test_rust_server_entry_omits_obfuscation_for_plain_case() -> None:
    module = load_suite_module()
    case = module.protocol_matrix.PROTOCOL_CASE_MAP["plain-server-plain-clients"]

    entry = module.rust_server_entry(case, "192.0.2.10", 4661)

    assert entry["obfuscationPortTcp"] == 0
    assert entry["obfuscationPortUdp"] == 0
    assert entry["udpKey"] == 0
    assert not entry["udpFlags"] & module.SERVER_UDP_FLAG_TCPOBFUSCATION
    assert not entry["udpFlags"] & module.SERVER_UDP_FLAG_UDPOBFUSCATION


def test_rust_protocol_surface_discloses_single_obfuscation_toggle() -> None:
    module = load_suite_module()
    case = module.protocol_matrix.PROTOCOL_CASE_MAP["obfuscated-required"]

    surface = module.rust_protocol_surface(case)

    assert surface["client_crypt_required"] is True
    assert surface["rust_client_crypt"]["obfuscation_enabled"] is True
    assert surface["rust_client_crypt"]["required_preference_supported"] is False


def test_rust_protocol_fixture_name_is_unicode_for_every_case() -> None:
    module = load_suite_module()

    names = [module.protocol_fixture_name(case) for case in module.protocol_matrix.PROTOCOL_CASES]
    secondary_names = [module.secondary_protocol_fixture_name(case) for case in module.protocol_matrix.PROTOCOL_CASES]
    hash_only_names = [module.hash_only_protocol_fixture_name(case) for case in module.protocol_matrix.PROTOCOL_CASES]

    assert all("Unicode-\u00e9-\u6f22" in name for name in names)
    assert all("Unicode-\u00e9-\u6f22" in name for name in secondary_names)
    assert all("Unicode-\u00e9-\u6f22" in name for name in hash_only_names)
    assert all(not name.isascii() for name in names)
    assert all(not name.isascii() for name in secondary_names)
    assert all(not name.isascii() for name in hash_only_names)
    assert len(set(names)) == len(module.protocol_matrix.PROTOCOL_CASES)
    assert len(set(secondary_names)) == len(module.protocol_matrix.PROTOCOL_CASES)
    assert len(set(hash_only_names)) == len(module.protocol_matrix.PROTOCOL_CASES)
    assert set(names).isdisjoint(secondary_names)
    assert set(names).isdisjoint(hash_only_names)
    assert set(secondary_names).isdisjoint(hash_only_names)


def test_decoded_ed2k_link_name_preserves_unicode_filename() -> None:
    module = load_suite_module()

    decoded = module.decoded_ed2k_link_name({"name": "rust-plain-Unicode-%C3%A9-%E6%BC%A2.bin"})

    assert decoded == "rust-plain-Unicode-\u00e9-\u6f22.bin"
    assert not decoded.isascii()


def test_full_rust_protocol_coverage_requires_all_surfaces() -> None:
    module = load_suite_module()

    coverage = module.require_protocol_coverage(
        list(module.protocol_matrix.PROTOCOL_CASES),
        require_full_matrix=True,
    )

    assert coverage["caseCount"] == len(module.protocol_matrix.PROTOCOL_CASES)
    assert coverage["missingRequiredCaseNames"] == []
    assert coverage["plainServerPlainClients"] is True
    assert coverage["obfuscatedPreferred"] is True
    assert coverage["obfuscatedRequired"] is True
    assert coverage["serverUdpDisabled"] is True
    assert coverage["compressibleFixture"] is True
    assert coverage["lowCompressibilityFixture"] is True
    assert coverage["unicodeFixtureNames"] is True
    assert coverage["multiTransferFixtureNames"] is True
    assert coverage["hashOnlyFixtureNames"] is True


def test_full_rust_protocol_coverage_rejects_missing_surfaces() -> None:
    module = load_suite_module()
    cases = [module.protocol_matrix.PROTOCOL_CASE_MAP["plain-server-plain-clients"]]

    try:
        module.require_protocol_coverage(cases, require_full_matrix=True)
    except RuntimeError as exc:
        assert "obfuscated-preferred" in str(exc)
        assert "obfuscatedRequired" in str(exc)
    else:
        raise AssertionError("partial Rust protocol matrix coverage was accepted as a full run")


def test_selected_rust_protocol_coverage_reports_partial_surface_without_failing() -> None:
    module = load_suite_module()
    cases = [module.protocol_matrix.PROTOCOL_CASE_MAP["plain-server-plain-clients"]]

    coverage = module.require_protocol_coverage(cases, require_full_matrix=False)

    assert coverage["fullMatrixRequired"] is False
    assert coverage["plainServerPlainClients"] is True
    assert coverage["obfuscatedPreferred"] is False
    assert "obfuscated-required" in coverage["missingRequiredCaseNames"]


def passing_case_result(module, name: str, *, has_user_hash: bool) -> dict[str, object]:
    """Builds a compact post-run case result for aggregate coverage tests."""

    source_metadata = {
        "hasUserHash": has_user_hash,
        "userHash": "00112233445566778899aabbccddeeff" if has_user_hash else None,
    }
    hashset_metadata = {
        "md4HashsetCount": 2,
        "aichHashsetCount": 2,
    }
    return {
        "name": name,
        "status": "passed",
        "checks": {
            "rust_multi_transfer_sequence": {
                "transferCount": 3,
                "hashOnlyMetadataRecovery": True,
            },
            "rust_hash_only_transfer_metadata": {
                "name": f"{name}-hash-only-Unicode-\u00e9-\u6f22.bin",
                "sizeBytes": module.HASH_ONLY_FIXTURE_SIZE_BYTES,
            },
            "rust_hashset_metadata": hashset_metadata,
            "rust_secondary_hashset_metadata": hashset_metadata,
            "rust_source_metadata": source_metadata,
            "rust_secondary_source_metadata": source_metadata,
            "rust_hash_only_source_metadata": source_metadata,
        },
    }


def test_rust_protocol_case_requirements_accept_complete_matrix_evidence() -> None:
    module = load_suite_module()

    coverage = module.require_case_result_coverage(
        [
            passing_case_result(module, "plain-server-plain-clients", has_user_hash=False),
            passing_case_result(module, "obfuscated-preferred", has_user_hash=True),
        ]
    )

    assert coverage["caseCount"] == 2
    assert coverage["allCasesPassed"] is True
    assert coverage["threeTransfersPerCase"] is True
    assert coverage["hashOnlyMetadataRecoveryPerCase"] is True
    assert coverage["unicodeHashOnlyMetadataPerCase"] is True
    assert coverage["namedTransferHashsetsPerCase"] is True
    assert coverage["obfuscatedSourceUserHashPerCase"] is True


def test_rust_protocol_case_requirements_reject_missing_hash_only_recovery() -> None:
    module = load_suite_module()
    case = passing_case_result(module, "obfuscated-required", has_user_hash=True)
    case["checks"]["rust_multi_transfer_sequence"]["hashOnlyMetadataRecovery"] = False

    try:
        module.require_case_result_coverage([case])
    except RuntimeError as exc:
        assert "hashOnlyMetadataRecovery" in str(exc)
    else:
        raise AssertionError("missing hash-only metadata recovery was accepted")


def test_rust_protocol_cases_reuse_shared_goed2k_launcher() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "goed2k.prepare_ed2k_server_binary(" in script_text
    assert "goed2k.launch_ed2k_server(" in script_text
    assert "goed2k.resolve_ed2k_server_exe(" not in script_text
    assert "goed2k.build_ed2k_server_binary(" not in script_text
    assert "goed2k.start_ed2k_server(" not in script_text
    assert "goed2k.build_server_config(" not in script_text


def test_obfuscated_rust_source_metadata_requires_peer_user_hash() -> None:
    module = load_suite_module()
    case = module.protocol_matrix.PROTOCOL_CASE_MAP["obfuscated-required-no-server-udp-compressible"]

    metadata = module.require_rust_source_metadata(
        case,
        [
            {
                "endpoint": "192.0.2.44:4662",
                "ip": "192.0.2.44",
                "tcpPort": 4662,
                "clientId": "00112233445566778899aabbccddeeff",
                "userHash": "00112233445566778899aabbccddeeff",
            }
        ],
        expected_ip="192.0.2.44",
        expected_tcp_port=4662,
    )

    assert metadata["hasUserHash"] is True
    assert metadata["obfuscatedSourceIdentityRequired"] is True
    assert metadata["userHash"] == "00112233445566778899aabbccddeeff"


def test_obfuscated_rust_source_metadata_rejects_missing_peer_user_hash() -> None:
    module = load_suite_module()
    case = module.protocol_matrix.PROTOCOL_CASE_MAP["obfuscated-required"]

    try:
        module.require_rust_source_metadata(
            case,
            [{"endpoint": "192.0.2.44:4662", "ip": "192.0.2.44", "tcpPort": 4662}],
            expected_ip="192.0.2.44",
            expected_tcp_port=4662,
        )
    except RuntimeError as exc:
        assert "userHash" in str(exc)
    else:
        raise AssertionError("missing obfuscated peer userHash was accepted")


def test_rust_hashset_metadata_accepts_large_file_manifest(tmp_path: Path) -> None:
    module = load_suite_module()
    rust_metadata.create_metadata_db(_rust_repo(), tmp_path / "metadata.sqlite")
    rust_metadata.seed_transfer_manifest(
        tmp_path / "metadata.sqlite",
        ed2k_hash="00112233445566778899aabbccddeeff",
        name="large-fixture.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES + 1,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100",
        ],
        aich_hashset_acquired=True,
        aich_root="0123456789abcdef0123456789abcdef01234567",
        aich_hashset=[
            "0123456789abcdef0123456789abcdef01234567",
            "89abcdef0123456789abcdef0123456789abcdef",
        ],
    )

    metadata = module.require_rust_hashset_metadata(
        tmp_path / "metadata.sqlite",
        expected_hash="00112233445566778899AABBCCDDEEFF",
        expected_name="large-fixture.bin",
        expected_size=module.ED2K_PART_SIZE_BYTES + 1,
    )

    assert metadata["expectedPartCount"] == 2
    assert metadata["md4HashsetAcquired"] is True
    assert metadata["md4HashsetCount"] == 2
    assert metadata["aichHashsetAcquired"] is True
    assert metadata["aichHashsetCount"] == 2


def test_rust_hashset_metadata_rejects_missing_large_file_aich(tmp_path: Path) -> None:
    module = load_suite_module()
    rust_metadata.create_metadata_db(_rust_repo(), tmp_path / "metadata.sqlite")
    rust_metadata.seed_transfer_manifest(
        tmp_path / "metadata.sqlite",
        ed2k_hash="00112233445566778899aabbccddeeff",
        name="large-fixture.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES + 1,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100",
        ],
        aich_hashset_acquired=False,
        aich_root=None,
        aich_hashset=[],
    )

    try:
        module.require_rust_hashset_metadata(
            tmp_path / "metadata.sqlite",
            expected_hash="00112233445566778899aabbccddeeff",
            expected_name="large-fixture.bin",
            expected_size=module.ED2K_PART_SIZE_BYTES + 1,
        )
    except RuntimeError as exc:
        assert "AICH" in str(exc)
    else:
        raise AssertionError("missing large-file AICH metadata was accepted")
