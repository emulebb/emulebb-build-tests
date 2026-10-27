"""Create or refresh an eMuleBB Rust profile from stock eMule metadata."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import mfc_known_met, mfc_profile_import  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create a fresh persisted Rust profile.")
    create.add_argument("--rust-repo", type=Path, required=True)
    create.add_argument("--emule-profile-dir", type=Path, required=True)
    create.add_argument("--rust-profile-dir", type=Path, required=True)
    create.add_argument("--kad-bootstrap-limit", type=int, default=40)
    create.add_argument("--import-user-hash", action="store_true")
    create.add_argument(
        "--rest-addr",
        default=mfc_profile_import.DEFAULT_REST_ADDR,
        help="Rust REST bind address. Defaults to inherited X_LOCAL_IP; loopback is not a live profile default.",
    )
    create.add_argument("--rest-port", type=int, default=mfc_profile_import.DEFAULT_REST_PORT)
    create.add_argument("--api-key", default=mfc_profile_import.DEFAULT_API_KEY)
    create.add_argument(
        "--p2p-bind-ip",
        help="Rust daemon P2P bind IP override. Normally leave unset and bind P2P through --p2p-bind-interface.",
    )
    create.add_argument(
        "--p2p-bind-interface",
        default=mfc_profile_import.DEFAULT_P2P_BIND_INTERFACE,
        help="Rust daemon P2P bind interface. Defaults to hide.me.",
    )
    create.add_argument("--ed2k-port", type=int, default=mfc_profile_import.DEFAULT_ED2K_PORT)
    create.add_argument("--kad-port", type=int, default=mfc_profile_import.DEFAULT_KAD_PORT)
    create.add_argument("--dry-run", action="store_true")

    upsert = subparsers.add_parser(
        "upsert-hashes",
        help="Refresh hashes and native fingerprints in an existing persisted Rust profile.",
    )
    upsert.add_argument("--rust-repo", type=Path, required=True)
    upsert.add_argument("--emule-profile-dir", type=Path, required=True)
    upsert.add_argument("--rust-profile-dir", type=Path, required=True)
    upsert.add_argument("--dry-run", action="store_true")

    inspect_servers = subparsers.add_parser(
        "inspect-servers",
        help="List ordered eD2K server candidates from the persisted MFC profile.",
    )
    inspect_servers.add_argument("--emule-profile-dir", type=Path, required=True)
    inspect_servers.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    if args.command == "create":
        summary = mfc_profile_import.import_stock_mfc_profile(
            rust_repo=args.rust_repo,
            emule_config_dir=mfc_profile_import.resolve_mfc_config_dir(args.emule_profile_dir),
            rust_profile_dir=args.rust_profile_dir,
            kad_bootstrap_limit=args.kad_bootstrap_limit,
            import_user_hash=args.import_user_hash,
            rest_addr=args.rest_addr,
            rest_port=args.rest_port,
            api_key=args.api_key,
            p2p_bind_ip=args.p2p_bind_ip,
            p2p_bind_interface=args.p2p_bind_interface,
            ed2k_port=args.ed2k_port,
            kad_port=args.kad_port,
            dry_run=args.dry_run,
        )
    elif args.command == "upsert-hashes":
        summary = mfc_profile_import.upsert_stock_mfc_profile_hashes(
            rust_repo=args.rust_repo,
            mfc_profile_dir=args.emule_profile_dir,
            rust_profile_dir=args.rust_profile_dir,
            dry_run=args.dry_run,
        )
    else:
        summary = mfc_profile_import.inspect_stock_mfc_servers(
            args.emule_profile_dir,
            limit=args.limit,
        )
    print(mfc_known_met.summary_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
