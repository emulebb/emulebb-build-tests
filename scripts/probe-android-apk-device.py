#!/usr/bin/env python3
"""Admit an exact physical-phone APK or perform a bounded, data-preserving smoke."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emule_test_harness.android_apk_device import AdbDevice, probe_physical_device
from emule_test_harness.android_apk_lifecycle import admit_payload
from emule_test_harness.android_apk_peer import admit_peer
from emule_test_harness.paths import get_workspace_output_root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--server-port", type=int, default=5037)
    parser.add_argument("--apk-payload", type=Path, required=True)
    parser.add_argument("--apk-manifest-name", required=True)
    parser.add_argument("--apk-manifest-sha256", required=True)
    parser.add_argument("--apk-source-sha", required=True)
    parser.add_argument("--expected-cert-sha256", required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--installation-receipt", type=Path)
    parser.add_argument("--installation-receipt-sha256")
    parser.add_argument("--dwell-seconds", type=int, default=30)
    parser.add_argument("--render-webui", action="store_true")
    parser.add_argument("--configure-storage", action="store_true")
    parser.add_argument("--allow-owned-compatible-update", action="store_true")
    parser.add_argument("--configuration-receipt", type=Path)
    parser.add_argument("--configuration-receipt-sha256")
    parser.add_argument("--compatibility-receipt", type=Path)
    parser.add_argument("--compatibility-receipt-sha256")
    parser.add_argument("--peer-payload", type=Path)
    parser.add_argument("--peer-manifest-sha256")
    parser.add_argument("--peer-abi", choices=("arm64-v8a", "x86_64"))
    parser.add_argument("--rust-source", type=Path)
    parser.add_argument("--probe-local-listeners", action="store_true")
    args = parser.parse_args()
    payload = admit_payload(args.apk_payload, args.apk_manifest_name,
                            source_sha=args.apk_source_sha, manifest_sha256=args.apk_manifest_sha256,
                            expected_cert_sha256=args.expected_cert_sha256)
    device = AdbDevice(args.adb, args.serial, server_port=args.server_port)
    peer_inputs = (args.peer_payload, args.peer_manifest_sha256, args.peer_abi, args.rust_source)
    if any(value is not None for value in peer_inputs) and (not all(value is not None for value in peer_inputs) or not args.execute):
        parser.error("Peer qualification requires --execute and all peer/source inputs")
    if args.probe_local_listeners and (not args.execute or not all(value is not None for value in peer_inputs)):
        parser.error("--probe-local-listeners requires --execute and all peer/source inputs")
    peer = None if args.peer_payload is None else admit_peer(args.peer_payload,
        manifest_sha256=args.peer_manifest_sha256, identity=payload["buildIdentity"], expected_abi=args.peer_abi)
    print(probe_physical_device(device.command, payload, serial=args.serial,
        expected_cert_sha256=args.expected_cert_sha256,
        output_root=get_workspace_output_root(), report_dir=args.report_dir, execute=args.execute,
        installation_receipt=args.installation_receipt, installation_receipt_sha256=args.installation_receipt_sha256,
        dwell_seconds=args.dwell_seconds, render_webui=args.render_webui, configure_storage=args.configure_storage,
        allow_owned_compatible_update=args.allow_owned_compatible_update,
        configuration_receipt=args.configuration_receipt, configuration_receipt_sha256=args.configuration_receipt_sha256,
        compatibility_receipt=args.compatibility_receipt, compatibility_receipt_sha256=args.compatibility_receipt_sha256,
        peer_payload=peer, rust_source=args.rust_source,
        peer_launcher=device.spawn_peer, peer_client_cleanup=device.stop_peer_client,
        probe_local_listeners=args.probe_local_listeners))


if __name__ == "__main__":
    main()
