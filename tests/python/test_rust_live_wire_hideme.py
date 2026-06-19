from __future__ import annotations

import importlib.util
from pathlib import Path


def load_live_wire_module():
    script_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "rust-live-wire-hideme.py"
    )
    spec = importlib.util.spec_from_file_location("rust_live_wire_hideme", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_udp_reask_protocol_log_counts_outbound_reasks_only(tmp_path: Path) -> None:
    module = load_live_wire_module()
    log_path = tmp_path / "daemon.out"
    log_path.write_text(
        "\n".join(
            [
                "ed2k udp reask loop started",
                "ed2k udp reask: PKT-IN <- 192.0.2.20:4672 (51 bytes) hex=abcd",
                "ed2k udp reask: routed reply from 192.0.2.21:4672",
                "ed2k udp reask: PKT-OUT reask ping -> 192.0.2.22:4672 (35 bytes) hex=abcd",
                "ed2k udp reask: reask to 192.0.2.22:4672 timed out: RetryUdp",
                "ed2k udp reask: PKT-OUT reask ping -> 192.0.2.23:4672 (35 bytes) hex=abcd",
                "Kad source accepted",
            ]
        ),
        encoding="utf-8",
    )

    counts = module.count_log_matches(log_path, ("udp reask", "Kad source"))

    assert counts == {"udp reask": 2, "Kad source": 1}


def test_p2p_bound_to_uses_python_socket_inventory(monkeypatch) -> None:
    module = load_live_wire_module()

    def fake_listening_socket_addresses(protocol: str) -> list[tuple[str, int]]:
        if protocol == "tcp":
            return [("192.0.2.10", module.ED2K_PORT)]
        if protocol == "udp":
            return [("192.0.2.10", module.KAD_PORT)]
        raise AssertionError(f"unexpected protocol {protocol}")

    monkeypatch.setattr(
        module, "_listening_socket_addresses", fake_listening_socket_addresses
    )

    assert module.p2p_bound_to("192.0.2.10")
    assert not module.p2p_bound_to("192.0.2.11")
