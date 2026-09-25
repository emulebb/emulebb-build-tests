from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "smoke-rust-gluetun.py"
    spec = importlib.util.spec_from_file_location("rust_gluetun_smoke_under_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_zero_packets_are_not_inferred_from_timeout_exit_code() -> None:
    module = load_module()
    result = subprocess.CompletedProcess(
        args=["tcpdump"], returncode=0, stdout="",
        stderr="0 packets captured\n0 packets received by filter\n",
    )
    assert module.captured_packet_count(result) == 0


def test_positive_packet_is_counted_from_capture_output() -> None:
    module = load_module()
    result = subprocess.CompletedProcess(
        args=["tcpdump"], returncode=0,
        stdout="16:24:20 veth0 P 192.0.2.2 > 198.51.100.1: UDP, length 58\n",
        stderr="1 packet captured\n",
    )
    assert module.captured_packet_count(result) == 1


def test_empty_capture_without_summary_is_not_a_pass() -> None:
    module = load_module()
    result = subprocess.CompletedProcess(
        args=["tcpdump"], returncode=0, stdout="", stderr="",
    )
    with pytest.raises(RuntimeError, match="no capture summary"):
        module.captured_packet_count(result)
