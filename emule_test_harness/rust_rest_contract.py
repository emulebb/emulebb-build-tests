"""Shared constants for the emulebb-rust native REST contract."""

from __future__ import annotations

REST_CONTRACT_VERSION = "2.0.0"
REST_CONTRACT_VERSION_HEADER = "X-Contract-Version"

# Compile-time packet-diagnostics controls are private harness surfaces. They
# are intentionally implemented by diagnostics builds and intentionally absent
# from the public product OpenAPI document.
RUST_PRIVATE_DIAGNOSTICS_ROUTES = frozenset(
    {
        ("POST", "/api/v1/diagnostics/protocol-fixtures/buddy-relay-eligibility"),
        ("POST", "/api/v1/diagnostics/protocol-fixtures/queued-lowid-sources"),
    }
)
