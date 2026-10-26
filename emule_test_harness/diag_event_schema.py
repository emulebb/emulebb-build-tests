"""Canonical schemas for current diagnostic events and derived reports."""

DIAG_EVENT_SCHEMA = "diag_event_v2"
DIAG_EVENT_DIFF_REPORT_SCHEMA = "diag_event_diff_v1"
DIAG_EVENT_SCHEMA_AUDIT_REPORT_SCHEMA = "diag_event_schema_audit_v1"
DIAG_EVENT_FAMILY_CONFORMANCE_REPORT_SCHEMA = "diag_event_family_conformance_v1"

ED2K_CLIENT_UDP_FAMILY = "ed2k_client_udp"
ED2K_TCP_FAMILY = "ed2k_tcp"
KAD_EVENT_FAMILY = "kad_event"
KAD_UDP_FAMILY = "kad_udp"
FULL_RUN_REQUIRED_PARITY_FAMILIES = frozenset({ED2K_CLIENT_UDP_FAMILY, ED2K_TCP_FAMILY})
PERSISTED_SOAK_REQUIRED_PARITY_FAMILIES = frozenset(
    {
        ED2K_CLIENT_UDP_FAMILY,
        ED2K_TCP_FAMILY,
        KAD_EVENT_FAMILY,
        KAD_UDP_FAMILY,
    }
)

LEGACY_DIAG_EVENT_SCHEMA = "diag_event_v1"
