# Common Diagnostic Event Schema — `diag_event_v2`

`diag_event_v2` is the only current diagnostic-event envelope for both
emulebb-rust and eMuleBB MFC diagnostics builds. Current writers, harness
loaders, semantic diffs, and soak gates must not emit or accept
`diag_event_v1`. A legacy source may enter the current pipeline only through an
explicitly named adapter that emits a complete v2 envelope.

These traces are local-only test evidence. Writers preserve exact identifiers,
names, hashes, endpoints, search values, and packet payloads. The harness does
not redact fields or excuse privacy-based omissions. Runtime traces must not be
uploaded, attached to pull requests, or committed.

## Envelope

Every retained record contains:

```json
{
  "schema": "diag_event_v2",
  "client": "rust",
  "ts": "2026-10-24T12:00:00.000Z",
  "runId": "opaque-run-id",
  "processId": 1234,
  "segmentId": 0,
  "seq": 1,
  "streamSeq": 1,
  "family": "sched",
  "event": "source_count",
  "severity": "info",
  "keys": {},
  "body": {}
}
```

| Field | Contract |
| --- | --- |
| `schema` | Literal `diag_event_v2`. |
| `client` | Literal `rust` or `mfc`. |
| `runId` | Opaque identity created once per diagnostics process launch. |
| `processId` | Operating-system process ID for the launch. |
| `segmentId` | Monotonically increasing file segment within one run. |
| `seq` | Strict process-wide retained-event order across families and segments. |
| `streamSeq` | Strict retained-event order within one `family`. |

Sequence numbers advance only after a complete JSONL record is retained. A
dropped event is reflected in writer health instead of creating a sequence gap.

## Client UDP Family

`ed2k_client_udp` is a mixed packet-and-lifecycle family inside the same
`diag_event_v2` envelope. It does not define another diagnostic schema.

Packet records use `event: "packet"`. Their body includes `direction`, exact
wire `rawHex`, and `rawLen`; decoded fields such as `protocolMarker`, `opcode`,
`opcodeName`, `role`, and encryption state are retained when known. Receive
records classify processing as `accepted`, `ignored`, or `dropped`. Malformed
or unknown datagrams still retain the exact wire bytes even when no opcode can
be decoded.

Every socket-boundary send is represented by:

1. one `packet` record with `direction: "send"`, `outcome: "attempted"`, and a
   positive `sendAttemptId`;
2. exactly one `send_outcome` record carrying the same `sendAttemptId` and an
   outcome of `send_succeeded`, `send_failed`, or `send_cancelled`.

`deliveryKnown` is `true` for success and failure and `false` for cancellation.
A retry after a would-block result cancels the first attempt and creates a new
attempt ID. Attempt IDs are process-local correlation keys; semantic diffs
audit each side independently and never require IDs to match across clients.

Complete-capture conformance requires this family on both clients and rejects
missing, duplicate, orphaned, invalid, or out-of-order send terminals. Narrow
action-window comparisons remain sampling-tolerant because a valid attempt or
terminal may fall outside the selected window.

## Files

```text
emulebb-rust-diag-<processId>-<runId>-<segmentId:06>.jsonl
emulebb-mfc-diag-<processId>-<runId>-<segmentId:06>.jsonl
```

MFC publishes `emulebb-mfc-diag-health.json`. Rust exposes the same writer
health fields as `diagnosticWriter` in runtime diagnostics and bundles.

Writers rotate before a record would exceed the configured byte or age limit.
Retention is a global cap across persisted launches in one log directory. The
active segment is never deleted.

## Consumer Rules

Current consumers must:

1. discover only the client-specific segmented names above;
2. group names by `(client, processId, runId)`;
3. select exactly one newest run, or the explicitly requested process;
4. reject duplicate or non-contiguous segment IDs;
5. preserve numeric `segmentId` order;
6. require matching client, process, run, and segment identity in every record;
7. require contiguous process-wide `seq` values across retained segments;
8. reject malformed complete lines and foreign schemas;
9. tolerate only one final unterminated line in the newest active segment;
10. validate matching writer health and fail on drops or writer errors.

Derived diff, audit, and conformance reports use their own report schemas. They
must never identify themselves as `diag_event_v2` records.
