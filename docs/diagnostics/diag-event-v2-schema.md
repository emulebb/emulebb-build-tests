# Rust Diagnostic Event Schema — `diag_event_v2`

`diag_event_v2` is the bounded Rust evolution of the common
`diag_event_v1` envelope documented in `diag-event-v1-schema.md`. Event-family
`keys` and `body` remain semantically comparable with MFC `diag_event_v1`
records. The incompatible change is the addition of explicit process/run/segment
identity and authoritative sequence semantics.

## Envelope

Every retained Rust record contains:

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
| `runId` | Opaque identity created once per diagnostics process launch. |
| `processId` | Operating-system process ID for the launch. |
| `segmentId` | Zero-based, monotonically increasing file segment within one run. |
| `seq` | Strict process-wide retained-event order across every family and segment. |
| `streamSeq` | Strict retained-event order within one `family`. |

Sequence numbers advance only after a complete JSONL record is retained. A
dropped event is reflected in writer health instead of creating a sequence gap.

## Files and Retention

Rust segments use:

```text
emulebb-rust-diag-<processId>-<runId>-<segmentId:06>.jsonl
```

The writer rotates before a record would exceed the configured segment byte
limit, or when the configured segment age has elapsed. The retention count is a
global cap across persisted launches in one log directory, not a per-run cap.
The current active segment is never selected for deletion. Older runs are
deleted before older segments from the current run.

Writer configuration and counters are exposed as `diagnosticWriter` in Rust
runtime diagnostics and diagnostic bundles. Consumers must use its `runId`,
`processId`, and `activeFileName` rather than selecting a globally newest file.

## Consumer Selection

Harness consumers must:

1. discover files matching `emulebb-rust-diag-*.jsonl`;
2. group segmented names by `(processId, runId)`;
3. select exactly one newest run, or a requested process when supplied;
4. order that run by numeric `segmentId`;
5. order parsed records by `seq`;
6. ignore a final unterminated line while the active segment is being appended;
7. never merge records from different run identities.

Legacy `emulebb-rust-diag-<processId>.jsonl` and `diag_event_v1` input remain
readable by the harness during migration. MFC continues to emit
`diag_event_v1`; semantic diffing compares the shared family/event payload and
does not require both clients to use the same envelope version.
