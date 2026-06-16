# Common Diagnostic Schema v2 — `diag_event_v1`

Status: design / contract. This document defines a single converged diagnostic
event schema (`diag_event_v1`) emitted **identically by both clients** —
emulebb-rust and the eMuleBB MFC master — so their protocol behaviour *and*
internal scheduling can be diffed event-for-event by a semantic comparison
harness.

It supersedes (without breaking) the existing per-area v1 dumps:

- `ed2k_packet_v1` (eD2k TCP packets) — rust + master,
- `udp_packet_v1` (Kad UDP packets) — rust,
- `kad_event_v1` / `kad_routing_summary_v1` — master,
- `bad_peer_event_v1` — master,
- the upload/download slot diagnostics key=value lines — master.

The existing `ed2k_packet_v1` convergence + `packet_trace_diff.py` flow stays
valid; `diag_event_v1` generalises the **same envelope + wire-identity idea** to
every diagnostic family, including the scheduling internals that today emit
nothing on the rust side.

> Diagnostics behind `#ifdef` / Cargo features are a verification-tooling
> exception to the MFC release soft freeze. Nothing in this contract ships in a
> release build; both sides are gated (see §5).

---

## 0. Why a unified envelope (`diag_event_v1`) instead of `*_v2` per family

The v1 dumps already share a *de facto* envelope on the master side
(`WriteDiagnosticsJsonEvent` in `Log.cpp`: `schema`, `source`, `marker`,
`ts_utc`, `event_seq`, `event`, `severity`, primary/secondary object, `action`,
`reason`, `evidence`) and a parallel one on the rust side (`schema`, `source`,
`ts`/`ts_utc`, `event_seq`, `trace_key`, `state_id`, `state_label`, ...). They
diverge in field names, timestamp format, and which family carries which fields.

Rather than mint four `*_v2` schemas that each re-specify the envelope, this
contract defines **one envelope** (`diag_event_v1`) carrying a `family`
discriminator and a typed `body`. Justification:

- the comparison harness aligns on a single record shape regardless of family;
- adding the new scheduling families costs a `family` value + a `body` shape,
  not a new top-level schema + new loader path;
- both emitters share one serialiser; field-name drift (the v1 pain point) is
  structurally prevented because there is exactly one field table.

The literal string `"diag_event_v1"` is the schema version. A future
incompatible change becomes `diag_event_v2`; additive `body` fields do **not**
bump the version (the harness ignores unknown fields).

---

## 1. Field-by-field inventory of the existing v1 diagnostics

### 1.1 Master (srchybrid) — shared envelope (`Log.cpp`)

`WriteDiagnosticsJsonEvent` emits one JSON object per line (`\r\n`,
UTF-8), used by `kad_event_v1` and `bad_peer_event_v1`:

| field | encoding | notes |
|---|---|---|
| `schema` | string | e.g. `kad_event_v1`, `bad_peer_event_v1` |
| `source` | string | always `"emulebb"` |
| `marker` | string | per-family binary marker (`kBinaryMarker`) |
| `ts_utc` | string | `BuildDiagnosticsTimestampUtc()` → `YYYY-MM-DDThh:mm:ss.mmmZ` |
| `event_seq` | u64 | per-family `InterlockedIncrement64` counter |
| `event` | string | event name (e.g. `kad_bootstrap_contact_added`) |
| `severity` | string | `info` / `low` / `medium` / `high` |
| *primaryKey* | object\|null | `contact` (kad) or `peer` (bad-peer) |
| *secondaryKey* | object\|null | `file` (bad-peer) |
| `action` | string | `observe` / `drop` / ... |
| `reason` | string | free text |
| `evidence` | object | family-specific evidence payload |

Helpers: `EscapeDiagnosticsJson`, `BuildDiagnosticsJsonStringField`,
`NormalizeDiagnosticsJsonPayload`, `NextDiagnosticsEventSeq`,
`InitializeDiagnosticsLog` (UTF-8, flush-on-write).

### 1.2 Master — `kad_event_v1` (`KadDiagnosticsSeams.cpp`)

Contact object (`ContactJson`): `node_id`, `address`, `udp_port`, `tcp_port`,
`version`, `type`, `ip_verified`, `received_hello`, `bootstrap`, `has_udp_key`,
`distance_bucket`, `local_quality_score`, `age_seconds`,
`last_seen_age_seconds`, `expires_in_seconds`.

Raw contact (`RawContactJson`): `address`, `udp_port`, `tcp_port`, `version`.

Packet-event evidence (`LogPacketEvent`): `opcode`, `original_opcode`,
`tokens_ms`; peer object carries `address`.

Search-response event (`LogSearchResponseEvent`): contact `{address, udp_port,
version}`; evidence `{search_id, search_type, result_count, expected_count}`.

Periodic `kad_routing_summary_v1` (separate schema, `LogRoutingSummary`,
30s interval): `connected`, `bootstrapping`, `firewalled`, `lan_mode`,
`routing` + `bootstrap_queue` each a summary object: `total`, `verified`,
`unverified`, `received_hello`, `with_udp_key`, `bootstrap`, `legacy_v2_to_v5`,
`modern_v8_or_newer`, `current_v10`, `expired_type`, `max_distance_bucket`,
`version_histogram[16]`, `version_other`, `type_histogram[5]`, `type_other`.

### 1.3 Master — `bad_peer_event_v1` (`BadPeerDiagnosticsSeams.cpp`)

Peer object (`ClientJson`): `address`, `connect_ip`, `user_port`, `user_hash`,
`user_name`, `client_software`, `client_mod`, `download_state`, `upload_state`,
`session_down`, `session_payload_down`, `session_up`, `payload_in_buffer`.

File object (`FileJson`): `hash`, `name`, `size`, `type`.
Search object (`SearchJson`): `hash`, `name`, `size`, `type`, `search_id`,
`source_count`, `complete_source_count`, `client_ip`, `client_port`,
`server_ip`, `server_port`, `spam_rating`, `considered_spam`, `kad`,
`server_udp_answer`.

Block-request evidence (`BlockRequestEvidenceJson`): `file_hash`,
`start_offset`, `end_offset`, `part_index`, `range_bytes`, `queued_blocks`,
`done_blocks`, `pending_io_blocks`, `repeat_count`, `window_seconds`,
`first_seen_age_ms`, `session_up`, `queue_session_payload`, `payload_in_buffer`.
Upload-file-behaviour evidence adds `behavior`. A behaviour ledger
(IP/hash-keyed, 60-min window) produces `upload_repeat_block_request_observed`
and `upload_repeat_file_request_observed` derived events.

### 1.4 Master — `ed2k_invalid_sub_opcode_v1` (`Log.cpp`, packet diagnostics)

Gated by `EMULEBB_ENABLE_PACKET_DIAGNOSTICS`. Fields: `schema`, `source`,
`ts_utc`, `event_seq`, `packet_family`, `remote_addr`, `transport_mode`,
`protocol`, `protocol_marker`, `outer_opcode`, `outer_opcode_name`,
`invalid_sub_opcode`, `previous_sub_opcode`, `payload_len`, `invalid_offset`,
`bytes_remaining`, `context_offset`, `context_len`, `context_hex`,
`payload_hex_truncated`, `payload_hex`. Hex cap:
`kMaxPacketDiagnosticsPayloadHexBytes = 4 KiB`.

**Finding:** the master does **not** currently emit a full bidirectional
`ed2k_packet_v1` send/recv packet dump. It emits only the invalid-sub-opcode
record. The rust client emits the full `ed2k_packet_v1` (below). For converged
packet diffing, the master side of `diag_event_v1` (family `ed2k_tcp`) is a
**new** re-emit at the same TCP send/recv boundaries the invalid-sub-opcode
hook already sits on (see §4, D3).

### 1.5 Master — upload slot diagnostics (`UploadQueue.cpp:424`)

Gated by `EMULEBB_ENABLE_UPLOAD_SLOT_DIAGNOSTICS`, file
`emulebb-diagnostics-upload-slot.log`, 10s interval. **Emitted as key=value
lines, not JSON** (`CDiagnosticsKeyValueLineBuilder` + `summary.GetLine()`).
A header summary line then one per-slot line.

Header summary keys (selected, full set in source): `waitingRetryNoRequest`,
`waitingRetryChurn`, `waitingRetryStalled`, `waitingRetrySlow`,
`waitingRetryUnknown`, `activeZeroRate`, `activeNoRequest`,
`activeNoRequestDrained*`, `activeNoRequestPendingIO`,
`activeNoRequestRecycleEligible`, `activeNoRequestRecycleGraceBlocked`,
`activeNoRequestRecycleUnderfillBlocked`, `activeNoRequestAgeAvgMs/MaxMs`,
`activeQueuedRequests`, `activePendingIO`, `activeBufferedPayload`,
`activeSocketBacklog`, `waitingCooldownMin/Avg/MaxMs`, `retryCooldowns`,
`noRequestCooldowns`, `sharedFiles`, `ed2kPublishedFiles`, `ed2kPendingFiles`,
`kadPublishReady`, `kadSourceDueFiles`, `kadSourceBackoffFiles`,
`kadSourceSearches`/`Cap`, `kadKeywordSearches`/`Cap`, `kadNotesSearches`/`Cap`,
`throttlerSlots`, `activeSlots`, `baseSlotTarget`, `elasticPercent`,
`effectiveSlotCap`, `cap`, `configuredBudgetBytesPerSec`,
`targetPerSlotBytesPerSec`, `toNetworkBytesPerSec`, `datarateBytesPerSec`,
`underfilled`, `underfillAgeMs`, `slowTracking`.

Per-slot line keys: `slot`, `live`, `client`, `state`, `socketConnected`,
`handshake`, `rateBytesPerSec`, `ageMs`, `sessionUp`, `queuePayload`,
`queueAdded`, `payloadInBuffer`, `reqBlocks`, `doneBlocks`, `pendingIO`,
`socketStdQueue`, `reqAccepted`, `reqDupDone`, `reqDupQueued`, `reqRejected`,
`reqSignals`, `reqLastAgeMs`, `reqLastAcceptedAgeMs`, `slowMs`, `zeroMs`,
`cooldownMs`, `fileKnown`.

### 1.6 Master — download slot diagnostics (`DownloadQueue.cpp:997`)

Gated by `EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS`, file
`emulebb-diagnostics-download-slot.log`, 10s interval, key=value summary line.

Keys (selected): `readyFiles`, `activeFiles`, `sourceStarvedReadyFiles`,
`sourceStarvedKad*ReadyFiles`, `sourceThinReadyFiles`, `sourceRichReadyFiles`,
`a4afReadyFiles`, `sources`, `validSources`, `downloadingSources`,
`onQueueSources`, `connectedSources`, `connectingSources`, `callbackSources`,
`hashsetSources`, `nnpSources` (NoNeededPart), `remoteFullSources`,
`tooManyConnSources`, `lowToLowIPSources`, `bannedSources`, `errorSources`,
`idleSources`, `duplicateZeroWrite*`, `localServerQueued*`,
`nextTcpSourceRequestWaitMs`, `udpSearchActive`, `udpSearchedServers`,
`udpRequestsSentToServer`, `udpFileReasks`, `udpFailedFileReasks`,
`udpLastSearchAgeMs`, `kadConnected`, `kadTotalFileSearches`,
`kad*ReadyFiles`, `datarateBytesPerSec`, `effectiveFileBufferBytes`,
`buffered*`, `maxBuffered*`, `asyncWrite*`, `protectedDiskBlocked`.

### 1.7 Master — log file locations (`LogArtifactNames.h`, `Emule.cpp`)

`InitializeDiagnosticsLog` opens each family's file under the configured
diagnostics log dir (`strDiagnosticsLogDir`). Names:
`emulebb-diagnostics-packet.log`, `emulebb-diagnostics-bad-peer.log`,
`emulebb-diagnostics-kad.log`, `emulebb-diagnostics-upload-slot.log`,
`emulebb-diagnostics-download-slot.log`.

### 1.8 Rust — `ed2k_packet_v1` (`crates/emulebb-ed2k/src/ed2k_tcp/dump.rs`)

Gated by Cargo feature `packet-diagnostics`; file under `EMULEBB_RUST_LOG_DIR`
named `emulebb-rust-ed2k-tcp-dump-<ts>.jsonl`. Record fields: `schema`
(`ed2k_packet_v1`), `source` (`emulebb-rust`), `ts_utc` (RFC3339 millis),
`event_seq`, `trace_key` (`<flow>:<remote_addr>`), `state_id`
(`<flow>.<phase>`), `state_label`, `flow` (`listener` / `native_download` /
`udp_firewall_check`), `phase`, `direction` (`send` / `recv` / `meta`),
`remote_addr`, `transport_mode`, `protocol`, `protocol_marker`, `opcode`,
`opcode_name`, `raw_len`, `raw_hex`, `payload_len`, `payload_hex`,
`payload_hex_truncated`, `note`. Hex cap: 4 KiB (matches master).

### 1.9 Rust — `udp_packet_v1` (`crates/emulebb-kad-net/src/wire_dump.rs`)

Gated by `EMULEBB_RUST_LOG_DIR` presence; file
`emulebb-rust-kad-udp-dump-<ts>.jsonl`. Record fields: `schema`
(`udp_packet_v1`), `source`, `ts` (`%Y-%m-%dT%H:%M:%S%.3f`, **local**, no `Z`),
`event_seq`, `trace_key` (`kad:<peer>`), `state_id`
(`kad.<dir>.<opcode_lower>`), `state_label`, `direction` (`send`/`recv`),
`family` (`kad`), `peer`, `wire_len`, `wire_hex` (UPPER hex), `decoded_len`,
`decoded_hex`, `summary` (kv string), then optional: `protocol`, `opcode`,
`opcode_name`, `raw_obfuscated`, `transport_mode`, `requested_obfuscation`,
`receiver_verify_key`, `sender_verify_key`, `receiver_verify_key_valid`,
`tracked_request_opcode`, `drop_reason`, `tracker_bucket`, `tracker_action`,
`tracker_observed_packets`, `tracker_max_packets`.

### 1.10 Rust — scheduling internals currently emitting NOTHING

- `ed2k_transfer/download_coordinator.rs`: global connection budget
  (`try_acquire_connection` / `release_connection`), per-file source soft/UDP
  caps, global reask round-robin (`next_reask_slot`).
- `ed2k_transfer/download_throttle.rs`: shared inbound token-bucket
  (`reserve`, `set_limit`).
- `ed2k_transfer/upload_queue.rs`: slot states (`Waiting{rank}`, active,
  stale), capacity snapshot (`base_slots`, `elastic_slots`, `active_slots`),
  queue rank.
- `ed2k_client_udp/`: UDP source reask send.
- `emulebb-core/src/download_source_registry.rs`: source register / lease /
  `swap_target_for_peer` (A4AF-lite NNP swap).

These are the **key new surface** `diag_event_v1` exposes, mapped to the
master's slot-diagnostics fields in §3.

---

## 2. The `diag_event_v1` envelope

One JSON object per line, JSONL, UTF-8, newline-terminated (`\n`; the master's
`\r\n` is tolerated by the loader). Every record:

```json
{
  "schema": "diag_event_v1",
  "client": "rust",                 // or "mfc"  — CLIENT-SPECIFIC, used for routing not compare
  "ts": "2026-06-16T10:11:12.345Z", // RFC3339 UTC millis, trailing Z  — NORMALISED, not compared
  "seq": 184,                       // per-process monotonic  — CLIENT-SPECIFIC, ordering only
  "family": "ed2k_tcp",             // discriminator (see §3)
  "event": "packet",                // event name within family
  "severity": "info",               // info|low|medium|high  — COMPARABLE for event families
  "keys": { ... },                  // alignment keys (peer/file/opcode/...) — COMPARABLE
  "body": { ... }                   // typed payload per family               — see §3
}
```

Envelope field comparability:

| field | comparable? | rationale |
|---|---|---|
| `schema` | yes (must equal `diag_event_v1`) | loader guard |
| `client` | **client-specific** | identifies side; harness uses it to bucket, never to diff |
| `ts` | **normalised, not compared** | wall-clock differs; both emit RFC3339 UTC millis `...Z` |
| `seq` | **client-specific** | per-process counter; used only for stable intra-side ordering |
| `family` | yes | alignment grouping |
| `event` | yes | alignment grouping |
| `severity` | yes | behaviour signal |
| `keys` | yes | alignment identity |
| `body` | per-field (see §3 tables) | each field tagged comparable / client-specific |

`keys` is a flat object of stable alignment identifiers; only the subset
relevant to a family is present:

- `peer` — `ip:port` string (the remote endpoint).
- `peerHash` — MD4 user hash hex when known (preferred peer identity).
- `fileHash` — MD4 file hash hex.
- `opcode` — integer opcode (protocol families).
- `protocolMarker` — integer protocol byte (protocol families).
- `nodeId` — Kad 128-bit id hex (kad family).
- `searchId` — integer (kad search / bad-peer search).

Field-name convention: **camelCase**, shared verbatim by both emitters. (The v1
master dumps used snake_case; `diag_event_v1` standardises on camelCase to match
the rust serde style and eliminate the per-side name table.)

---

## 3. Families and their `body` shapes

For every `body` field: **C** = comparable (harness diffs it), **S** =
client-specific (harness ignores it; emitted for human/debug context).

### 3.1 `family: "ed2k_tcp"` — eD2k TCP packet (supersedes `ed2k_packet_v1`)

`event`: `"packet"`. `keys`: `peer`, `peerHash?`, `opcode`, `protocolMarker`,
`fileHash?`.

| body field | C/S | encoding | notes |
|---|---|---|---|
| `direction` | C | `send`/`recv`/`meta` | |
| `protocolMarker` | C | u8 | `0xE3`/`0xC5`/`0xD4` |
| `protocolName` | S | string | per-client name table |
| `opcode` | C | u8 | |
| `opcodeName` | S | string | per-client name table |
| `rawLen` | C | usize | full framed length |
| `rawHex` | C | hex (lower) | cap 4 KiB; **canonical compare key** with opcode |
| `payloadLen` | C | usize | |
| `payloadHex` | C | hex (lower) | cap 4 KiB |
| `payloadHexTruncated` | C | bool | |
| `obfuscated` | C | bool | on-wire obfuscation applied |
| `transportMode` | S | string | vocab differs per client |
| `flow` | S | string | rust `flow`; master maps to nearest bucket |
| `phase` | S | string | rust phase; master best-effort |
| `note` | S | string | meta lines |

Wire-identity compare key (mirrors `packet_trace_diff.py`):
`(protocolMarker, opcode, payloadHex)`.

### 3.2 `family: "kad_udp"` — Kad UDP packet (unifies rust `udp_packet_v1` + master kad packet diag)

`event`: `"packet"`. `keys`: `peer`, `opcode`, `protocolMarker`, `nodeId?`.

| body field | C/S | encoding | notes |
|---|---|---|---|
| `direction` | C | `send`/`recv` | |
| `protocolMarker` | C | u8 | `0xE4`/`0xE5` |
| `opcode` | C | u8 | |
| `opcodeName` | S | string | |
| `wireLen` | C | usize | on-wire (post-obfuscation) |
| `wireHex` | C | hex (UPPER) | cap 4 KiB; both sides UPPER for kad parity |
| `decodedLen` | C | usize | |
| `decodedHex` | C | hex (UPPER) | cap 4 KiB |
| `rawObfuscated` | C | bool | |
| `requestedObfuscation` | C | bool? | |
| `transportMode` | S | string | |
| `receiverVerifyKey` | S | u32? | |
| `senderVerifyKey` | S | u32? | |
| `receiverVerifyKeyValid` | C | bool? | |
| `trackedRequestOpcode` | C | string? | paired request |
| `dropReason` | C | string? | drop classification |

Wire-identity compare key: `(protocolMarker, opcode, decodedHex)` (decoded, so
obfuscation key differences do not cause false mismatches).

### 3.3 `family: "kad_event"` — Kad milestones (supersedes `kad_event_v1` + summary)

`event`: one of `bootstrap`, `lookup`, `publish`, `firewall`, `buddy`,
`routing_summary`. `keys`: `nodeId?`, `peer?`, `searchId?`.

| body field | C/S | encoding | notes |
|---|---|---|---|
| `milestone` | C | string | e.g. `bootstrap_contact_added`, `lookup_complete`, `firewalled`, `buddy_established` |
| `action` | C | string | `observe`/`drop`/... |
| `reason` | S | string | free text |
| `connected` | C | bool? | routing_summary |
| `bootstrapping` | C | bool? | routing_summary |
| `firewalled` | C | bool? | routing_summary / firewall |
| `lanMode` | C | bool? | routing_summary |
| `contactTotal` | C | u32? | routing_summary `routing.total` |
| `contactVerified` | C | u32? | routing_summary |
| `contactWithUdpKey` | C | u32? | routing_summary |
| `searchType` | C | u32? | lookup |
| `resultCount` | C | u32? | lookup |
| `expectedCount` | C | u32? | lookup |
| `version` | S | u32? | contact context |
| `distanceBucket` | S | u32? | contact context |

(Histograms / per-contact ages from `kad_routing_summary_v1` carry over as
client-specific context fields, prefixed and tagged S; not enumerated here.)

### 3.4 `family: "bad_peer"` — abusive-peer events (supersedes `bad_peer_event_v1`)

`event`: e.g. `repeat_block_request`, `repeat_file_request`, `spam_search`.
`keys`: `peer`, `peerHash?`, `fileHash?`, `searchId?`.

| body field | C/S | encoding | notes |
|---|---|---|---|
| `behavior` | C | string | classification |
| `action` | C | string | |
| `reason` | S | string | |
| `repeatCount` | C | u32 | ledger count |
| `windowSeconds` | C | u64 | ledger window |
| `startOffset` | C | u64? | block events |
| `endOffset` | C | u64? | block events |
| `partIndex` | C | u64? | block events |
| `spamRating` | C | u32? | search events |
| `consideredSpam` | C | bool? | search events |
| `sessionUp` | S | u64? | volatile counter |
| `payloadInBuffer` | S | u64? | volatile counter |
| `clientSoftware` | S | string? | peer context |

### 3.5 `family: "sched"` — internal scheduling (the new converged surface)

These are the events that make rust↔master scheduling diffable. Both clients
emit the **same `event` names** at the **same semantic decision points**. Each
event additionally carries a coarse, comparable `outcome`; volatile rates/ages
are tagged S.

`keys`: `peer?`, `peerHash?`, `fileHash?`.

Event taxonomy (the `event` value within `family:"sched"`):

| event | semantic point | master origin | rust origin |
|---|---|---|---|
| `source_engaged` | a source starts being served for a file | DownloadClient connect/accept | per-transfer driver engage |
| `source_dropped` | a source is dropped from a file | source removal | driver drop |
| `source_swapped` | A4AF / NoNeededParts move to another file | `SwapToAnotherFile` / `nnpSources` | `swap_target_for_peer` |
| `upload_slot_opened` | a peer is granted an upload slot | `AddUpNextClient` | upload_queue active transition |
| `upload_slot_closed` | an upload slot is released | slot removal | upload_queue close |
| `upload_slot_recycled` | idle/no-request slot reclaimed | `activeNoRequestRecycle*` | upload_queue recycle |
| `queue_rank` | a waiting peer's rank (periodic / on change) | per-slot `state=waiting` | `Waiting{rank}` |
| `reask_sent` | a source reask is sent (TCP or UDP) | `udpFileReasks` / TCP reask | reask loop / coordinator |
| `throttle_applied` | rate limiter delayed a send/read | upload throttler | `throttle.reserve` delay |
| `conn_budget` | connection admit/deny decision | `TooManySockets` | `try_acquire_connection` |
| `source_count` | per-file source-count snapshot (periodic) | download slot summary | registry snapshot |

| body field | C/S | encoding | applies to | notes |
|---|---|---|---|---|
| `outcome` | C | string | all | `engaged`/`dropped`/`swapped`/`opened`/`closed`/`recycled`/`admit`/`deny`/`sent`/`applied` |
| `transport` | C | `tcp`/`udp` | reask_sent | which reask path |
| `swapReason` | C | string | source_swapped | `nnp`/`a4af`/... |
| `swapTargetFileHash` | C | hex? | source_swapped | NNP swap target |
| `queueRank` | C | u16? | queue_rank / upload_slot_* | |
| `slotKind` | C | `base`/`elastic`/`friend` | upload_slot_* | |
| `activeSlots` | C | usize? | upload_slot_* / source_count | |
| `baseSlots` | C | usize? | capacity snapshot | |
| `elasticSlots` | C | usize? | capacity snapshot | |
| `effectiveSlotCap` | C | usize? | capacity snapshot | master `effectiveSlotCap` |
| `denyReason` | C | string? | conn_budget deny | `concurrent_cap`/`window_cap` |
| `activeConnections` | C | usize? | conn_budget | budget occupancy |
| `connectionCap` | C | usize? | conn_budget | configured cap |
| `sourceCount` | C | u32? | source_count | per-file total |
| `validSourceCount` | C | u32? | source_count | master `validSources` |
| `nnpSourceCount` | C | u32? | source_count | master `nnpSources` |
| `a4afFileCount` | C | u32? | source_count | master `a4afReadyFiles` |
| `delayMs` | S | u64? | throttle_applied | exact delay differs |
| `rateBytesPerSec` | S | u64? | throttle / slot | volatile |
| `ageMs` | S | u64? | slot / source | volatile |
| `limitBytesPerSec` | C | u64? | throttle_applied | configured limit (stable) |

Design note on comparability for `sched`: exact counts and timings will not be
byte-identical between two independent live clients. The harness therefore
diffs `sched` **structurally** — does the *same sequence of event/outcome
transitions* occur for an aligned (peer,file) — and treats numeric C fields as
**presence + monotonic-sanity** checks (e.g. `queueRank` decreases over time;
`conn_budget deny` only when `activeConnections >= connectionCap`), not exact
equality. This is called out in §4 (D4) and is the main reason `sched` C fields
are "comparable in shape", distinct from the byte-exact packet families.

---

## 4. Implementation plan (D2 rust / D3 master / D4 harness)

### D2 — rust emitter (gated by `EMULEBB_RUST_LOG_DIR`, feature `packet-diagnostics` for packet families)

A single `diag_event_v1` writer module (e.g. `emulebb-core` `diag_event.rs`)
owning the JSONL file `emulebb-rust-diag-<ts>.jsonl` and the `seq` counter,
mirroring `wire_dump.rs` (OnceLock writer, `EMULEBB_RUST_LOG_DIR`). Emit points:

- `ed2k_tcp/dump.rs`: re-shape the existing `Ed2kTcpDumpRecord` into a
  `family:"ed2k_tcp"` `diag_event_v1` record (keep `ed2k_packet_v1` during
  migration; emit both, retire v1 after D4 lands).
- `kad-net/wire_dump.rs`: re-shape `UdpDumpRecord` into `family:"kad_udp"`;
  normalise `ts` to UTC `...Z` (currently local).
- `download_coordinator.rs`: emit `conn_budget` at `try_acquire_connection`
  (admit/deny + `denyReason`, `activeConnections`, `connectionCap`);
  `reask_sent{transport:"udp"}` at `next_reask_slot` grant.
- `download_throttle.rs`: emit `throttle_applied` when `reserve` returns a
  non-zero delay (`delayMs` S, `limitBytesPerSec` C).
- `upload_queue.rs`: emit `upload_slot_opened/closed/recycled`, `queue_rank` on
  state transitions; periodic capacity snapshot → `source_count`/slot fields.
- `ed2k_client_udp/`: `reask_sent{transport:"udp"}` (or tcp) on actual send.
- `download_source_registry.rs`: `source_engaged`/`source_dropped`;
  `source_swapped` with `swapReason:"nnp"` + `swapTargetFileHash` from
  `swap_target_for_peer`.

### D3 — master emitter (verification-tooling, behind existing `#ifdef`s)

Add a shared `diag_event_v1` writer alongside `WriteDiagnosticsJsonEvent`
(`Log.cpp`) producing the camelCase envelope; one file
`emulebb-diagnostics-diag.log`. Then **re-emit** existing diagnostics in the
common shape (do not delete the v1 emitters during migration):

- Packet family: add an `ed2k_tcp` send/recv emit at the TCP packet boundaries
  that already host the packet-diagnostics hooks in `ListenSocket.cpp` (the
  invalid-sub-opcode hook proves the boundary exists) — this is the **new**
  full bidirectional dump the master lacks today. Gated by
  `EMULEBB_ENABLE_PACKET_DIAGNOSTICS`.
- Kad family: re-emit `kad_event_v1` / `kad_routing_summary_v1` as
  `family:"kad_event"`, and add a `family:"kad_udp"` packet emit at the Kad UDP
  send/recv boundary (gated by the kad-diagnostics flag).
- Bad-peer: re-emit `bad_peer_event_v1` as `family:"bad_peer"`.
- Scheduling: the slot-diagnostics functions already compute every C field in
  §3.5. Convert the periodic key=value summaries to per-decision
  `family:"sched"` events (`upload_slot_*`, `source_count`, `conn_budget`,
  `reask_sent`, `throttle_applied`) plus keep the periodic snapshot as
  `source_count`. Map: `effectiveSlotCap`→`effectiveSlotCap`,
  `validSources`→`validSourceCount`, `nnpSources`→`nnpSourceCount`,
  `a4afReadyFiles`→`a4afFileCount`, `udpFileReasks`→count of `reask_sent`,
  `TooManySockets`→`conn_budget deny`.

### D4 — comparison harness (`diag_event_diff.py`, mirrors `packet_trace_diff.py`)

A semantic diff of two `diag_event_v1` JSONL traces:

1. Load both, filter `schema == diag_event_v1`, bucket by `client`.
2. Group by `(family, event)` then align within group by `keys`
   (peer/peerHash → file → opcode/sequence), per direction for packet families.
3. Compare only **C** fields per the §3 tables; ignore S fields, `ts`, `seq`,
   `client`.
4. Packet families (`ed2k_tcp`, `kad_udp`): exact wire-identity match
   (`packet_trace_diff.py` algorithm — `SequenceMatcher` over wire keys,
   `payload_mismatches` / `only_rust` / `only_mfc`).
5. `kad_event` / `bad_peer`: set/sequence match on `(event, action/behavior,
   keys)` with C-field equality.
6. `sched`: **structural** match — same ordered sequence of `(event, outcome)`
   transitions per aligned `(peer,file)`; numeric C fields checked for
   presence + invariants (rank monotonic, deny only at cap), not equality.
7. Report `{ok, totals, families[]}` JSON; exit non-zero on divergence — same
   contract as `packet_trace_diff.py`, so it slots into the existing G-series
   harness wiring (`compare-protocol-oracle.py` style CLI wrapper in
   `scripts/`).

Skeleton: `emule_test_harness/diag_event_diff.py` (this lane ships the stub;
D4 fills the family comparators).

---

## 5. Gating summary

| side | gate | output file |
|---|---|---|
| rust packet families | Cargo feature `packet-diagnostics` + `EMULEBB_RUST_LOG_DIR` | `emulebb-rust-diag-<ts>.jsonl` |
| rust kad/sched families | `EMULEBB_RUST_LOG_DIR` present | same file |
| master packet | `#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS` | `emulebb-diagnostics-diag.log` |
| master kad | `EMULEBB_HAS_KAD_DIAGNOSTICS` | same file |
| master bad-peer | `EMULEBB_HAS_BAD_PEER_DIAGNOSTICS` | same file |
| master upload sched | `#ifdef EMULEBB_ENABLE_UPLOAD_SLOT_DIAGNOSTICS` | same file |
| master download sched | `#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS` | same file |

All gates are off in release builds; this contract is verification tooling only.
