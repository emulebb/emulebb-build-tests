# Community Coverage Map

Canonical app target: `baseline/community-0.72a`
Canonical test branch: `main`

`baseline/community-0.72a` is a seam-enabled parity and regression baseline
only. It is not a product release or public tag/package target.

## Automated Coverage

- Upload queue entry lifetime parity: `src/upload_queue.tests.cpp`
- Upload queue scoring and FEAT-023 consumer divergence: `src/community_core_divergence.tests.cpp`, `src/upload_score.tests.cpp`
- Protocol receive replay parity from fragmented temp-file streams: `src/protocol_receive_flow.tests.cpp`
- Long-path reference filesystem IO and temp-file lifecycle parity: `src/long_path_fs_parity.tests.cpp`
- Part/met write-guard and atomic replace divergence on overlong live temp paths: `src/part_file_persistence.tests.cpp`, `src/community_core_divergence.tests.cpp`
- Core socket send/receive bookkeeping parity: `src/socket_io.tests.cpp`, `src/emsocket_send.tests.cpp`, `src/async_socket_ex.tests.cpp`
- Packet length parsing hardening: `src/protocol.tests.cpp`
- Blob/tag payload bounds checking: `src/protocol.tests.cpp`
- Hello and server tag bounds checking helpers: `src/protocol.tests.cpp`
- Explicit dotted IPv4 parsing: `src/protocol.tests.cpp`
- Progress denominator and clamp guards: `src/protocol.tests.cpp`, `src/part_file_numeric.tests.cpp`, `src/known_file_list.tests.cpp`
- `TryToConnect` lifetime and detach safety: `src/client_socket_lifetime.tests.cpp`
- Queue and numeric guard helpers: `src/part_file_numeric.tests.cpp`, `src/source_exchange_flow.tests.cpp`, `src/source_exchange_replay.tests.cpp`
- Orphaned known2 AICH cleanup: `src/known_file_list.tests.cpp`
- UPnP delete safety seam logic: `src/upnp_impl_minilib.tests.cpp`
- Null/resource hardening helpers used by low-risk tail fixes: `src/null_guard.tests.cpp`, `src/resource_ownership.tests.cpp`

## Manual Verification

- Clipboard ANSI export overflow fix
- `WebSocket.cpp` wide-path TLS cert/key loading
- AddFriend dialog control guards
- ArchivePreview dialog/state guards
- ColourPopup owner and column guards
- Safe fixed-buffer UI copy fixes
- CaptchaGenerator GDI/DC cleanup
- ToolBarCtrlX desktop DC ownership cleanup

## Current Checkpoint

- Canonical comparison wrapper: `scripts/run-community-core-coverage.py`
- Live-diff implementation: `scripts/run-live-diff.py`
- Latest wrapper run:
  - combined summary: `reports/community-core-coverage/20260411-195801/community-core-coverage-summary.json`
  - canonical `main` coverage: `reports/native-coverage/20260411-195802-eMuleaz01-v0.72a-emulebb-main-x64-Debug`
  - canonical `baseline/community-0.72a` coverage: `reports/native-coverage/20260411-195836-eMuleaz01-v0.72a-emulebb-community-baseline-x64-Debug`
  - live diff summary: `reports/live-diff-summary.json`
- Latest wrapper metrics:
  - canonical `main`: `parity` 328 passed, `community-core-divergence` 3 passed, line rate `88.32%`
  - canonical `baseline/community-0.72a`: `parity` 268 passed, line rate `95.51%`
  - focused divergence results: 3 expected `test-run pass / baseline fail` cases for upload score ordering, queue-score helpers, and part/met persistence seams
