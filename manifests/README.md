# Manifests

Shared live-fixture manifests for protocol and parser coverage will be stored here.

`live-profile-seed\config` is the deterministic test-only eMule config baseline for live named-pipe, live REST, and live UI runs.
It intentionally keeps only the curated seed files needed to start a fresh working profile.

`release-live-wire-golden.v1.json` tracks stable release-gate vectors such as
seed sources and safe synthetic REST stress operations. Operator-owned runtime
search terms, Radarr movie terms, Sonarr series terms, bootstrap hashes, and
direct ED2K bootstrap rows are intentionally externalized to the ignored repo-root
`live-wire-inputs.local.json`; use the tracked `live-wire-inputs.example.json`
for the schema shape. Tracked manifests must keep only placeholders, stable
contract vectors, or redacted summaries for live-wire runtime data.

`protocol-oracle-golden.v1.json` tracks compact Kad/eD2K protocol oracle
vectors and state-machine summaries. Raw tracing-harness JSONL dumps, packet
hex, timestamps, peer addresses, and passive capture files must stay under
generated `reports` artifacts and must not be committed as protocol goldens.

`release-campaigns\` contains the eMule BB-owned release test campaign model.
The default template defines the strict release phase taxonomy used by future
release instances. Concrete campaign manifests map feature-flow scenarios to
the current command and evidence surfaces without executing those commands.
