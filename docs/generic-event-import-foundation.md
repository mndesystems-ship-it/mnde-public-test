# Generic Event Import Foundation v1.0

Working name: Universal Execution Import Engine (UEI).

The event-import foundation turns source evidence into one canonical execution
event model. Source-specific interpretation belongs in adapters. Storage,
search, replay, timelines, and reports consume canonical events only.

## Implemented pipeline

```text
raw bytes -> immutable staging -> manifest/hash/signature validation
  -> format parser -> source adapter -> canonical validation
  -> transactional storage -> tenant-scoped search/replay/views
```

The implementation lives in `src/event-import/` and exports its public API from
`src/event-import/index.mjs`.

## Raw evidence and manifests

`stageEvidence()` writes every accepted byte stream with exclusive-create
semantics under:

```text
<raw-root>/<tenant>/<source>/<yyyy>/<mm>/<dd>/<import-id>/
```

The directory contains the original evidence bytes and a generated
`mnde.import.manifest.v1` manifest. The manifest binds:

- tenant, source, import ID, operator, origin, and received time
- original filename, media type, encoding, compression, and parser format
- SHA-256, byte/file counts, schema version, warnings, and signatures
- evidence ID, tenant chain position, and previous evidence hash
- hash and signature-verification status

Files are created without overwrite permission and marked read-only where the
host supports it. The database binds the complete generated manifest by SHA-256.
Every resume re-hashes both evidence and manifest and compares them with the
staged database record. Filesystem permissions are not treated as a cryptographic
boundary.

`stageEvidence()` and `resumeImport()` are separate deliberately. If a process
stops after staging, the import remains `PENDING` and can resume without copying
or rewriting evidence. `importEvidence()` performs both calls for the common
single-process path.

## Validation and failure states

The validator recognizes ASCII, UTF-8, BOM-tagged UTF-16LE/BE, gzip, zip, and
tar signatures. Gzip is decoded in-process. Zip and tar are preserved and then
quarantined until extracted by a trusted adapter/tool.

An expected-hash mismatch is preserved first and then quarantined with both
hashes recorded. Source signatures use a caller-supplied
`signatureVerifier(bytes, signatures)`
hook; a caller cannot assert `VERIFIED` with a status string. Set
`requireSignature: true` to fail closed unless that hook returns a verified
result. This keeps source-specific trust logic out of the import core.

Import states are:

- `PENDING`: immutable evidence is staged and processing can resume.
- `COMPLETED`: canonical events committed transactionally.
- `QUARANTINED`: bytes, compression, encoding, parsing, manifest, hash, or
  signature validation failed.
- `PRESERVED`: parsing succeeded but normalization or canonical validation
  failed. Raw evidence remains available for a corrected adapter and resume.

Failures carry a stable reason code, severity, suggested action, evidence
context, and import ID.

## Parser boundary

Parsers interpret file formats, not source semantics.

| Family | v1 behavior |
| --- | --- |
| JSON, CloudTrail JSON, GitHub/GitLab JSON exports | object, array, or `{ events: [] }` decomposition |
| JSONL / NDJSON | one event per non-empty line with line and byte offset |
| CSV / TSV | quoted-field parser with unique headers and exact column counts |
| text, Apache, syslog | one raw event per line; ISO timestamp prefix retained when present |
| SQLite export | JSON or delimited text export; raw SQLite database files are not opened |
| XML, YAML, Windows EVTX export | document-preserving raw event for a registered source adapter |
| gzip | decompressed before the selected parser |
| zip / tar | preserved and quarantined; extraction is not implicit |

Binary EVTX decoding, arbitrary YAML object construction, archive extraction,
and source-native database access are intentionally not claimed. They require a
registered parser or connector with an explicit security review. Raw evidence is
still retained when those inputs cannot be processed.

## Canonical execution event

Every stored event uses `mnde.canonical_execution_event.v1` and contains:

- UUID event ID, tenant, source, timestamp, duration, status, and result
- actor and actor type
- resource and resource type
- action, action category, decision, reason, and risk level
- policy reference, evidence references, relationships, attributes, and tags

Canonical validation requires canonical ISO timestamps, allowed decision/risk
values, a matching import tenant, valid UUID event relationships, resolvable
references, unique event IDs, and an acyclic parent graph. Event IDs generated
by the generic adapter are deterministic over the import and raw-event position.

`createPassthroughAdapter()` is useful only when the input already uses generic
field names. Real source mappings must be implemented as adapters. No GitHub,
Kubernetes, Slack, or other source-specific field rule belongs in the parser,
store, query, replay, timeline, or report modules.

## Storage and search

`openEventStore()` uses SQLite with WAL, `synchronous=FULL`, and foreign keys.
The v1 schema creates the specification's foundation tables:

- `imports`, `evidence`, `canonical_events`
- `actors`, `resources`, `relationships`, `timelines`, `receipts`
- `simulation_runs`, `simulation_results`, `policy_decisions`

Indexes cover tenant/time, actor, resource, action, decision, import, and
relationships. Every query requires an explicit tenant. Supported exact filters
include source, actor, resource, action/category, decision, status, risk, import,
reason, repository, branch, policy, workflow, session, ticket, deployment,
receipt, tag, evidence hash, and time range. Results use a deterministic
timestamp/event-ID order.

CLI examples:

```bash
npm run events -- import --db .data/events.db --raw-root .data/raw \
  --tenant tenant-a --source manual --file ./events.json \
  --format json --operator operator-1

npm run events -- find --db .data/events.db --tenant tenant-a \
  --action deploy --decision deny
```

## Replay, simulation, resolution, and views

`replayEvents()` accepts only canonical events and a synchronous policy object.
It records historical versus simulated decisions, allow/deny/review/escalation
flags, decision changes, and reasons. It never invokes an executor or connector.
A policy exception stops the run.

`resolveIdentities()` and `resolveResources()` use explicit alias records. They
do not guess fuzzy matches. `buildTimeline()` produces execution, actor,
resource, decision, workflow, session, ticket, deployment, and receipt views.
`executionSummary()` provides a deterministic foundation report.

AI and downstream analytics should read canonical events, relationships,
policies, receipts, and evidence references first. Raw evidence is retrieved only
when the canonical record is insufficient.

## Connector SDK contract

Every connector must implement:

```text
discover()  health()  import()  validate()
normalize() version() shutdown()
```

`runConnectorImport()` health-checks the connector, obtains and validates its
package, wraps `normalize()` as the only source-specific mapping step, and sends
the result through the same immutable staging and canonical pipeline. A
connector receives no event-store handle from this API and must not write
storage, evaluate policy, or generate execution receipts.

## Security and scalability boundaries

- Evidence bytes and generated manifests never update in place.
- Hash, manifest, signature, tenant, reference, and cycle failures fail closed.
- Duplicate evidence for the same tenant/source/hash is rejected.
- Tenant is mandatory at the query boundary.
- SQLite commits an import's canonical events atomically.
- Parsing can be parallelized after per-tenant evidence staging; v1 staging
  serializes chain-position allocation through the store boundary.
- Whole-directory deletion, compromised signing keys, and a hostile database
  administrator remain deployment/security boundaries and require external
  backup, retention, and custody controls.

## Validation

Run:

```bash
npm run test:event-import-foundation
```

The hostile suite covers staging/resume, duplicate rejection, deterministic
tenant-scoped search, JSONL/CSV/gzip, signature verification, malformed evidence
preservation, normalization failure, cross-tenant output, invalid references,
parent cycles, raw/manifest tampering, connector enforcement, replay, identity
resolution, timelines, and reports.
