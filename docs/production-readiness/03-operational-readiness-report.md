# 3. Operational Readiness Report

Can a platform/support engineer deploy, operate, diagnose, and recover MNDe? Findings cite code; gaps map to roadmap items.

## What exists today (verified)

| Capability | Status | Evidence |
| --- | --- | --- |
| Health checks | **Present** | `GET /healthz`, `GET /readyz` (`mnde-local-sidecar.mjs:1029,1051`) |
| Liveness watchdog | **Present** | `sidecar/runtime_watchdog.mjs`; degraded/fatal on event-loop lag + socket caps (`:127-132`); decisions gated when unhealthy (`:669-671`) |
| Service recovery (worker) | **Present** | crashed worker auto-restarts fail-closed (`:252`) |
| Safe shutdown | **Present** | `SIGINT`/`SIGTERM` → drain receipt queue, worker pool, sockets (`:1332-1342`) |
| Metrics | **Present** | Prometheus `GET /metrics` (`:1061`), incl. GC, heap, RSS, queue, worker, latency |
| Durable persistence | **Present** | receipt queue with `strict_audit` durability (`sidecar/receipt_persistence_queue.mjs`) |
| Evidence export | **Present** | `POST /audit/bundle` (receipts + manifest + replay + metrics + policy) |
| Config backup on change | **Partial** | onboarding backs up MCP configs before wiring + restore (`src/wiring/index.mjs`) — applies to integration, not the runtime |
| Identity endpoint | **Present** | `GET /identity` (repo root, pid, policy hash, start time) (`:1040`) |

This is a strong operational baseline: the runtime already exposes the signals an SRE expects.

## Findings

### O-01 (High) — No production installer / upgrade / rollback for the runtime
`installer/README.md` covers downloading a desktop binary and a manual `sha256sum` check only. There is no scripted install, environment validation, post-install health verification, upgrade path, config migration, or rollback for the sidecar/service.
- **Impact:** "how do I deploy/operate/recover it?" is unanswered for the runtime.
- **Recommendation:** ship `scripts/install.*` + `scripts/upgrade.*` that: validate environment (Node version, ports, write perms), back up existing config + keys, apply, run post-install `mnde doctor`, and support `--rollback` to the prior backup.

### O-02 (Medium) — No exportable diagnostics package for support
`/audit/bundle` exports *evidence*, not a *support diagnostics* set (versions, config snapshot with secrets redacted, recent logs, health/readiness, watchdog state).
- **Recommendation:** `mnde diagnostics --out diag.zip` bundling: version+commit, sanitized config/env, `/healthz` + `/readyz` + `/metrics` snapshots, recent N log lines, watchdog history. No secrets (reuse custody's no-secret guarantees).

### O-03 (High) — Log rotation & retention
The receipt log (`mnde-local-sidecar.mjs:66`) is append-only with no rotation/retention and a demo-named default path (`hostile-verifier-proof-bundle/receipts.jsonl`).
- **Impact:** unbounded disk growth; confusing operator path.
- **Recommendation:** size/time-based rotation with retention; default to a stable data dir (e.g. platform app-data); keep receipts verifiable across rotation (segment files).

### O-04 (Medium) — Version & build tracking at runtime
`package.json` is `0.1.0`; `/identity` exposes no version/build hash, so operators cannot confirm the deployed build.
- **Recommendation:** embed version + git commit at build; expose in `/identity`, `/metrics` (`mnde_build_info`), and receipt metadata.

### O-05 (Medium) — First-run / pre-flight verification
No single command validates a node before serving (keys present, policy valid, port free, data dir writable, signing mode coherent).
- **Recommendation:** `mnde doctor` pre-flight, also used as the post-install health gate (ties to O-01).

### O-06 (Low) — Shutdown lacks a bounded timeout
`shutdown()` (`:1332-1338`) awaits queue/pool/socket drains but does not bound them; `server.close()` is not awaited. A hung worker could delay exit.
- **Recommendation:** wrap drains in a timeout, then force `process.exit`.

## Diagnostics readiness for a support engineer

Today a support engineer can already pull: `/healthz`, `/readyz`, `/metrics`, `/identity`, recent receipts (`/receipts/recent`), replay (`/replay/recent`), and an evidence bundle (`/audit/bundle`). What's missing is a **one-shot diagnostics package** (O-02) and **version visibility** (O-04). With those two, time-to-diagnose drops to minutes.

## Verdict

Runtime observability and recovery are **pilot-ready**. The operational blockers for confident deployment are O-01 (install/upgrade/rollback) and O-03 (log rotation/retention). O-02/O-04/O-05 materially improve supportability and should land before broad rollout.
