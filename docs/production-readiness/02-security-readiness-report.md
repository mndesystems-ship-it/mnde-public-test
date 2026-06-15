# 2. Security Readiness Report

Documents and verifies MNDe's security model and includes the authority-verification proof requested in the initiative. Citations are to real code.

## Threat model (summary)

**What MNDe defends:** integrated execution paths. An agent/tool asks MNDe *before* acting; MNDe returns ALLOW/REFUSE and emits a signed receipt. The product claim is: **for a wrapped tool, there is no code path where REFUSE executes.**

**In scope**
- Pre-execution authorization of tool calls routed through MNDe (sidecar `/v1/decisions`, MCP proxy, executor wrapper).
- Tamper-evident, offline-verifiable evidence (receipts) with deterministic replay.
- Fail-closed behavior on every error class.

**Out of scope (must be stated to buyers)**
- Kernel-level enforcement or OS-wide process control. A process that never integrates with MNDe is not evaluated (`docs/production-readiness.md:22-32`).
- Production key custody and availability guarantees beyond the local node (addressed by the custody subsystem, see S-02).

## Trust boundaries

| Boundary | Rule | Evidence |
| --- | --- | --- |
| Request → decision | Caller identity is **never** taken from the request body when auth is on | `src/policy-engine/sidecar-adapter.mjs` (caller overrides body principal) |
| Trust anchors | Supplied **out of band** by verifier/sidecar config; never from request/policy/receipt | `tools/verify.mjs` (`--trust-anchors`, `--authority-bundle`); `src/policy-engine/trust.mjs` |
| Network exposure | Binds `127.0.0.1` only; CORS allowlist | `mnde-local-sidecar.mjs:62`; `sidecar/runtime_request.mjs:1-18` |
| Authority path isolation | Engines/shared/verifier never import demo or custody code | verified by grep in prior slices |
| Admin actions | Authority-gated and audited | `sidecar/auth_authority.mjs:99` (append-only audit) |

## Key management model

- **Algorithm:** Ed25519 for receipts, policies, approvals, and the authority bundle.
- **Manifest:** `shared/authority-manifest.mjs` supports multiple active keys, retired keys, validity windows, and root-signed manifests — i.e. rotation and historical verification.
- **Custody abstraction:** `src/custody/` publishes `mnde.authority.bundle.v1` (public material only) and offers `local-demo` (default, ephemeral) and `file-backed-production` (opt-in) providers; future KMS/HSM slots documented. Private keys never appear in receipts, logs, or errors (`docs/key-custody.md`).
- **Live signing:** `src/authority-signing/` wraps a built receipt in a custody attestation when `MNDE_RECEIPT_SIGNING_MODE=custody`; default `legacy`.

### S-02 (Critical) — Production trust root not the default
The default signing path uses dev-generated keys (`scripts/bootstrap_dev_receipt_keys.mjs`). Custody is opt-in. **Trust assumption is unclear to an operator who runs defaults.**
- **Remediation:** document custody as the production default; pre-flight refuses production profile with dev keys; publish the authority bundle + root fingerprint through a trusted channel.
- **Status: MITIGATED.** A deterministic trust-root pre-flight (`src/authority-signing/preflight.mjs`, wired in `mnde-local-sidecar.mjs` before the cluster forks) refuses startup in `MNDE_PROFILE=production` unless `MNDE_RECEIPT_SIGNING_MODE=custody` + `MNDE_KEY_CUSTODY=file-backed-production` are set, the custody provider loads and self-verifies, and no demo/dev key material (repo key paths or `mnde-local-*` bundle) is detected. Distinct reason codes (`ERR_TRUST_ROOT_*`), no silent downgrade. Local/demo mode unchanged. Proof: `npm run test:trust-root` (10/10). Residual (operational): publishing/distributing the production bundle through a trusted channel — see `docs/key-custody.md`.

## Fail-closed behavior (verified)

Fail-closed is the default on every error class:
- Executor: any transport/parse/shape/timeout problem returns without executing (`executor/index.mjs:6-15`, `139-195`).
- Sidecar: malformed body, unsigned ALLOW (`:768-771`), queue saturation, watchdog fatal (`:669-671`) → REFUSE / typed `ERR_*`.
- Verifier: a trust-enforced or approval-enforced receipt fails closed without verifier-supplied anchors (`src/policy-engine/receipt.mjs:82-87`).
- Custody: missing/malformed/stale/unsigned bundle or expired/revoked key → distinct `ERR_CUSTODY_*` codes; no silent downgrade to legacy (`src/authority-signing/index.mjs`).

## Replay protection & determinism

- Receipts embed the canonical request + policy; verification **re-runs the deterministic engine** and compares decision, reason code, and all hashes before checking the signature (`src/policy-engine/receipt.mjs:89-116`).
- Bulk replay over the recent log: `replayRecentReceipts` (`sidecar/production_api.mjs:103-135`), exposed at `POST /replay/recent`.

## Signature verification & audit integrity

- One unified verifier dispatches by schema: custody envelope → PE → legacy, each preserving byte-for-byte guarantees (`tools/verify.mjs`).
- Audit/admin actions are appended to a signed/audited log (`sidecar/auth_authority.mjs:99`); evidence bundles via `POST /audit/bundle` (`mnde-local-sidecar.mjs` + `sidecar/production_api.mjs:171+`).

### S-05 (Medium) — Audit log integrity is append-only, not chained
Receipts and admin audit are append-only JSONL. Individual receipts are signed, but the *log itself* is not hash-chained, so deletion/reordering of whole lines isn't self-evident from the log alone (replay detects content tampering of signed receipts).
- **Remediation:** optional per-line hash chaining (Merkle/rolling hash) for tamper-evident ordering; document retention/WORM expectations.

---

## Authority Verification — Proof Documentation

The initiative requires proof of six authority properties. Each is backed by code and a test.

| Property | Proof (code) | Test |
| --- | --- | --- |
| **No execution occurs after REFUSE** | Single post-ALLOW call site; all other paths return (`executor/index.mjs:6-15,169-195`) | `tests/test_executor.mjs` |
| **Receipts verifiable offline** | `tools/verify.mjs` reads a file, replays + checks signature; no network | `tests/test_policy_receipt.mjs`, `tests/test_trust_anchor.mjs` |
| **Replay is deterministic** | Re-run engine, compare all hashes (`src/policy-engine/receipt.mjs:89-103`) | `tests/test_policy_receipt.mjs`, `tests/test_correctness_fixes.mjs` |
| **Decisions are explainable** | Typed reason codes + decision/request/policy hashes on every decision | `tests/test_policy_engine.mjs` |
| **Enforcement is auditable** | Signed receipts persisted to durable queue; `/audit/bundle` evidence export | `tests/test_sidecar_*` |
| **Verification is independent** | Trust anchors out-of-band; verifier needs only the public bundle/manifest | `tests/test_trust_anchor.mjs`, `tests/test_custody.mjs` |

Reproduce the end-to-end proof without the desktop app:
```bash
npm run reviewer-kit        # ALLOW + REFUSE + receipt verify + replay + hostile inputs + executor blocked
npm run test:custody        # offline bundle verification, expired/revoked/tampered fail closed
npm run test:production-signing  # live custody-signed receipt verifies offline; fail-closed matrix
```

## Unclear trust assumptions (remediation list)

1. **S-02:** Default signing uses dev keys — make custody the production default + pre-flight guard. *(Critical)*
2. **S-05:** Audit log ordering not hash-chained — add optional chaining + retention policy. *(Medium)*
3. **Caller-auth scope:** bearer auth is per-token, off by default; document expected unauthenticated behavior and token lifecycle (`docs/production-readiness.md:95-106`). *(Medium)*
4. **Network trust:** local binding is correct for the node model; document that any reverse-proxy exposure must re-establish auth + TLS. *(Low)*

## Verdict

The security **model is coherent and the enforcement/verification properties are proven by tests**. The one trust-critical gap for a default deployment is S-02 (production trust root). S-05 strengthens audit integrity. With S-02 resolved, MNDe is defensible to a security engineer asking "does it enforce, can I verify it, can it be bypassed."
