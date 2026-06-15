# 6. Prioritized Production Roadmap

Consolidates every finding from reports 1–5 into a sequenced plan. Each item lists the **risk addressed**, **business impact**, **technical effort** (S ≤1 day, M ≤1 week, L >1 week), and a **recommended order**. IDs map back to their source report (P=stability, S=security, O=operational, UX=experience, D=documentation).

Effort legend: **S** small, **M** medium, **L** large.

---

## Critical Before Production

These block a defensible pilot. Do them first, in this order.

| Order | ID | Item | Risk addressed | Business impact | Effort |
| --- | --- | --- | --- | --- | --- |
| 1 | S-02 / P-01 | **Make production custody the default trust root** — pre-flight refuses a "production profile" running on dev keys; document publishing the authority bundle + root fingerprint through a trusted channel | Receipts signed by ephemeral/dev keys undermine "verifiable" | Without this, a security engineer rejects the core claim | **M** — **DONE** (pre-flight shipped; `npm run test:trust-root`). Residual: publish bundle via trusted channel. |
| 2 | O-01 / D-01 | **Production installer + upgrade + rollback** (env validation, backup config+keys, apply, post-install `mnde doctor`, `--rollback`) | Unpredictable deploys, no recovery path | Platform teams cannot adopt without it | **L** |
| 3 | O-03 / P-03 | **Receipt log rotation + retention + stable data dir** (replace `hostile-verifier-proof-bundle/` default) | Disk exhaustion; misleading operator path | Outages and operator confusion in long-running pilots | **M** |

**Exit criterion:** a fresh node installs cleanly, runs on a published production trust root, and cannot exhaust disk or sign with dev keys by default.

---

## High Priority

Strongly recommended before broad rollout; safe to begin a *controlled* pilot in parallel.

| Order | ID | Item | Risk addressed | Business impact | Effort |
| --- | --- | --- | --- | --- | --- |
| 4 | O-05 / P-06 | **`mnde doctor` pre-flight** (keys, policy, port, data dir, signing-mode coherence); reused as post-install gate | Startup misconfiguration discovered at runtime | Cuts failed installs and support load | **S** |
| 5 | O-02 | **Exportable diagnostics package** (`mnde diagnostics`: version, sanitized config, health/ready/metrics, recent logs, watchdog history; no secrets) | Slow incident diagnosis | Support can triage in minutes | **M** |
| 6 | O-04 / D-04 | **Version & build tracking** (embed version+commit; expose in `/identity`, `mnde_build_info` metric, receipt metadata; adopt pilot semver) | Cannot confirm deployed build | Required for change control / audits | **S** |
| 7 | D-02 | **Troubleshooting guide** keyed by `ERR_*` and health signals | Operators stuck without a runbook | Self-serve operations | **S** |

**Exit criterion:** a support engineer can determine version, pull a diagnostics bundle, and follow a runbook from symptom to fix.

---

## Medium Priority

Hardening and clarity; schedule after the pilot starts.

| Order | ID | Item | Risk addressed | Business impact | Effort |
| --- | --- | --- | --- | --- | --- |
| 8 | S-05 | **Hash-chain the audit/receipt log** (rolling/Merkle) + documented retention/WORM expectation | Whole-line deletion/reorder not self-evident | Strengthens auditor trust in records | **M** |
| 9 | P-04 | **Typed reason codes on all admin endpoints** (e.g. `/replay/recent` fallback) | Less-explainable admin failures | Cleaner audits and debugging | **S** |
| 10 | P-07 | **Validate + back up the runtime policy on load** (last-known-good) | Config corruption on restart | Resilience to bad policy files | **S** |
| 11 | O-06 | **Bounded shutdown** (timeout drains, await `server.close`, then force exit) | Hung worker delays shutdown | Predictable restarts/upgrades | **S** |
| 12 | D-03 | **Consolidate the canonical threat model** into `security-model.md` | Buyers expect one canonical security doc | Faster security review | **S** |
| 13 | UX-2 / UX-3 | **In-console deploy/recovery links + "Protected in N s" quickstart** | Platform/founder personas underserved | Improves adoption/time-to-value | **S** |
| 14 | D-05 / D-06 | **Separate historical artifacts; add README doc index** | Evergreen vs dated docs ambiguity | Easier evaluation | **S** |

---

## Future Enhancements

Valuable, not required for pilot. Explicitly out of scope for this initiative (no new product categories).

| ID | Item | Rationale |
| --- | --- | --- |
| F-1 | Managed-KMS/HSM custody providers (AWS KMS, Azure Key Vault, GCP KMS, PKCS#11) | Interface slots already documented in `src/custody`; implement per enterprise demand |
| F-2 | Optional enterprise identity (Entra ID, Okta, SSO), centralized policy, fleet, shared audit | Keep optional and off by default; local protection must never require them |
| F-3 | Transparency log / distributed revocation propagation | Stronger multi-node trust guarantees |
| F-4 | Signed installer artifacts + auto-update channel | Supply-chain hardening for the desktop binary |
| F-5 | Conformance vectors for the full Policy Engine spec | Per `docs/mnde-policy-engine-production-spec-v1.md` |

---

## Sequenced summary

```
Critical:  S-02 → O-01 → O-03
High:      O-05 → O-02 → O-04 → D-02
Medium:    S-05 → P-04 → P-07 → O-06 → D-03 → UX-2/3 → D-05/06
Future:    KMS/HSM, enterprise identity, transparency log, signed installer, PE conformance
```

## Effort rollup

- **Critical:** 1×L + 2×M — the installer is the long pole.
- **High:** 2×S + 1×M + 1×S — mostly small once `mnde doctor` exists.
- **Medium:** 1×M + 6×S — incremental hardening.

## Pilot-readiness statement

With the **Critical** tier complete, a skeptical engineering leader can conclude MNDe is **stable, understandable, auditable, verifiable, operationally manageable, and secure** for a controlled pilot. The **High** tier makes it self-serviceable for platform teams; the **Medium** tier closes the remaining auditor/operator polish. No item requires adding a new product category, AI feature, or cloud dependency.
