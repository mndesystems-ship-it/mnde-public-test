# 5. Documentation Audit Report

Reviews README, architecture/security/integration docs, the reviewer kit, and deployment/troubleshooting guides for accuracy, currency, and production framing.

## Inventory (docs/)

26 documents plus this initiative. Core set: `execution-firewall-overview.md`, `execution-receipt-spec-v1.md`, `mnde-policy-engine-production-spec-v1.md`, `security-model.md`, `key-custody.md`, `authority-bundle.md`, `live-receipt-signing.md`, `independent-verification.md`, `trust-anchored-verification.md`, `integration-guide.md`, `production-readiness.md`, `operational-dashboard.md`, `release-checklist.md`, `security-review-checklist.md`.

## Strengths

- **Claims are verifiable, not vague.** The README pairs every capability with a runnable command (`npm run executor-demo`, `npm run test:mcp`, etc.) and states the safety property tests assert. This is the standard the rest of the docs should match.
- **Honest scoping.** README "What It Does Not Do" and `production-readiness.md` "What the Public Tester Does Not Prove" pre-empt the buyer objections (cooperative enforcement, illustrative policy, no kernel enforcement).
- **Accurate caveats, not marketing.** Prototype language is limited to correct disclaimers (e.g. `key-custody.md:64`, `security-model.md:68,77` — "local-demo is not production custody"). No overclaiming found.

## Findings

### D-01 (High) — No runtime deployment / installation guide
`installer/README.md` covers downloading a desktop binary + manual hash check only. There is no guide for installing/operating the **sidecar runtime** as a service.
- **Fix:** add `docs/deployment-guide.md` (install, env validation, service supervision, upgrade, rollback) — pairs with Operational O-01.

### D-02 (High) — No troubleshooting guide
There is no single "it's not working / how do I diagnose" document mapping symptoms → checks (`/healthz`, `/readyz`, watchdog states, `ERR_*` codes) → fixes.
- **Fix:** add `docs/troubleshooting.md` keyed by reason code and health signal; reference the diagnostics package (O-02).

### D-03 (Medium) — Threat model is distributed, not consolidated
`security-model.md` is onboarding-scoped plus a custody section; the full threat model/trust boundaries now live in this initiative's Security report. Buyers expect one canonical doc.
- **Fix:** promote `02-security-readiness-report.md`'s threat model into a canonical `docs/security-model.md` top section (or link prominently).

### D-04 (Medium) — Repository/product naming signals "test"
Repo and package are `mnde-public-test`. For evaluation this reads as a throwaway, undercutting the production message.
- **Fix:** clarify in README that this is the public evaluation repo of the MNDe product; align naming/version (Operational O-04) before pilot.

### D-05 (Low) — Point-in-time artifacts mixed with evergreen docs
`release-891ceda-onboarding.md`, `repo-cleanup-report.md`, and the untracked `openclaw-integration-spec.md` are dated/in-flight artifacts living beside evergreen specs.
- **Fix:** move historical artifacts to `docs/history/` (or date them) so evergreen docs are unambiguous.

### D-06 (Low) — Cross-link the new production docs
`key-custody.md`, `live-receipt-signing.md`, `operational-dashboard.md`, and this initiative should be linked from the README "Documentation" section so an evaluator can find them.
- **Fix:** add a Documentation index to the README.

## Currency check

Docs reference real, present code and scripts (verified against `package.json` scripts and source paths). No stale references to removed features were found in the core set. The reviewer kit (`npm run reviewer-kit`) matches its documented behavior (`tools/reviewer-kit.mjs`).

## Verdict

Documentation is **accurate and honest** — its main deficits are *missing* operational docs (deployment, troubleshooting) and *organization* (consolidated threat model, naming, history separation), not incorrect or prototype-flavored content. Closing D-01/D-02 is required before a platform team can self-serve a pilot.
