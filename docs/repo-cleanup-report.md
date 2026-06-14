# Repository Wording Cleanup Report

Goal: make the repository read like an infrastructure project described by engineers — concrete statements traceable to code, tests, demos, or receipts — while preserving future commercial/enterprise concepts in neutral language.

This pass changed wording only. No behavior, APIs, test assertions, decision logic, or output tokens were modified.

## Files changed

Documentation:
- `README.md`
- `docs/execution-firewall-overview.md`
- `docs/execution-receipt-spec-v1.md`
- `docs/README.md`
- `executor/README.md`
- `mcp/README.md`
- `shell/README.md`

Code comments (no logic touched):
- `executor/index.mjs`
- `mcp/mnde-mcp-server.mjs`
- `mcp/shell-mcp-server.mjs`
- `scripts/executor-demo.mjs`
- `scripts/mcp-demo.mjs`
- `scripts/shell-demo.mjs`
- `tests/test_mcp_server.mjs`
- `examples/executor-wrapper/agent-tool-wrapper.js`

New:
- `docs/repo-cleanup-report.md` (this file)

## Phrases removed or replaced

| Before | After |
|---|---|
| "Enforcement Wedge" (heading) | "Components" |
| "the wedge" / "the distribution wedge" / "Why this is the wedge" | removed; replaced with "What it is for" / plain description |
| "This is the sales moment" | removed |
| "verticalized proof" | "deny-by-default authorization" / removed |
| "the layer between intent and execution" | "authorize a function call through MNDe before running it" |
| "the one-command proof that MNDe sits between intent and execution" | "authorize, run on ALLOW, refuse otherwise, verify receipts" |
| "Known Reviewer Claims Now Proven" (heading) | "Verified Behaviors" (with a line stating each item maps to a test or demo) |
| "Execution Firewall" (product branding) | "pre-execution authorization layer" |
| "turn that claim into code anyone can drop in" | "Three integration paths share the same decision and receipt flow" |
| "one-line drop-in" / "ships clean" | removed |

## Claims downgraded or qualified

- Enforcement is now explicitly described as **cooperative**: MNDe evaluates an action only when the caller routes it through MNDe. It is not OS-level and does not stop a process that bypasses it. (README, overview, mcp/README.)
- The bundled decision policy is described as **small and illustrative**, not a complete policy for any deployment.
- The manual-approval threshold and the shell `APPROVAL_REQUIRED` decision are stated to depend on a **caller-supplied `hold_state`** with **no authenticated approver binding** yet.
- `orbit_intent.signatures` is stated to be **shape-validated, not cryptographically verified**.
- Verification is stated to chain to a **locally generated test authority**; there is **no published authority bundle** yet.
- The enforcement invariant in the overview is scoped: it holds for actions routed through MNDe, not for code paths that never call it.

Every retained claim corresponds to something runnable in the repo (`npm run executor-demo`, `mcp-demo`, `mcp-proxy-demo`, `shell-demo`, `reviewer-kit`, the `test:*` scripts, `verify-receipt`).

## Limitations sections added

- `README.md` → "What It Does Not Do" and "Limitations".
- `docs/execution-firewall-overview.md` → "Limitations".
- `mcp/README.md` → "Limitations".
- `docs/production-readiness.md` already contained a "What the Public Tester Does Not Prove" section and was left in place.

## Future / commercial concepts preserved (neutral language)

All retained, none claimed as complete:
- Authority model and receipt system — described as implemented (local test authority) with a published-bundle item on the roadmap.
- Replay verification, proxy architecture, executor architecture — described concretely (they exist and are tested).
- Approval-required, policy, audit, and identity concepts — kept and moved to the README "Roadmap" section as "Centralized policy and audit management", "Authenticated approval (signed approval tokens)", "Identity-aware authorization for multi-user deployments", and "A published authority bundle with documented key rotation".

## Recommendations requiring human review

1. **File rename (not done):** `docs/execution-firewall-overview.md` could be renamed to `docs/authorization-layer-overview.md` for consistency with the neutralized wording. Left as-is to avoid breaking inbound links and history; update the README "More Docs" list and `docs/README.md` if renamed.
2. **Internal engine codenames:** `preflight`, `orbit`, `arm`, `ram0na` (and the reason code `OK_RAM0NA`) are internal jargon rather than promotional, but are opaque to a new reader. Renaming to functional names (e.g. request-validation / intent / authorization / runtime) is a separate refactor that touches many imports and was not attempted here.
3. **Legacy `signature` (HMAC) field:** still emitted on receipts though no longer trusted by any verifier. Consider stopping emission in a separate change.
4. **Term "firewall":** retained only in the `execution-firewall-overview.md` filename and the ERS cross-reference; the prose no longer uses it as branding. Decide whether to drop the filename per item 1.
5. **Sidecar surface area:** unrelated to wording, but the sidecar still ships cluster, enterprise-auth, and metrics code paths not exercised by any test. Flagged in prior review; out of scope for this pass.

## Review question applied to each file

"Would a skeptical security engineer respect this wording after reading the code?" Where the answer was no — hype headings, unscoped claims, missing limitations — the wording was rewritten or qualified, and a Limitations section was added.
