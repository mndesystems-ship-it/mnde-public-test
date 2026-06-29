// Canonical decision-engine signal.
//
// Single source of truth for "which decision engine is selected" and, more
// importantly, for the security property "is policy enforcement enabled". The
// production posture gate must express that *outcome*, not match a specific
// engine name — so when a future enforcement backend is added (e.g. a next-gen
// or enterprise engine), it is registered here ONCE and every caller (the
// sidecar's engine selection and the production gate) follows automatically.
//
// "legacy" is the non-enforced default pipeline; it is intentionally NOT in the
// enforcement set.

// Engines that constitute an enforced policy decision path. Add future
// enforcement backends here — this is the only place that should change.
export const POLICY_ENFORCEMENT_ENGINES = new Set(["policy-engine"]);

const DEFAULT_ENGINE = "legacy";

// Resolve the configured engine to a known value. Any value in the enforcement
// set is returned as-is; anything else (including unset) is the legacy default.
export function resolveDecisionEngine(env = process.env) {
  const raw = env.MNDE_DECISION_ENGINE;
  return POLICY_ENFORCEMENT_ENGINES.has(raw) ? raw : DEFAULT_ENGINE;
}

// The security property the production gate cares about: is an enforced policy
// engine selected? Independent of which specific enforcement engine it is.
export function isPolicyEnforcementEnabled(env = process.env) {
  return POLICY_ENFORCEMENT_ENGINES.has(env.MNDE_DECISION_ENGINE);
}
