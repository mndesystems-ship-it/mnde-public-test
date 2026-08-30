// Policy lifecycle: DRAFT -> READY -> ACTIVE -> RETIRED.
//
// This module CLASSIFIES a policy's authority state. It is strictly read-only:
// it never signs, activates, or mutates the bundle-state file. Activation stays
// owned by activateSignedPolicyBundle() in ../policy-bundles.
//
// ACTIVE is bound to the exact compiled policy_hash the activation boundary
// records on a signed bundle — not to the policy_id — so "editing an active
// policy" can never read as ACTIVE. It fails closed: without cryptographic proof
// that the working policy equals the current activation, the strongest phase it
// will report is READY.

import { policyHash } from "../policy-bundles/index.mjs";

export const PHASE = { DRAFT: "DRAFT", READY: "READY", ACTIVE: "ACTIVE", RETIRED: "RETIRED" };

function isObject(v) { return typeof v === "object" && v !== null && !Array.isArray(v); }

// Short, display-only fingerprint of a policy hash ("sha256:abcd…" -> "ABCD1234").
export function fingerprint(hash) {
  if (typeof hash !== "string") return "";
  const hex = hash.startsWith("sha256:") ? hash.slice(7) : hash;
  return hex.slice(0, 8).toUpperCase();
}

// Shape-level review gate that separates DRAFT from READY. Mirrors the essential
// checks in the editor's validatePolicy(); deliberately conservative.
export function reviewReady(policyDocument) {
  const issues = [];
  if (!isObject(policyDocument)) return { ok: false, issues: ["not a policy object"] };
  if (policyDocument.schema_version !== "1.0") issues.push('schema_version must be "1.0"');
  if (typeof policyDocument.policy_id !== "string" || !/^[\w.-]+$/.test(policyDocument.policy_id)) issues.push("policy_id is missing or malformed");
  if (!Array.isArray(policyDocument.rules) || policyDocument.rules.length === 0) issues.push("policy has no rules (an empty policy refuses everything)");
  const seen = new Set();
  for (const r of policyDocument.rules || []) {
    if (!isObject(r) || typeof r.rule_id !== "string" || r.rule_id.length === 0) { issues.push("a rule is missing rule_id"); continue; }
    if (seen.has(r.rule_id)) issues.push(`duplicate rule_id "${r.rule_id}"`);
    seen.add(r.rule_id);
    if (r.effect !== "ALLOW" && r.effect !== "REFUSE") issues.push(`rule "${r.rule_id}" has an invalid effect`);
  }
  return { ok: issues.length === 0, issues };
}

// The current activation per policy_id = the most recent ACTIVATED event for it.
// Every earlier ACTIVATED event for the same policy_id is RETIRED (previously
// active, preserved for evidence, no longer authoritative).
export function activationHistory(state) {
  if (!isObject(state) || !Array.isArray(state.activation_events)) return [];
  const events = state.activation_events.filter((e) => isObject(e) && e.result === "ACTIVATED");
  const lastIndexByPolicy = new Map();
  events.forEach((e, i) => lastIndexByPolicy.set(e.policy_id, i));
  return events.map((e, i) => ({
    policy_id: e.policy_id,
    serial: e.serial,
    activated_at: e.activated_at ?? null,
    phase: lastIndexByPolicy.get(e.policy_id) === i ? PHASE.ACTIVE : PHASE.RETIRED
  }));
}

// The activation currently authoritative for a policy_id (or the most recent one
// overall when policyId is omitted), derived from state alone.
export function currentActivation(state, policyId) {
  const active = activationHistory(state).filter((h) => h.phase === PHASE.ACTIVE);
  if (policyId != null) return active.find((h) => h.policy_id === policyId) ?? null;
  return active.length ? active[active.length - 1] : null;
}

// Classify a WORKING (unsigned) compiled policy document against the current
// activation. `activeBundle` is the signed mnde.policy.bundle.v1 wired into the
// engine (carries policy_hash); `state` is the parsed bundle-state file.
export function evaluatePolicyPhase({ policyDocument, validated, activeBundle, state } = {}) {
  const hasPolicy = isObject(policyDocument);
  const workingHash = hasPolicy ? policyHash(policyDocument) : null;
  const policyId = hasPolicy ? policyDocument.policy_id : undefined;
  const isValid = typeof validated === "boolean" ? validated : reviewReady(policyDocument).ok;

  const bundleValid = isObject(activeBundle) && activeBundle.schema_version === "mnde.policy.bundle.v1";
  let active = null;
  if (bundleValid) {
    active = {
      policy_id: activeBundle.policy_id,
      serial: activeBundle.serial,
      policy_hash: activeBundle.policy_hash,
      fingerprint: fingerprint(activeBundle.policy_hash)
    };
  } else if (state) {
    const cur = currentActivation(state, policyId);
    if (cur) active = { policy_id: cur.policy_id, serial: cur.serial, policy_hash: null, fingerprint: null };
  }

  // Is the wired bundle actually the current activation according to state? If we
  // have no state to confirm against, trust the wired bundle as current.
  let bundleIsCurrent = true;
  if (bundleValid && state) {
    const cur = currentActivation(state, activeBundle.policy_id);
    bundleIsCurrent = !!cur && cur.serial === activeBundle.serial;
  }

  const matchesActiveHash = !!(active && active.policy_hash && workingHash && active.policy_hash === workingHash);
  const sameLine = !!(active && policyId != null && active.policy_id === policyId);

  let phase;
  if (matchesActiveHash && bundleIsCurrent) phase = PHASE.ACTIVE;
  else if (matchesActiveHash && !bundleIsCurrent) phase = PHASE.RETIRED; // equals a superseded activation
  else if (isValid) phase = PHASE.READY;
  else phase = PHASE.DRAFT;

  // Editing the active policy line without re-activating: same policy_id but the
  // working hash differs from the active bundle's hash -> a new DRAFT revision,
  // and the old activation stays authoritative until an explicit activation.
  const dirtyFromActive = !!(sameLine && active.policy_hash && workingHash && active.policy_hash !== workingHash);

  return { phase, workingHash, active, dirtyFromActive, bundleIsCurrent, valid: isValid };
}
