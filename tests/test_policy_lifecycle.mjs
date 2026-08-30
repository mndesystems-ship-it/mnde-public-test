#!/usr/bin/env node
// Policy lifecycle: DRAFT / READY / ACTIVE / RETIRED, and the central invariant —
// editing a policy must never silently change active authority.
//
// Drives the shipped src/policy-lifecycle classifier and reuses the engine's own
// policyHash() to build active bundles, so ACTIVE is bound to the exact compiled
// policy_hash the activation boundary records.

import { policyHash } from "../src/policy-bundles/index.mjs";
import { evaluatePolicyPhase, activationHistory, currentActivation, reviewReady, fingerprint, PHASE } from "../src/policy-lifecycle/index.mjs";

let failures = 0;
function check(label, condition) {
  if (condition) { console.log(`  ok   ${label}`); }
  else { console.error(`  FAIL ${label}`); failures++; }
}

function policy(rules, id = "coding", version = "1") {
  return { schema_version: "1.0", policy_id: id, version, state: "ACTIVE", rules };
}
const RULE_READ = { rule_id: "allow-read", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read" } };
const RULE_DELETE = { rule_id: "refuse-delete", effect: "REFUSE", match: { field: "tool.tool_name", op: "eq", value: "delete" } };

const policyV1 = policy([RULE_READ]);
const policyV2 = policy([RULE_READ, RULE_DELETE]); // an edited revision — different hash

function bundle(pdoc, serial) {
  return { schema_version: "mnde.policy.bundle.v1", bundle_id: `${pdoc.policy_id}-${serial}`, policy_id: pdoc.policy_id, serial, policy_hash: policyHash(pdoc), policy_document: pdoc };
}
const bundleV1 = bundle(policyV1, 1);
const bundleV2 = bundle(policyV2, 2);

function state(events) {
  return { schema_version: "mnde.policy.bundle.state.v1", mode: "enforce", serial_floors: {}, serial_digests: {}, consumed_rollback_authorizations: [], activation_events: events };
}
const stateV1 = state([{ policy_id: "coding", serial: 1, result: "ACTIVATED", activated_at: "2026-08-20T10:00:00.000Z" }]);
const stateV1V2 = state([
  { policy_id: "coding", serial: 1, result: "ACTIVATED", activated_at: "2026-08-20T10:00:00.000Z" },
  { policy_id: "coding", serial: 2, result: "ACTIVATED", activated_at: "2026-08-21T10:00:00.000Z" }
]);

// --- DRAFT / READY ----------------------------------------------------------
console.log("draft / ready:");
check("empty/invalid working policy -> DRAFT", evaluatePolicyPhase({ policyDocument: policy([]) }).phase === PHASE.DRAFT);
check("valid working policy, nothing active -> READY", evaluatePolicyPhase({ policyDocument: policyV1 }).phase === PHASE.READY);
check("READY carries no execution authority signal (no active match)", evaluatePolicyPhase({ policyDocument: policyV1 }).active === null);
check("reviewReady flags a duplicate rule_id", reviewReady(policy([RULE_READ, { ...RULE_READ }])).ok === false);
check("reviewReady flags an invalid effect", reviewReady(policy([{ rule_id: "x", effect: "MAYBE", match: {} }])).ok === false);

// --- ACTIVE (bound to compiled hash) ----------------------------------------
console.log("active (hash-bound):");
const activeR = evaluatePolicyPhase({ policyDocument: policyV2, activeBundle: bundleV2, state: stateV1V2 });
check("working policy == current activation (by hash) -> ACTIVE", activeR.phase === PHASE.ACTIVE);
check("ACTIVE reports the active identity + fingerprint", activeR.active.policy_id === "coding" && activeR.active.serial === 2 && activeR.active.fingerprint === fingerprint(bundleV2.policy_hash));
check("ACTIVE is not dirty", activeR.dirtyFromActive === false);

// --- THE INVARIANT: editing an active policy never reads as ACTIVE -----------
console.log("editing active never changes authority (core invariant):");
const frozenActive = JSON.stringify(bundleV2);
const edited = evaluatePolicyPhase({ policyDocument: policyV1, activeBundle: bundleV2, state: stateV1V2 }); // same policy_id, different (older) content
check("an edited revision of the active policy is NOT ACTIVE", edited.phase !== PHASE.ACTIVE);
check("an edited revision is READY (a signable draft), not authoritative", edited.phase === PHASE.READY);
check("dirtyFromActive is set (new revision of the active line)", edited.dirtyFromActive === true);
check("classification never mutated the active bundle", JSON.stringify(bundleV2) === frozenActive);
check("the active identity still points at serial 2 while a revision is open", edited.active.serial === 2);

// --- RETIRED ----------------------------------------------------------------
console.log("retired:");
const retiredR = evaluatePolicyPhase({ policyDocument: policyV1, activeBundle: bundleV1, state: stateV1V2 });
check("working policy matches a superseded activation -> RETIRED", retiredR.phase === PHASE.RETIRED);
const hist = activationHistory(stateV1V2);
check("history labels the latest serial ACTIVE", hist.find((h) => h.serial === 2).phase === PHASE.ACTIVE);
check("history labels the earlier serial RETIRED", hist.find((h) => h.serial === 1).phase === PHASE.RETIRED);
check("currentActivation picks the latest serial for the policy", currentActivation(stateV1V2, "coding").serial === 2);

// --- ACTIVE only when the wired bundle is the current activation -------------
console.log("active requires the wired bundle to be current:");
check("v1 wired while state's current is v1 -> ACTIVE", evaluatePolicyPhase({ policyDocument: policyV1, activeBundle: bundleV1, state: stateV1 }).phase === PHASE.ACTIVE);
check("v1 wired while state's current is v2 -> not ACTIVE (fails closed)", evaluatePolicyPhase({ policyDocument: policyV1, activeBundle: bundleV1, state: stateV1V2 }).phase !== PHASE.ACTIVE);

// --- fingerprint is deterministic and display-shaped ------------------------
check("fingerprint is 8 uppercase hex chars", /^[0-9A-F]{8}$/.test(fingerprint(bundleV2.policy_hash)));

if (failures > 0) {
  console.error(`\nFAIL policy lifecycle (${failures} check(s) failed)`);
  process.exit(1);
}
console.log("\nPASS policy lifecycle");
