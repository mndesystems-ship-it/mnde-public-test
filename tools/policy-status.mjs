#!/usr/bin/env node
// Read-only policy lifecycle status: DRAFT / READY / ACTIVE / RETIRED.
//
// Answers "which reviewed policy is authoritative right now?" by reading the
// signed bundle-state file the activation boundary maintains, and classifies a
// working policy against it. It NEVER signs, activates, or writes anything.
//
// Usage:
//   node tools/policy-status.mjs [--policy <working.json>] [--bundle <active.bundle.json>] [--state <state.json>]
//
//   --policy <path>  A working compiled policy (schema_version "1.0") to classify.
//   --bundle <path>  The signed mnde.policy.bundle.v1 currently wired to the engine.
//                    Defaults to $MNDE_PE_POLICY_BUNDLE.
//   --state  <path>  The mnde.policy.bundle.state.v1 file.
//                    Defaults to $MNDE_PE_POLICY_BUNDLE_STATE.
//
// Exit code is 0 whenever status could be reported (this is a status command,
// not a gate). It exits non-zero only on unreadable/malformed inputs.

import { readFileSync } from "node:fs";

import { evaluatePolicyPhase, activationHistory, currentActivation, fingerprint } from "../src/policy-lifecycle/index.mjs";

function fail(message) { process.stderr.write(`policy-status: ${message}\n`); process.exit(1); }

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) { const key = a.slice(2); const value = argv[i + 1]; if (value === undefined || value.startsWith("--")) fail(`missing value for --${key}`); args[key] = value; i++; }
  }
  return args;
}

function readJson(path, label) {
  let text;
  try { text = readFileSync(path, "utf8"); } catch (e) { fail(`could not read ${label} (${path}): ${e?.message ?? e}`); }
  try { return JSON.parse(text); } catch (e) { fail(`${label} is not valid JSON (${path}): ${e?.message ?? e}`); }
}

const args = parseArgs(process.argv.slice(2));
const bundlePath = args.bundle ?? process.env.MNDE_PE_POLICY_BUNDLE;
const statePath = args.state ?? process.env.MNDE_PE_POLICY_BUNDLE_STATE;

const activeBundle = bundlePath ? readJson(bundlePath, "signed bundle") : null;
const state = statePath ? readJson(statePath, "bundle state") : null;
const policyDocument = args.policy ? readJson(args.policy, "working policy") : null;

const out = [];
out.push("MNDe policy lifecycle status");
out.push("");

// Current authority.
if (activeBundle) {
  out.push("Active authority (wired signed bundle):");
  out.push(`  policy_id: ${activeBundle.policy_id}   serial: ${activeBundle.serial}   fingerprint: ${fingerprint(activeBundle.policy_hash)}`);
  if (state) {
    const cur = currentActivation(state, activeBundle.policy_id);
    if (!cur) out.push("  WARNING: this policy_id has no ACTIVATED event in the state file.");
    else if (cur.serial !== activeBundle.serial) out.push(`  WARNING: the state's current activation for this policy is serial ${cur.serial}, not ${activeBundle.serial} — the wired bundle is not current.`);
  }
} else if (state) {
  const cur = currentActivation(state);
  if (cur) out.push(`Active authority (from state): policy_id: ${cur.policy_id}   serial: ${cur.serial}${cur.activated_at ? `   activated_at: ${cur.activated_at}` : ""}`);
  else out.push("Active authority: none recorded in the state file.");
} else {
  out.push("Active authority: not provided (pass --bundle and/or --state, or set MNDE_PE_POLICY_BUNDLE / MNDE_PE_POLICY_BUNDLE_STATE).");
}
out.push("");

// Working policy classification.
if (policyDocument) {
  const r = evaluatePolicyPhase({ policyDocument, activeBundle, state });
  out.push(`Working policy (${args.policy}):`);
  out.push(`  phase: ${r.phase}`);
  out.push(`  policy_hash: ${r.workingHash}`);
  if (r.phase === "DRAFT" || r.phase === "READY") out.push("  (no execution authority — activation is a separate, explicit, signed operation)");
  if (r.dirtyFromActive) out.push(`  NOTE: this is a new revision of the active policy line "${policyDocument.policy_id}". The active authority is UNCHANGED until you activate this revision.`);
  out.push("");
}

// History.
if (state) {
  const hist = activationHistory(state);
  if (hist.length) {
    out.push("Activation history (most recent last):");
    for (const h of hist) out.push(`  serial ${h.serial}  ${h.phase.padEnd(7)}  ${h.policy_id}${h.activated_at ? `  (${h.activated_at})` : ""}`);
  }
}

process.stdout.write(out.join("\n") + "\n");
