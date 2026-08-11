#!/usr/bin/env node
// Published-bundle acceptance gate — the repository side of the future
// clean-machine verification test.
//
//   node scripts/verify-published-bundle.mjs
//
// Reproduces, in CI-friendly form, the governing Phase 1 acceptance path:
//
//   1. Obtain the expected pinned root fingerprint from an INDEPENDENTLY
//      configured value (env: MNDE_PINNED_ROOT_FINGERPRINT) — NOT from the bundle.
//   2. Load the published authority bundle           (env: MNDE_PUBLISHED_BUNDLE).
//   3. Authenticate the bundle against the pinned root (verifyAuthorityBundle).
//   4. Load a production-format receipt              (env: MNDE_PUBLISHED_RECEIPT).
//   5. Verify the receipt against the authenticated bundle
//      (verifySignedExecutionReceipt — production path, role "receipt").
//   6. Succeed only if the ENTIRE chain verifies.
//
// Deliberately NOT wired to trust.mnde.com and NOT a hard CI dependency: when the
// three inputs are not configured it reports NOT CONFIGURED and exits 0 (skip),
// so the repository does not depend on a published artifact until one exists.
// Verification uses the production verifiers only — no weaker "gate verifier".

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyAuthorityBundle } from "../src/custody/index.mjs";
import { verifySignedExecutionReceipt } from "../src/execution-gate/verify-signed-receipt.mjs";

export const GATE_ENV = Object.freeze({
  fingerprint: "MNDE_PINNED_ROOT_FINGERPRINT",
  bundle: "MNDE_PUBLISHED_BUNDLE",
  receipt: "MNDE_PUBLISHED_RECEIPT",
  request: "MNDE_PUBLISHED_REQUEST" // optional: enables request_hash re-check
});

// Decide gate state from env WITHOUT reading files. Returns one of:
//   { state: "skip" }                  — nothing configured
//   { state: "misconfigured", missing } — partially configured (fail closed)
//   { state: "ready", paths, fingerprint }
export function resolveConfig(env = process.env) {
  const fingerprint = env[GATE_ENV.fingerprint];
  const bundle = env[GATE_ENV.bundle];
  const receipt = env[GATE_ENV.receipt];
  const any = [fingerprint, bundle, receipt].some((v) => typeof v === "string" && v.length > 0);
  if (!any) return { state: "skip" };
  const missing = [];
  if (!fingerprint) missing.push(GATE_ENV.fingerprint);
  if (!bundle) missing.push(GATE_ENV.bundle);
  if (!receipt) missing.push(GATE_ENV.receipt);
  if (missing.length > 0) return { state: "misconfigured", missing };
  return { state: "ready", fingerprint, paths: { bundle, receipt, request: env[GATE_ENV.request] } };
}

// Pure verification core. Given the already-loaded objects, run the full chain.
// Returns { ok, steps: [{name, ok, detail}], reason }.
export async function verifyPublishedChain({ pinnedRootFingerprint, bundle, receipt, originalRequest, now = new Date().toISOString() }) {
  const steps = [];
  const record = (name, ok, detail) => { steps.push({ name, ok, detail }); return ok; };

  // Fail closed as a whole: even if an underlying verifier throws on an exotic
  // input (e.g. a value that breaks canonicalization), the gate returns a
  // controlled failure — it never throws and never reports VERIFIED.
  try {
    const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: pinnedRootFingerprint, now });
    if (!record("authenticate_bundle", bundleCheck.ok, bundleCheck.reason)) {
      return { ok: false, steps, reason: `bundle authentication failed: ${bundleCheck.reason}` };
    }

    const receiptCheck = await verifySignedExecutionReceipt(receipt, {
      authorityBundle: bundle,
      trustedRootFingerprint: pinnedRootFingerprint,
      now,
      ...(originalRequest !== undefined ? { originalRequest } : {})
    });
    if (!record("verify_receipt", receiptCheck.verified, receiptCheck.reason)) {
      return { ok: false, steps, reason: `receipt verification failed: ${receiptCheck.reason}` };
    }

    return { ok: true, steps, reason: undefined };
  } catch (error) {
    return { ok: false, steps, reason: `verification error (fail-closed): ${error?.message ?? String(error)}` };
  }
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function main() {
  const cfg = resolveConfig(process.env);
  if (cfg.state === "skip") {
    process.stdout.write("published-bundle gate: NOT CONFIGURED — skipping.\n");
    process.stdout.write(`  set ${GATE_ENV.fingerprint}, ${GATE_ENV.bundle}, ${GATE_ENV.receipt} to run against a published artifact.\n`);
    process.exit(0);
  }
  if (cfg.state === "misconfigured") {
    process.stderr.write(`published-bundle gate: partial configuration — missing ${cfg.missing.join(", ")}. Failing closed.\n`);
    process.exit(1);
  }

  let bundle, receipt, originalRequest;
  try {
    bundle = loadJson(cfg.paths.bundle);
    receipt = loadJson(cfg.paths.receipt);
    if (cfg.paths.request) originalRequest = loadJson(cfg.paths.request);
  } catch (error) {
    process.stderr.write(`published-bundle gate: cannot read inputs: ${error?.message ?? String(error)}. Failing closed.\n`);
    process.exit(1);
  }

  const result = await verifyPublishedChain({
    pinnedRootFingerprint: cfg.fingerprint, bundle, receipt, originalRequest
  });
  for (const step of result.steps) {
    process.stdout.write(`  [${step.ok ? "OK" : "FAIL"}] ${step.name}${step.detail ? ` (${step.detail})` : ""}\n`);
  }
  if (!result.ok) {
    process.stderr.write(`published-bundle gate: FAIL — ${result.reason}\n`);
    process.exit(1);
  }
  process.stdout.write("published-bundle gate: VERIFIED — root -> bundle -> receipt chain authenticated.\n");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => { process.stderr.write(`published-bundle gate: ${error?.message ?? String(error)}\n`); process.exit(1); });
}
