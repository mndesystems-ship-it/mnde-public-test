#!/usr/bin/env node
// Export public evidence needed to independently verify a policy receipt against
// its original signed policy bundle. This command never reads or writes private
// signing keys and refuses inputs that contain obvious private material.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

function valueOf(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function fail(message) {
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(1);
}

function readJson(path, label) {
  if (!path) fail(`${label} is required`);
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch { fail(`${label} is not valid JSON or cannot be read`); }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function containsPrivateMaterial(value, path = "$") {
  if (typeof value === "string") {
    return /BEGIN (?:[A-Z ]+ )?PRIVATE KEY|privatePem|private_key|bearer\s+\S+|access[_-]?token/i.test(value) ? path : null;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const found = containsPrivateMaterial(value[i], `${path}[${i}]`);
      if (found) return found;
    }
    return null;
  }
  if (isPlainObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (/^(?:private|secret|password|token|credential)/i.test(key)) return `${path}.${key}`;
      const found = containsPrivateMaterial(child, `${path}.${key}`);
      if (found) return found;
    }
  }
  return null;
}

// M1: policy_document fields must be explicitly export-safe. This allowlist is
// the authoritative control for what policy content may be published as evidence;
// the deep blocklist scan above is defense-in-depth, not the primary gate. The
// export fails closed on any top-level policy field that is neither a known
// structural field nor declared in policy_document.export_safe_fields.
const POLICY_DOCUMENT_BASELINE = new Set(["policy_id", "schema_version", "version", "state", "rules", "export_safe_fields"]);

function assertExportSafePolicyDocument(policyBundle) {
  const policyDocument = policyBundle?.policy_document;
  if (!isPlainObject(policyDocument)) fail("policy bundle has no policy_document object");
  const declared = policyDocument.export_safe_fields;
  if (declared !== undefined && (!Array.isArray(declared) || declared.some((field) => typeof field !== "string" || field.length === 0))) {
    fail("policy_document.export_safe_fields must be an array of field names");
  }
  const allowed = new Set([...POLICY_DOCUMENT_BASELINE, ...(Array.isArray(declared) ? declared : [])]);
  const offending = Object.keys(policyDocument).find((key) => !allowed.has(key));
  if (offending) {
    fail(`policy_document field '${offending}' is not export-safe; declare it in policy_document.export_safe_fields or remove it before exporting`);
  }
}

function serialFloorSnapshot(state) {
  if (!isPlainObject(state) || state.schema_version !== "mnde.policy.bundle.state.v1" || state.mode !== "enforce" || !isPlainObject(state.serial_floors)) {
    fail("state is not a safe enforce-mode policy bundle state");
  }
  for (const [policyId, serial] of Object.entries(state.serial_floors)) {
    if (typeof policyId !== "string" || policyId.length === 0 || !Number.isSafeInteger(serial) || serial < 1) {
      fail("state serial_floors is malformed");
    }
  }
  return {
    schema_version: "mnde.policy.bundle.serial-floor-snapshot.v1",
    mode: "enforce",
    serial_floors: structuredClone(state.serial_floors)
  };
}

function writePublicJson(outDir, name, value) {
  writeFileSync(resolve(outDir, name), `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
}

const receiptPath = valueOf("--receipt");
const policyBundlePath = valueOf("--policy-bundle");
const policyAuthorityBundlePath = valueOf("--policy-authority-bundle");
const statePath = valueOf("--state");
const outDir = valueOf("--out");
if (!outDir) fail("--out is required");

const receipt = readJson(receiptPath, "receipt");
const policyBundle = readJson(policyBundlePath, "policy bundle");
const policyAuthorityBundle = readJson(policyAuthorityBundlePath, "policy authority bundle");
const state = statePath ? readJson(statePath, "state") : null;
for (const [label, value] of [["receipt", receipt], ["policy bundle", policyBundle], ["policy authority bundle", policyAuthorityBundle]]) {
  const privateAt = containsPrivateMaterial(value);
  if (privateAt) fail(`${label} contains private or credential material at ${privateAt}`);
}
// Authoritative policy-content gate (M1): refuse undeclared policy fields.
assertExportSafePolicyDocument(policyBundle);

const target = resolve(outDir);
if (existsSync(target)) fail(`output directory already exists: ${target}`);
try { mkdirSync(target, { recursive: false, mode: 0o700 }); }
catch { fail(`cannot create output directory: ${target}`); }

try {
  writePublicJson(target, "receipt.json", receipt);
  writePublicJson(target, "policy-bundle.json", policyBundle);
  writePublicJson(target, "policy-authority-bundle.json", policyAuthorityBundle);
  const rootFingerprint = policyAuthorityBundle?.root_key?.fingerprint;
  if (typeof rootFingerprint !== "string" || rootFingerprint.length === 0) fail("policy authority bundle has no root fingerprint");
  writeFileSync(resolve(target, "trusted-root-fingerprint.txt"), `${rootFingerprint}\n`, { encoding: "utf8", flag: "wx" });
  if (state) writePublicJson(target, "serial-floor-snapshot.json", serialFloorSnapshot(state));
} catch (error) {
  fail(error instanceof Error ? error.message : "evidence export failed");
}

process.stdout.write(`MNDe policy bundle evidence exported: ${target}\n`);
process.stdout.write("Public files: receipt.json, policy-bundle.json, policy-authority-bundle.json, trusted-root-fingerprint.txt\n");
if (state) process.stdout.write("Public serial-floor snapshot included.\n");
