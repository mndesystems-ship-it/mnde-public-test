#!/usr/bin/env node
// Activate a reviewed compiled policy: sign it, verify it, and make it the ACTIVE
// authority — atomically. Thin CLI over activatePolicy() in src/policy-activate;
// it adds no crypto and no second activation path.
//
// No partial activation: if any step after signing fails, the previous ACTIVE
// authority remains authoritative and no signed bundle is written to --out.
//
// Usage:
//   node tools/activate-policy.mjs <compiled-policy.json> \
//     --key <policy-key.pem> --key-id <id> \
//     --authority <authority-bundle.json> --trusted-root <fingerprint> \
//     --state <bundle-state.json> --out <signed-bundle.json> [--now <iso>]
//
// Env fallbacks: MNDE_POLICY_SIGNING_KEY, MNDE_POLICY_KEY_ID,
//   MNDE_PE_AUTHORITY_BUNDLE, MNDE_PE_TRUSTED_ROOT_FINGERPRINT,
//   MNDE_PE_POLICY_BUNDLE_STATE. MNDE_PROFILE=production enforces the trust root.

import { readFileSync, writeFileSync } from "node:fs";

import { activatePolicy } from "../src/policy-activate/index.mjs";

function die(message) { process.stderr.write(`activate-policy: ${message}\n`); process.exit(1); }

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) { const key = a.slice(2); const value = argv[i + 1]; if (value === undefined || value.startsWith("--")) die(`missing value for --${key}`); args[key] = value; i++; }
    else args._.push(a);
  }
  return args;
}
function readJson(path, label) {
  let text; try { text = readFileSync(path, "utf8"); } catch (e) { die(`could not read ${label} (${path}): ${e?.message ?? e}`); }
  try { return JSON.parse(text); } catch (e) { die(`${label} is not valid JSON (${path}): ${e?.message ?? e}`); }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const policyPath = args._[0];
  if (!policyPath) die("a compiled policy JSON path is required");
  const keyPath = args.key ?? process.env.MNDE_POLICY_SIGNING_KEY;
  const keyId = args["key-id"] ?? process.env.MNDE_POLICY_KEY_ID;
  const authorityPath = args.authority ?? process.env.MNDE_PE_AUTHORITY_BUNDLE;
  const trustedRootFingerprint = args["trusted-root"] ?? process.env.MNDE_PE_TRUSTED_ROOT_FINGERPRINT;
  const statePath = args.state ?? process.env.MNDE_PE_POLICY_BUNDLE_STATE;
  const outPath = args.out;
  if (!keyPath) die("no signing key: pass --key or set MNDE_POLICY_SIGNING_KEY");
  if (!keyId) die("no key id: pass --key-id or set MNDE_POLICY_KEY_ID");
  if (!authorityPath) die("no authority bundle: pass --authority or set MNDE_PE_AUTHORITY_BUNDLE");
  if (!trustedRootFingerprint) die("no trusted root fingerprint: pass --trusted-root or set MNDE_PE_TRUSTED_ROOT_FINGERPRINT");
  if (!statePath) die("no state path: pass --state or set MNDE_PE_POLICY_BUNDLE_STATE");
  if (!outPath) die("no output path for the signed bundle: pass --out");

  const policyDocument = readJson(policyPath, "compiled policy");
  const authorityBundle = readJson(authorityPath, "authority bundle");
  let privateKeyPem; try { privateKeyPem = readFileSync(keyPath, "utf8"); } catch (e) { die(`could not read signing key (${keyPath}): ${e?.message ?? e}`); }

  const result = await activatePolicy({
    policyDocument, keyId, privateKeyPem, authorityBundle, trustedRootFingerprint, statePath,
    now: args.now ?? new Date().toISOString(),
    issuedAt: args["issued-at"],
    bundleId: args["bundle-id"],
    profile: process.env.MNDE_PROFILE
  });

  if (!result.ok) {
    process.stderr.write(`ACTIVATION FAILED: ${result.reason}${result.detail ? ` (${result.detail})` : ""}\n`);
    process.stderr.write("The previous ACTIVE authority is unchanged. No signed bundle was written.\n");
    process.exit(1);
  }

  // Only now — after activation and ACTIVE confirmation — persist the bundle.
  try { writeFileSync(outPath, `${JSON.stringify(result.bundle, null, 2)}\n`, "utf8"); }
  catch (e) { die(`activation succeeded but writing the signed bundle to --out failed: ${e?.message ?? e}. Wire the bundle from the state record before starting the engine.`); }

  const prev = result.previous ? `${result.previous.policy_id} serial ${result.previous.serial}` : "none";
  process.stdout.write([
    "ACTIVATION SUCCEEDED",
    `  previous authority: ${prev}`,
    `  new authority:      ${result.current.policy_id} serial ${result.current.serial}`,
    `  policy hash:        ${result.policy_hash}`,
    `  serial:             ${result.serial}`,
    `  signer:             ${result.signer_key_id}${result.signer_fingerprint ? ` (fingerprint ${result.signer_fingerprint})` : ""}`,
    `  result:             ${result.result}`,
    `  signed bundle:      ${outPath}`,
    "",
    `Wire this bundle via MNDE_PE_POLICY_BUNDLE and start the engine. Confirm anytime with:`,
    `  npm run policy:status -- --policy ${policyPath} --bundle ${outPath} --state ${statePath}`,
    ""
  ].join("\n"));
}

main().catch((e) => die(e?.stack ?? String(e)));
