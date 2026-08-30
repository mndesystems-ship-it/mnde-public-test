#!/usr/bin/env node
// Sign a policy (schema_version "1.0") into an mnde.policy.bundle.v1 that the
// production policy engine will accept via MNDE_PE_POLICY_BUNDLE.
//
// This is a thin CLI over signPolicyBundle() in src/policy-bundles — it adds no
// new crypto and invents no key material. You supply the POLICY signing key that
// your published authority bundle already vouches for (role: policy); the bundle
// is refused at activation unless its signing key chains to your trusted root.
//
// Usage:
//   node tools/sign-policy-bundle.mjs <policy.json> \
//     --key <policy-private-key.pem> --key-id <id> --serial <n> [options]
//
//   --key <path>        PEM file of the policy signing private key.
//                       Defaults to $MNDE_POLICY_SIGNING_KEY (a file path).
//   --key-id <id>       Signing key id (must match the authority bundle entry).
//                       Defaults to $MNDE_POLICY_KEY_ID.
//   --serial <n>        Monotonic activation serial (integer >= 1). REQUIRED.
//                       Each activation must use a serial >= the last one.
//   --issued-at <iso>   ISO-8601 UTC millisecond timestamp. Defaults to now.
//   --bundle-id <id>    Bundle id. Defaults to "<policy_id>-<serial>".
//   --allow-rollback    Mark the bundle rollback-eligible (still requires a
//                       signed rollback authorization at activation).
//   --out <path>        Write the signed bundle here. Defaults to stdout.
//
// The signed bundle is only half of production activation. You also need the
// published authority bundle and the out-of-band trusted-root fingerprint, wired
// via MNDE_PE_AUTHORITY_BUNDLE, MNDE_PE_TRUSTED_ROOT_FINGERPRINT, and
// MNDE_PE_POLICY_BUNDLE_STATE. See docs/signed-policy-bundle-evidence.md.

import { readFileSync, writeFileSync } from "node:fs";

import { signPolicyBundle } from "../src/policy-bundles/index.mjs";

function fail(message) {
  process.stderr.write(`sign-policy-bundle: ${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--allow-rollback") { args.allowRollback = true; continue; }
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) fail(`missing value for --${key}`);
      args[key] = value; i++;
      continue;
    }
    args._.push(a);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const policyPath = args._[0];
  if (!policyPath) fail("a policy JSON file path is required (see --help header in this file)");

  const keyPath = args.key ?? process.env.MNDE_POLICY_SIGNING_KEY;
  if (!keyPath) fail("no signing key: pass --key <pem-path> or set MNDE_POLICY_SIGNING_KEY");

  const keyId = args["key-id"] ?? process.env.MNDE_POLICY_KEY_ID;
  if (!keyId) fail("no key id: pass --key-id <id> or set MNDE_POLICY_KEY_ID");

  if (args.serial === undefined) fail("--serial <n> is required (monotonic activation serial, integer >= 1)");
  const serial = Number(args.serial);
  if (!Number.isSafeInteger(serial) || serial < 1) fail(`--serial must be an integer >= 1 (got "${args.serial}")`);

  let policyDocument;
  try {
    policyDocument = JSON.parse(readFileSync(policyPath, "utf8"));
  } catch (error) {
    fail(`could not read policy file: ${error?.message ?? String(error)}`);
  }
  if (!policyDocument || typeof policyDocument !== "object" || Array.isArray(policyDocument)) fail("policy file is not a JSON object");
  if (policyDocument.schema_version !== "1.0") fail(`policy schema_version must be "1.0" (got ${JSON.stringify(policyDocument.schema_version)})`);
  if (typeof policyDocument.policy_id !== "string" || policyDocument.policy_id.length === 0) fail("policy is missing a non-empty policy_id");

  let privateKeyPem;
  try {
    privateKeyPem = readFileSync(keyPath, "utf8");
  } catch (error) {
    fail(`could not read signing key: ${error?.message ?? String(error)}`);
  }

  const issuedAt = args["issued-at"] ?? new Date().toISOString();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(issuedAt)) {
    fail(`--issued-at must be an ISO-8601 UTC timestamp like 2026-08-15T12:00:00.000Z (got "${issuedAt}")`);
  }
  const bundleId = args["bundle-id"] ?? `${policyDocument.policy_id}-${serial}`;

  let bundle;
  try {
    bundle = await signPolicyBundle(
      {
        bundle_id: bundleId,
        policy_id: policyDocument.policy_id,
        serial,
        issued_at: issuedAt,
        policy_document: policyDocument,
        ...(args.allowRollback ? { allow_rollback: true } : {})
      },
      { keyId, privateKeyPem }
    );
  } catch (error) {
    fail(`signing failed: ${error?.message ?? String(error)}`);
  }

  const out = `${JSON.stringify(bundle, null, 2)}\n`;
  if (args.out) {
    try { writeFileSync(args.out, out, "utf8"); }
    catch (error) { fail(`could not write --out: ${error?.message ?? String(error)}`); }
    process.stderr.write(`signed bundle written to ${args.out} (policy_id=${bundle.policy_id}, serial=${bundle.serial}, key_id=${bundle.signing_key_id})\n`);
  } else {
    process.stdout.write(out);
  }
}

main().catch((error) => fail(error?.stack ?? String(error)));
