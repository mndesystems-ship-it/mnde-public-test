#!/usr/bin/env node
// Build a production trust root.
//
//   node scripts/init-production-authority.mjs --out /secure/path --authority-id acme-prod
//
// Generates the long-lived ROOT authority key and the first receipt signing key,
// builds a root-signed mnde.authority.bundle.v1, and verifies it before writing
// anything. Secrets are written outside the repository with 0600 permissions.
//
// What comes out:
//   <out>/root.key.pem            ROOT private key — the crown jewel. Move this
//                                 offline / into an HSM or escrow. It is NOT
//                                 needed on the serving host; it only signs the
//                                 bundle and key rotations.
//   <out>/root.pub.pem            ROOT public key.
//   <out>/receipt-signing.key.pem Receipt signing private key — this is the only
//                                 secret the sidecar needs (file-backed-production).
//   <out>/authority.bundle.json   Public bundle to publish; verifiers pin its root
//                                 fingerprint out of band.
//
// Fail-closed: refuses to write into the repository, refuses to overwrite, and
// refuses to finish if the produced bundle does not verify.

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  signCanonical,
  verifyAuthorityBundle,
  findBundleKey
} from "../src/custody/index.mjs";
import { canonicalizeJson } from "../shared/json.ts";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function addDaysIso(nowIso, days) {
  const t = Date.parse(nowIso);
  return new Date(t + days * 24 * 60 * 60 * 1000).toISOString();
}

// Pure, testable core. Returns { ok, ... } or { ok:false, reason }.
export async function initProductionAuthority(options = {}) {
  const {
    outDir,
    authorityId,
    now = new Date().toISOString(),
    validDays = 365,
    bundleDays = 90,
    receiptKeyId = "receipt-1",
    rootKeyId = "root-1",
    repoRoot = REPO_ROOT
  } = options;

  if (typeof outDir !== "string" || outDir.length === 0) return { ok: false, reason: "outDir is required" };
  if (typeof authorityId !== "string" || authorityId.length === 0) return { ok: false, reason: "authorityId is required" };
  if (/local|demo/i.test(authorityId)) return { ok: false, reason: "authorityId must not contain 'local' or 'demo' (those mark development bundles)" };

  const out = resolve(outDir);
  const root = resolve(repoRoot);
  if (out === root || out.startsWith(root + "\\") || out.startsWith(root + "/")) {
    return { ok: false, reason: "refusing to write keys inside the repository; choose an --out path outside the project" };
  }

  const paths = {
    rootPrivate: resolve(out, "root.key.pem"),
    rootPublic: resolve(out, "root.pub.pem"),
    receiptPrivate: resolve(out, "receipt-signing.key.pem"),
    bundle: resolve(out, "authority.bundle.json")
  };
  for (const p of Object.values(paths)) {
    if (existsSync(p)) return { ok: false, reason: `refusing to overwrite existing file: ${p}` };
  }

  const root_ = { keyId: rootKeyId, ...generateAuthorityKeyPair() };
  const receipt = { keyId: receiptKeyId, ...generateAuthorityKeyPair() };

  const bundle = await buildAuthorityBundle({
    authorityId,
    issuedAt: now,
    notAfter: addDaysIso(now, bundleDays),
    root: root_,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: now, validUntil: addDaysIso(now, validDays) }],
    revocation: []
  });

  // Verify the produced trust root before writing anything (fail closed).
  const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now });
  if (!bundleCheck.ok) return { ok: false, reason: `produced bundle failed verification: ${bundleCheck.reason}` };
  const probe = await signCanonical(canonicalizeJson({ probe: true }), receipt.privatePem);
  const keyCheck = findBundleKey(bundle, "receipt", receipt.keyId, now);
  if (!keyCheck.ok || probe.length === 0) return { ok: false, reason: "receipt key did not validate against the bundle" };

  mkdirSync(out, { recursive: true });
  writeFileSync(paths.rootPrivate, root_.privatePem, { mode: 0o600 });
  writeFileSync(paths.rootPublic, root_.publicPem, { mode: 0o644 });
  writeFileSync(paths.receiptPrivate, receipt.privatePem, { mode: 0o600 });
  writeFileSync(paths.bundle, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o644 });

  return {
    ok: true,
    authorityId,
    rootFingerprint: bundle.root_key.fingerprint,
    receiptKeyId: receipt.keyId,
    bundleNotAfter: bundle.not_after,
    receiptKeyValidUntil: bundle.keys.receipt[0].valid_until,
    paths
  };
}

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

async function main() {
  const outDir = arg("--out");
  const authorityId = arg("--authority-id");
  if (!outDir || !authorityId) {
    process.stderr.write("usage: node scripts/init-production-authority.mjs --out <dir-outside-repo> --authority-id <id> [--valid-days 365] [--bundle-days 90] [--receipt-key-id receipt-1] [--root-key-id root-1]\n");
    process.exit(2);
  }
  const result = await initProductionAuthority({
    outDir,
    authorityId,
    validDays: Number(arg("--valid-days", "365")),
    bundleDays: Number(arg("--bundle-days", "90")),
    receiptKeyId: arg("--receipt-key-id", "receipt-1"),
    rootKeyId: arg("--root-key-id", "root-1")
  });
  if (!result.ok) {
    process.stderr.write(`init-production-authority: ${result.reason}\n`);
    process.exit(1);
  }
  const e = (k, v) => process.stdout.write(`  ${k}=${v}\n`);
  process.stdout.write("\nProduction trust root created.\n\n");
  process.stdout.write(`Authority id:      ${result.authorityId}\n`);
  process.stdout.write(`Root fingerprint:  ${result.rootFingerprint}\n`);
  process.stdout.write("  ^ publish this and have verifiers PIN it out of band (site, signed release notes).\n\n");
  process.stdout.write("Files written:\n");
  process.stdout.write(`  ${result.paths.bundle}        (public — publish this)\n`);
  process.stdout.write(`  ${result.paths.receiptPrivate}  (sidecar secret — keep on the serving host)\n`);
  process.stdout.write(`  ${result.paths.rootPrivate}             (CROWN JEWEL — move OFFLINE / to HSM/escrow; not needed on the host)\n`);
  process.stdout.write(`  ${result.paths.rootPublic}\n\n`);
  process.stdout.write("Run the sidecar against this trust root:\n");
  e("MNDE_PROFILE", "production");
  e("MNDE_RECEIPT_SIGNING_MODE", "custody");
  e("MNDE_KEY_CUSTODY", "file-backed-production");
  e("MNDE_AUTHORITY_BUNDLE", result.paths.bundle);
  e("MNDE_RECEIPT_SIGNING_KEY", result.paths.receiptPrivate);
  e("MNDE_RECEIPT_KEY_ID", result.receiptKeyId);
  process.stdout.write(`\nReceipt key valid until ${result.receiptKeyValidUntil}; bundle stale after ${result.bundleNotAfter}.\n`);
  process.stdout.write("Rotate with: npm run authority -- rotate ...   Revoke with: npm run authority -- revoke ...\n");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    process.stderr.write(`init-production-authority: ${error?.message ?? String(error)}\n`);
    process.exit(1);
  });
}
