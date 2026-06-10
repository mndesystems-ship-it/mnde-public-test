#!/usr/bin/env node
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  authorityPaths,
  findAuthorityReceiptKey,
  loadAuthorityBundle,
  publicKeyFingerprint,
  signAuthorityManifest
} from "../shared/authority-manifest.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { verifyReceiptFile, verificationPassed } from "../tools/verify-receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempRoot = join(repoRoot, "reviewer-kit", "artifacts", "trust-anchor-tests");
mkdirSync(tempRoot, { recursive: true });

function writeReceipt(name, receipt) {
  const receiptPath = join(tempRoot, name);
  writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return receiptPath;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function verifyPath(receiptPath) {
  return verificationPassed(verifyReceiptFile(receiptPath));
}

function signReceiptWithKey(receipt, privateKey) {
  const { signature: _legacySignature, verifiable_signature: _verifiableSignature, ...payload } = receipt;
  const canonicalPayload = canonicalizeJson(payload);
  return sign(null, Buffer.from(canonicalPayload, "utf8"), privateKey).toString("hex");
}

const validReceipt = JSON.parse(readFileSync(join(repoRoot, "tests", "receipts", "valid-receipt.json"), "utf8").replace(/^\uFEFF/, ""));
assert(verifyPath(writeReceipt("valid-authority-receipt.json", validReceipt)), "valid authority receipt should pass");

const attackerKeys = generateKeyPairSync("ed25519");
const attackerPublicPem = attackerKeys.publicKey.export({ type: "spki", format: "pem" });
const selfSigned = structuredClone(validReceipt);
selfSigned.verifiable_signature = {
  algorithm: "ED25519",
  authority_id: validReceipt.verifiable_signature.authority_id,
  key_id: "attacker-key",
  public_key_fingerprint: publicKeyFingerprint(attackerPublicPem),
  signed_at: validReceipt.verifiable_signature.signed_at,
  value: ""
};
selfSigned.verifiable_signature.value = signReceiptWithKey(selfSigned, attackerKeys.privateKey);
assert(!verifyPath(writeReceipt("self-signed-attacker-receipt.json", selfSigned)), "self-signed attacker receipt should fail");

const wrongAuthority = structuredClone(validReceipt);
wrongAuthority.verifiable_signature.authority_id = "attacker-authority";
assert(!verifyPath(writeReceipt("modified-authority-id.json", wrongAuthority)), "modified authority_id should fail");

const wrongKey = structuredClone(validReceipt);
wrongKey.verifiable_signature.key_id = "unknown-key";
assert(!verifyPath(writeReceipt("modified-key-id.json", wrongKey)), "modified key_id should fail");

const paths = authorityPaths(repoRoot);
const manifestBackup = `${paths.manifestPath}.trust-test-backup`;
try {
  if (existsSync(paths.manifestPath)) renameSync(paths.manifestPath, manifestBackup);
  assert(!verifyPath(writeReceipt("missing-manifest.json", validReceipt)), "invalid or missing manifest should fail");
} finally {
  if (!existsSync(paths.manifestPath) && existsSync(manifestBackup)) renameSync(manifestBackup, paths.manifestPath);
}

const retiredKeys = generateKeyPairSync("ed25519");
const retiredPublicPem = retiredKeys.publicKey.export({ type: "spki", format: "pem" });
const rootPrivatePem = readFileSync(paths.rootPrivateKeyPath, "utf8");
const originalManifest = JSON.parse(readFileSync(paths.manifestPath, "utf8").replace(/^\uFEFF/, ""));
const manifestWithRetired = structuredClone(originalManifest);
const signedAt = new Date("2026-06-01T00:00:00.000Z");
manifestWithRetired.retired_keys = [{
  key_id: "receipt-key-retired-test",
  public_key: retiredPublicPem,
  public_key_fingerprint: publicKeyFingerprint(retiredPublicPem),
  valid_from: "2026-01-01T00:00:00.000Z",
  valid_to: "2026-12-31T23:59:59.000Z"
}];
manifestWithRetired.manifest_signature = signAuthorityManifest(manifestWithRetired, rootPrivatePem);
writeFileSync(paths.manifestPath, `${JSON.stringify(manifestWithRetired, null, 2)}\n`, "utf8");

try {
  const retiredReceipt = structuredClone(validReceipt);
  retiredReceipt.verifiable_signature = {
    algorithm: "ED25519",
    authority_id: originalManifest.authority_id,
    key_id: "receipt-key-retired-test",
    public_key_fingerprint: publicKeyFingerprint(retiredPublicPem),
    signed_at: signedAt.toISOString(),
    value: ""
  };
  retiredReceipt.verifiable_signature.value = signReceiptWithKey(retiredReceipt, retiredKeys.privateKey);
  assert(verifyPath(writeReceipt("retired-key-valid-at-signing-time.json", retiredReceipt)), "retired key valid at signing time should pass");
  const activeOnly = findAuthorityReceiptKey(manifestWithRetired, {
    authorityId: retiredReceipt.verifiable_signature.authority_id,
    keyId: retiredReceipt.verifiable_signature.key_id,
    signedAt,
    activeOnly: true
  });
  assert(!activeOnly.ok, "active-only retired key policy should fail");
} finally {
  writeFileSync(paths.manifestPath, `${JSON.stringify(originalManifest, null, 2)}\n`, "utf8");
}

console.log("PASS trust anchor tests");
