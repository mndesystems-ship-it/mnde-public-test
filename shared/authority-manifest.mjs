import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { canonicalizeJson } from "./json.ts";

export const AUTHORITY_ID = "mnde-public-test-local";
export const AUTHORITY_NAME = "MNDe Public Test Local Authority";
export const RECEIPT_KEY_ID = "receipt-key-local";

export function authorityPaths(repoRoot) {
  return {
    manifestPath: join(repoRoot, "authority", "authority-manifest.json"),
    rootPrivateKeyPath: join(repoRoot, "authority", "root_authority_private.pem"),
    rootPublicKeyPath: join(repoRoot, "authority", "root_authority_public.pem")
  };
}

export function publicKeyFingerprint(publicKeyPem) {
  const publicKey = createPublicKey(publicKeyPem);
  const der = publicKey.export({ format: "der", type: "spki" });
  return createHash("sha256").update(der).digest("hex");
}

export function canonicalAuthorityManifestPayload(manifest) {
  const { manifest_signature: _signature, ...payload } = manifest;
  return canonicalizeJson(payload);
}

export function signAuthorityManifest(manifest, rootPrivateKeyPem) {
  return sign(null, Buffer.from(canonicalAuthorityManifestPayload(manifest), "utf8"), createPrivateKey(rootPrivateKeyPem)).toString("hex");
}

export function verifyAuthorityManifest(manifest, rootPublicKeyPem) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    return { ok: false, reason: "manifest must be an object" };
  }
  for (const field of ["authority_id", "authority_name", "root_key_fingerprint", "active_keys", "retired_keys", "manifest_signature"]) {
    if (!(field in manifest)) return { ok: false, reason: `manifest.${field} is required` };
  }
  const rootFingerprint = publicKeyFingerprint(rootPublicKeyPem);
  if (manifest.root_key_fingerprint !== rootFingerprint) {
    return { ok: false, reason: "manifest root_key_fingerprint does not match trusted root key" };
  }
  const valid = verify(
    null,
    Buffer.from(canonicalAuthorityManifestPayload(manifest), "utf8"),
    createPublicKey(rootPublicKeyPem),
    Buffer.from(manifest.manifest_signature, "hex")
  );
  return valid ? { ok: true, reason: null } : { ok: false, reason: "manifest signature invalid" };
}

export function createAuthorityManifest({ rootPublicKeyPem, receiptPublicKeyPem, now = new Date() }) {
  const validFrom = new Date(now);
  validFrom.setUTCFullYear(validFrom.getUTCFullYear() - 1);
  const validTo = new Date(now);
  validTo.setUTCFullYear(validTo.getUTCFullYear() + 10);
  return {
    authority_id: AUTHORITY_ID,
    authority_name: AUTHORITY_NAME,
    root_key_fingerprint: publicKeyFingerprint(rootPublicKeyPem),
    active_keys: [{
      key_id: RECEIPT_KEY_ID,
      public_key: receiptPublicKeyPem,
      public_key_fingerprint: publicKeyFingerprint(receiptPublicKeyPem),
      valid_from: validFrom.toISOString(),
      valid_to: validTo.toISOString()
    }],
    retired_keys: [],
    manifest_signature: ""
  };
}

export function writeSignedAuthorityManifest({ repoRoot, rootPrivateKeyPem, rootPublicKeyPem, receiptPublicKeyPem }) {
  const paths = authorityPaths(repoRoot);
  mkdirSync(dirname(paths.manifestPath), { recursive: true });
  const manifest = createAuthorityManifest({ rootPublicKeyPem, receiptPublicKeyPem });
  manifest.manifest_signature = signAuthorityManifest(manifest, rootPrivateKeyPem);
  writeFileSync(paths.rootPublicKeyPath, rootPublicKeyPem, { encoding: "utf8", mode: 0o644 });
  writeFileSync(paths.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return { manifest, ...paths };
}

export function loadAuthorityBundle(repoRoot) {
  const paths = authorityPaths(repoRoot);
  if (!existsSync(paths.manifestPath)) {
    return { ok: false, reason: `authority manifest missing: ${resolve(paths.manifestPath)}` };
  }
  if (!existsSync(paths.rootPublicKeyPath)) {
    return { ok: false, reason: `authority root public key missing: ${resolve(paths.rootPublicKeyPath)}` };
  }
  try {
    const manifest = JSON.parse(readFileSync(paths.manifestPath, "utf8"));
    const rootPublicKeyPem = readFileSync(paths.rootPublicKeyPath, "utf8");
    const verified = verifyAuthorityManifest(manifest, rootPublicKeyPem);
    if (!verified.ok) return verified;
    return { ok: true, manifest, rootPublicKeyPem, paths };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

export function findAuthorityReceiptKey(manifest, { authorityId, keyId, signedAt = new Date(), activeOnly = false }) {
  if (manifest.authority_id !== authorityId) {
    return { ok: false, reason: "unknown authority_id" };
  }
  const allKeys = [
    ...(Array.isArray(manifest.active_keys) ? manifest.active_keys.map((key) => ({ ...key, status: "active" })) : []),
    ...(Array.isArray(manifest.retired_keys) ? manifest.retired_keys.map((key) => ({ ...key, status: "retired" })) : [])
  ];
  const key = allKeys.find((candidate) => candidate.key_id === keyId);
  if (!key) return { ok: false, reason: "unknown key_id" };
  if (activeOnly && key.status !== "active") return { ok: false, reason: "receipt key is retired" };
  const timestamp = signedAt instanceof Date ? signedAt : new Date(signedAt);
  if (Number.isNaN(timestamp.getTime())) return { ok: false, reason: "invalid receipt signing time" };
  if (new Date(key.valid_from) > timestamp || new Date(key.valid_to) < timestamp) {
    return { ok: false, reason: "receipt key was not valid at signing time" };
  }
  return { ok: true, key };
}
