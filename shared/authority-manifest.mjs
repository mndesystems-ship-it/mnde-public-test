import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { canonicalizeJson } from "./json.ts";

export const DEMO_AUTHORITY_ID = "mnde-public-test-demo";
export const DEMO_AUTHORITY_NAME = "MNDe Public Test Demo Authority";
export const LOCAL_AUTHORITY_ID = "mnde-public-test-local";
export const LOCAL_AUTHORITY_NAME = "MNDe Public Test Local Authority";
export const AUTHORITY_ID = LOCAL_AUTHORITY_ID;
export const AUTHORITY_NAME = LOCAL_AUTHORITY_NAME;
export const RECEIPT_KEY_ID = "receipt-key-local";

export function authorityPaths(repoRoot, { kind = "demo" } = {}) {
  const authorityRoot = kind === "local"
    ? join(repoRoot, ".mnde-test", "authority")
    : join(repoRoot, "authority");
  return {
    manifestPath: join(authorityRoot, "authority-manifest.json"),
    rootPrivateKeyPath: join(authorityRoot, "root_authority_private.pem"),
    rootPublicKeyPath: join(authorityRoot, "root_authority_public.pem")
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

export function createAuthorityManifest({
  rootPublicKeyPem,
  receiptPublicKeyPem,
  now = new Date(),
  authorityId = AUTHORITY_ID,
  authorityName = AUTHORITY_NAME,
  receiptKeyId = RECEIPT_KEY_ID
}) {
  const validFrom = new Date(now);
  validFrom.setUTCFullYear(validFrom.getUTCFullYear() - 1);
  const validTo = new Date(now);
  validTo.setUTCFullYear(validTo.getUTCFullYear() + 10);
  return {
    authority_id: authorityId,
    authority_name: authorityName,
    root_key_fingerprint: publicKeyFingerprint(rootPublicKeyPem),
    active_keys: [{
      key_id: receiptKeyId,
      public_key: receiptPublicKeyPem,
      public_key_fingerprint: publicKeyFingerprint(receiptPublicKeyPem),
      valid_from: validFrom.toISOString(),
      valid_to: validTo.toISOString()
    }],
    retired_keys: [],
    manifest_signature: ""
  };
}

export function writeSignedAuthorityManifest({
  repoRoot,
  rootPrivateKeyPem,
  rootPublicKeyPem,
  receiptPublicKeyPem,
  kind = "demo",
  authorityId = kind === "local" ? LOCAL_AUTHORITY_ID : DEMO_AUTHORITY_ID,
  authorityName = kind === "local" ? LOCAL_AUTHORITY_NAME : DEMO_AUTHORITY_NAME,
  receiptKeyId = RECEIPT_KEY_ID
}) {
  const paths = authorityPaths(repoRoot, { kind });
  mkdirSync(dirname(paths.manifestPath), { recursive: true });
  const manifest = createAuthorityManifest({ rootPublicKeyPem, receiptPublicKeyPem, authorityId, authorityName, receiptKeyId });
  manifest.manifest_signature = signAuthorityManifest(manifest, rootPrivateKeyPem);
  writeFileSync(paths.rootPublicKeyPath, rootPublicKeyPem, { encoding: "utf8", mode: 0o644 });
  writeFileSync(paths.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return { manifest, ...paths };
}

export function loadAuthorityBundle(repoRoot, { kind = "demo" } = {}) {
  const paths = authorityPaths(repoRoot, { kind });
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

export function loadAuthorityBundles(repoRoot) {
  const candidates = [
    { kind: "demo", bundle: loadAuthorityBundle(repoRoot, { kind: "demo" }) },
    { kind: "local", bundle: loadAuthorityBundle(repoRoot, { kind: "local" }) }
  ];
  return candidates.filter((candidate) => candidate.bundle.ok).map((candidate) => ({
    kind: candidate.kind,
    ...candidate.bundle
  }));
}

export function loadAuthorityBundleForReceipt(repoRoot, authorityId) {
  const bundles = loadAuthorityBundles(repoRoot);
  const bundle = bundles.find((candidate) => candidate.manifest.authority_id === authorityId);
  if (bundle) return { ok: true, ...bundle };
  const available = bundles.map((candidate) => candidate.manifest.authority_id).join(", ") || "none";
  return { ok: false, reason: `unknown authority_id ${authorityId ?? "missing"}; available authority bundles: ${available}` };
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
