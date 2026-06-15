// Authority bundle format `mnde.authority.bundle.v1` + offline verifier.
//
// A bundle publishes ONLY public material: the root authority public key, and
// the receipt / policy / approval signing public keys with their key ids and
// validity windows, plus a revocation list and a root-signed bundle signature.
// Private keys never appear in a bundle and never appear in a receipt.
//
// Verification is fully offline: a verifier independently holds the trusted root
// key fingerprint (out of band), confirms the bundle's root matches it, verifies
// the bundle signature, rejects a stale bundle, and looks up signing keys while
// honoring validity windows and revocation.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

import { canonicalizeJson } from "../../shared/json.ts";

export const BUNDLE_SCHEMA = "mnde.authority.bundle.v1";

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

export function fingerprintOf(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ format: "der", type: "spki" });
  return createHash("sha256").update(der).digest("hex");
}
export function generateAuthorityKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" })
  };
}
export function signCanonical(payloadString, privateKeyPem) {
  return sign(null, Buffer.from(payloadString, "utf8"), createPrivateKey(privateKeyPem)).toString("hex");
}
export function verifyCanonical(payloadString, signatureHex, publicKeyPem) {
  try {
    return verify(null, Buffer.from(payloadString, "utf8"), createPublicKey(publicKeyPem), Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

function bundleWithoutSignature(bundle) {
  const { signature: _omit, ...rest } = bundle;
  return rest;
}

// Build and root-sign an authority bundle (public material only).
export function buildAuthorityBundle(input) {
  const mapKeys = (keys) => (keys ?? []).map((k) => ({
    key_id: k.keyId,
    public_key: k.publicPem,
    fingerprint: fingerprintOf(k.publicPem),
    valid_from: k.validFrom,
    valid_until: k.validUntil
  }));
  const body = {
    schema_version: BUNDLE_SCHEMA,
    authority_id: input.authorityId,
    issued_at: input.issuedAt,
    not_after: input.notAfter,
    root_key: { key_id: input.root.keyId, public_key: input.root.publicPem, fingerprint: fingerprintOf(input.root.publicPem) },
    keys: {
      receipt: mapKeys(input.receiptKeys),
      policy: mapKeys(input.policyKeys),
      approval: mapKeys(input.approvalKeys)
    },
    revocation: Array.isArray(input.revocation) ? input.revocation : []
  };
  return { ...body, signature: { algorithm: "ED25519", value: signCanonical(canonicalizeJson(body), input.root.privatePem) } };
}

// Verify a bundle offline. `trustedRootFingerprint` is the out-of-band trust
// anchor; the bundle is never trusted on its own say-so.
export function verifyAuthorityBundle(bundle, options = {}) {
  if (!isObject(bundle) || bundle.schema_version !== BUNDLE_SCHEMA) return { ok: false, reason: "UNSUPPORTED_BUNDLE" };
  const root = bundle.root_key;
  if (!isObject(root) || typeof root.public_key !== "string" || typeof root.fingerprint !== "string") return { ok: false, reason: "MALFORMED_BUNDLE" };
  if (fingerprintOf(root.public_key) !== root.fingerprint) return { ok: false, reason: "ROOT_FINGERPRINT_MISMATCH" };
  if (options.trustedRootFingerprint && root.fingerprint !== options.trustedRootFingerprint) return { ok: false, reason: "UNTRUSTED_ROOT" };

  const signature = bundle.signature;
  if (!isObject(signature) || signature.algorithm !== "ED25519" || typeof signature.value !== "string") return { ok: false, reason: "UNSIGNED_BUNDLE" };
  if (!verifyCanonical(canonicalizeJson(bundleWithoutSignature(bundle)), signature.value, root.public_key)) return { ok: false, reason: "BUNDLE_SIGNATURE_INVALID" };

  const now = options.now ?? new Date().toISOString();
  if (!isValidTimestamp(now)) return { ok: false, reason: "INVALID_NOW" };
  if (isValidTimestamp(bundle.not_after) && Date.parse(now) > Date.parse(bundle.not_after)) return { ok: false, reason: "BUNDLE_STALE" };
  if (options.maxAgeMs && isValidTimestamp(bundle.issued_at) && Date.parse(now) - Date.parse(bundle.issued_at) > options.maxAgeMs) return { ok: false, reason: "BUNDLE_STALE" };
  return { ok: true };
}

// Look up a signing key by role + key id, honoring revocation and validity.
export function findBundleKey(bundle, role, keyId, signedAt) {
  if (Array.isArray(bundle?.revocation) && bundle.revocation.includes(keyId)) return { ok: false, reason: "KEY_REVOKED" };
  const list = bundle?.keys?.[role];
  const key = Array.isArray(list) ? list.find((k) => k.key_id === keyId) : undefined;
  if (!key) return { ok: false, reason: "UNKNOWN_KEY" };
  if (!isValidTimestamp(signedAt)) return { ok: false, reason: "INVALID_SIGNED_AT" };
  const t = Date.parse(signedAt);
  if (isValidTimestamp(key.valid_from) && t < Date.parse(key.valid_from)) return { ok: false, reason: "KEY_EXPIRED" };
  if (isValidTimestamp(key.valid_until) && t >= Date.parse(key.valid_until)) return { ok: false, reason: "KEY_EXPIRED" };
  return { ok: true, publicKey: key.public_key };
}

// Verify a signature over a canonical payload against a bundle key (offline).
export function verifyAgainstBundle(canonicalPayload, signatureHex, role, keyId, signedAt, bundle) {
  const key = findBundleKey(bundle, role, keyId, signedAt);
  if (!key.ok) return key;
  return verifyCanonical(canonicalPayload, signatureHex, key.publicKey) ? { ok: true } : { ok: false, reason: "SIGNATURE_INVALID" };
}
