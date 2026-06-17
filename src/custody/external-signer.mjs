// External-signer custody (Tier 2) — vendor-neutral, HSM-ready.
//
// MNDe stays Ed25519-native and never holds the signing private key. Signing is
// delegated to an operator-supplied command. The private key can live in a
// PKCS#11 HSM (YubiHSM2, SoftHSM, Thales Luna) or any wrapper that speaks the
// contract below; MNDe ships no vendor SDK and makes no cloud calls.
//
// Signer contract:
//   stdin  : the exact canonical bytes to sign
//   stdout : a 64-byte Ed25519 signature, hex-encoded
//   exit 0 : success
//   nonzero: failure (MNDe fails closed)
//
// The command is run with spawn argv parsing (never a shell string), so there is
// no shell-injection surface. Every returned signature is verified against the
// configured public key before it is accepted. Anything off — timeout, nonzero
// exit, invalid hex, wrong length, signature that does not verify — fails closed.

import { spawnSync } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";

import { fingerprintOf, findBundleKey, verifyCanonical } from "./bundle.mjs";

const DEFAULT_TIMEOUT_MS = 5000;
const ED25519_SIG_HEX = /^[0-9a-f]{128}$/i; // 64 bytes => 128 hex chars

// Parse MNDE_EXTERNAL_SIGNER_CMD into argv WITHOUT a shell. A JSON array is the
// safe form for arguments with spaces; a bare string is whitespace-split.
function parseArgv(cmd) {
  if (typeof cmd !== "string" || cmd.trim().length === 0) {
    throw new Error("custody: MNDE_EXTERNAL_SIGNER_CMD not configured");
  }
  const text = cmd.trim();
  if (text.startsWith("[")) {
    let arr;
    try { arr = JSON.parse(text); } catch { throw new Error("custody: MNDE_EXTERNAL_SIGNER_CMD is not a valid JSON array"); }
    if (!Array.isArray(arr) || arr.length === 0 || !arr.every((x) => typeof x === "string" && x.length > 0)) {
      throw new Error("custody: MNDE_EXTERNAL_SIGNER_CMD must be a non-empty array of strings");
    }
    return arr;
  }
  return text.split(/\s+/);
}

function loadPublicKeyPem(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("custody: MNDE_EXTERNAL_SIGNER_PUBLIC_KEY not configured");
  }
  let pem;
  if (value.includes("BEGIN PUBLIC KEY")) {
    pem = value;
  } else {
    try { pem = readFileSync(value, "utf8"); } catch { throw new Error(`custody: cannot read MNDE_EXTERNAL_SIGNER_PUBLIC_KEY at ${value}`); }
  }
  try { createPublicKey(pem); } catch { throw new Error("custody: MNDE_EXTERNAL_SIGNER_PUBLIC_KEY is not a valid public key"); }
  return pem;
}

export function createExternalSignerCustody(env = process.env, options = {}) {
  // Published bundle (public material only).
  let bundleRaw;
  try { bundleRaw = readFileSync(env.MNDE_AUTHORITY_BUNDLE, "utf8"); }
  catch { throw new Error(`custody: cannot read MNDE_AUTHORITY_BUNDLE at ${env.MNDE_AUTHORITY_BUNDLE}`); }
  let bundle;
  try { bundle = JSON.parse(bundleRaw); } catch { throw new Error("custody: MNDE_AUTHORITY_BUNDLE is not valid JSON"); }
  if (bundle?.schema_version !== "mnde.authority.bundle.v1") {
    throw new Error("custody: MNDE_AUTHORITY_BUNDLE is not an mnde.authority.bundle.v1");
  }

  const argv = parseArgv(env.MNDE_EXTERNAL_SIGNER_CMD);
  const publicPem = loadPublicKeyPem(env.MNDE_EXTERNAL_SIGNER_PUBLIC_KEY);
  const publicFingerprint = fingerprintOf(publicPem);

  const receiptKeys = Array.isArray(bundle.keys?.receipt) ? bundle.keys.receipt : [];
  const keyId = env.MNDE_EXTERNAL_SIGNER_KEY_ID ?? receiptKeys[0]?.key_id;
  const entry = receiptKeys.find((k) => k.key_id === keyId);
  if (!entry) throw new Error(`custody: no published receipt key '${keyId ?? "?"}' in bundle`);

  // Configured public key must be the bundle's key.
  if (entry.fingerprint !== publicFingerprint) {
    throw new Error("custody: MNDE_EXTERNAL_SIGNER_PUBLIC_KEY does not match the bundle key (fingerprint mismatch)");
  }
  // Key must be active and not revoked right now.
  const now = options.now ?? new Date().toISOString();
  const usable = findBundleKey(bundle, "receipt", keyId, now);
  if (!usable.ok) throw new Error(`custody: receipt key '${keyId}' is not usable (${usable.reason})`);

  const rawTimeout = Number(env.MNDE_EXTERNAL_SIGNER_TIMEOUT_MS);
  const timeoutMs = Number.isFinite(rawTimeout) && rawTimeout > 0 ? rawTimeout : DEFAULT_TIMEOUT_MS;

  function signReceipt(payload) {
    const bytes = Buffer.from(payload, "utf8");
    const result = spawnSync(argv[0], argv.slice(1), { input: bytes, timeout: timeoutMs, maxBuffer: 1024 * 1024 });
    // Timeout, ENOENT, and other spawn failures land here. Never include key material.
    if (result.error) {
      throw new Error(`custody: external signer failed (${result.error.code ?? result.error.message ?? "spawn error"})`);
    }
    if (result.status !== 0) {
      throw new Error(`custody: external signer exited ${result.status === null ? `via signal ${result.signal}` : `with code ${result.status}`}`);
    }
    const sigHex = (result.stdout ? result.stdout.toString("utf8") : "").trim();
    if (!ED25519_SIG_HEX.test(sigHex)) {
      throw new Error("custody: external signer did not return a 64-byte Ed25519 signature as hex");
    }
    // Verify the signature against the configured public key BEFORE accepting it.
    if (!verifyCanonical(payload, sigHex, publicPem)) {
      throw new Error("custody: external signer signature did not verify against the configured public key");
    }
    return { key_id: keyId, value: sigHex.toLowerCase(), fingerprint: entry.fingerprint };
  }

  const notConfigured = (role) => () => { throw new Error(`custody: external signer is configured for receipts, not ${role}`); };

  return {
    mode: "external-signer",
    production: true,
    trustedRootFingerprint: bundle.root_key?.fingerprint ?? null,
    keyId,
    signReceipt,
    signPolicy: notConfigured("policy"),
    signApproval: notConfigured("approval"),
    getPublicBundle: () => structuredClone(bundle),
    // Startup self-test: actually invokes the signer and verifies the result.
    selfTest: () => { signReceipt('{"mnde.external_signer.selftest":true}'); return true; }
  };
}
