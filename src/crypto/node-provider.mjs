// Node crypto provider.
//
// Implements the crypto provider seam (see provider.mjs) using Node's built-in
// node:crypto. This is the ONLY non-authoring module permitted to import
// node:crypto. Behavior is identical to the inline node:crypto calls it
// replaces — sha256 is single-shot hex, Ed25519 signatures are hex, and the
// SPKI fingerprint is sha256 hex of the DER-encoded SPKI public key.
//
// sign() and verify() are async to match the WebCrypto provider's contract,
// even though Node's primitives are synchronous; they simply resolve immediately.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes as nodeRandomBytes,
  sign as nodeSign,
  timingSafeEqual,
  verify as nodeVerify
} from "node:crypto";

export const PROVIDER_NAME = "node";

function toBuffer(data) {
  if (typeof data === "string") return Buffer.from(data, "utf8");
  return Buffer.from(data);
}

// sha256 hex of a string (utf8) or byte array. Single-shot.
export function sha256(data) {
  return createHash("sha256").update(toBuffer(data)).digest("hex");
}

// sha256 hex of the DER (SPKI) encoding of an Ed25519 public key PEM.
export function spkiFingerprint(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ format: "der", type: "spki" });
  return createHash("sha256").update(der).digest("hex");
}

// Ed25519 sign. Returns lowercase hex. Async to match the provider contract.
export async function sign(messageBytes, privateKeyPem) {
  return Buffer.from(nodeSign(null, toBuffer(messageBytes), createPrivateKey(privateKeyPem))).toString("hex");
}

// Ed25519 verify. Returns boolean; never throws (malformed inputs => false).
export async function verify(messageBytes, signatureHex, publicKeyPem) {
  try {
    return nodeVerify(
      null,
      toBuffer(messageBytes),
      createPublicKey(publicKeyPem),
      Buffer.from(signatureHex, "hex")
    );
  } catch {
    return false;
  }
}

// Generate an Ed25519 keypair as PEM strings. Node-only authoring primitive.
export function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" })
  };
}

// Constant-time equality for two hex strings or byte arrays of equal length.
// Unequal lengths short-circuit to false (lengths are not secret here).
export function constantTimeEqual(a, b) {
  const ab = toBuffer(a);
  const bb = toBuffer(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function randomBytes(length) {
  return nodeRandomBytes(length);
}

export function now() {
  return Date.now();
}
