import { createHash, createPrivateKey, createPublicKey, sign, verify } from "crypto";
import { existsSync, readFileSync } from "fs";

const PRIVATE_KEY_URL = new URL("./receipt_keys/receipt_signing_private.pem", import.meta.url);
const PUBLIC_KEY_URL = new URL("./receipt_keys/receipt_signing_public.pem", import.meta.url);
const FALLBACK_PUBLIC_KEY_PEM = [
  "-----BEGIN PUBLIC KEY-----",
  "MCowBQYDK2VwAyEAPa7aWBEmje8lfVbjSpT9eTTYu06z1iXm+Dy8EG5VYzA=",
  "-----END PUBLIC KEY-----",
  ""
].join("\n");
const PUBLIC_KEY_PEM = existsSync(PUBLIC_KEY_URL) ? readFileSync(PUBLIC_KEY_URL, "utf8") : FALLBACK_PUBLIC_KEY_PEM;
const PUBLIC_KEY_OBJECT = createPublicKey(PUBLIC_KEY_PEM);
const PUBLIC_KEY_DER = PUBLIC_KEY_OBJECT.export({ format: "der", type: "spki" });
const PUBLIC_KEY_RAW_HEX = Buffer.from(PUBLIC_KEY_DER).subarray(-32).toString("hex");

export const RECEIPT_PUBLIC_KEY_PEM = PUBLIC_KEY_PEM;
export const RECEIPT_SIGNATURE_ALGORITHM = "ED25519";
export const RECEIPT_PUBLIC_KEY_FINGERPRINT = createHash("sha256")
  .update(Buffer.from(PUBLIC_KEY_RAW_HEX, "hex"))
  .digest("hex");
export const RECEIPT_SIGNATURE_KEY_ID = `receipt-ed25519-${RECEIPT_PUBLIC_KEY_FINGERPRINT.slice(0, 16)}`;

export function signReceiptPayload(payload: string): string {
  const privateKeyPem = readFileSync(PRIVATE_KEY_URL, "utf8");
  const privateKeyObject = createPrivateKey(privateKeyPem);
  return sign(null, Buffer.from(payload, "utf8"), privateKeyObject).toString("hex");
}

export function verifyReceiptPayloadSignature(payload: string, signatureHex: string, publicKeyPem = RECEIPT_PUBLIC_KEY_PEM): boolean {
  const publicKey = createPublicKey(publicKeyPem);
  return verify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(signatureHex, "hex"));
}
