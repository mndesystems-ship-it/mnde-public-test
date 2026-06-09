import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function bootstrapReceiptKeys({ repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), ".."), force = false } = {}) {
  const keyDir = join(repoRoot, "shared", "receipt_keys");
  const privateKeyPath = join(keyDir, "receipt_signing_private.pem");
  const publicKeyPath = join(keyDir, "receipt_signing_public.pem");
  const existing = [privateKeyPath, publicKeyPath].filter((path) => existsSync(path));

  if (existing.length > 0 && !force) {
    return {
      status: "exists",
      privateKeyPath,
      publicKeyPath,
      message: "Receipt signing keys already exist. Refusing to overwrite without --force."
    };
  }

  mkdirSync(keyDir, { recursive: true });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "w", mode: 0o600 });
  writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }), { flag: "w", mode: 0o644 });

  return {
    status: "created",
    privateKeyPath,
    publicKeyPath,
    message: "Local development receipt signing keys generated."
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const force = process.argv.includes("--force");
  const result = bootstrapReceiptKeys({ force });
  console.log(result.message);
  console.log(`private: ${result.privateKeyPath}`);
  console.log(`public:  ${result.publicKeyPath}`);
  process.exit(0);
}
