import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { LOCAL_AUTHORITY_ID, LOCAL_AUTHORITY_NAME, authorityPaths, writeSignedAuthorityManifest } from "../shared/authority-manifest.mjs";

export function bootstrapReceiptKeys({ repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), ".."), force = false } = {}) {
  const keyDir = join(repoRoot, "shared", "receipt_keys");
  const privateKeyPath = join(keyDir, "receipt_signing_private.pem");
  const publicKeyPath = join(keyDir, "receipt_signing_public.pem");
  const authority = authorityPaths(repoRoot, { kind: "local" });
  const existing = [privateKeyPath, publicKeyPath].filter((path) => existsSync(path));
  const existingAuthority = [authority.rootPrivateKeyPath, authority.rootPublicKeyPath].filter((path) => existsSync(path));

  mkdirSync(keyDir, { recursive: true });
  mkdirSync(dirname(authority.manifestPath), { recursive: true });

  if (force || existing.length !== 2) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "w", mode: 0o600 });
    writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }), { flag: "w", mode: 0o644 });
  }

  if (force || existingAuthority.length !== 2) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(authority.rootPrivateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "w", mode: 0o600 });
    writeFileSync(authority.rootPublicKeyPath, publicKey.export({ type: "spki", format: "pem" }), { flag: "w", mode: 0o644 });
  }

  writeSignedAuthorityManifest({
    repoRoot,
    kind: "local",
    authorityId: LOCAL_AUTHORITY_ID,
    authorityName: LOCAL_AUTHORITY_NAME,
    rootPrivateKeyPem: readFileSync(authority.rootPrivateKeyPath, "utf8"),
    rootPublicKeyPem: readFileSync(authority.rootPublicKeyPath, "utf8"),
    receiptPublicKeyPem: readFileSync(publicKeyPath, "utf8")
  });

  return {
    status: existing.length === 2 && !force ? "exists" : existing.length === 1 ? "repaired" : "created",
    privateKeyPath,
    publicKeyPath,
    manifestPath: authority.manifestPath,
    message: existing.length === 2 && !force
      ? "Receipt signing keys and authority manifest are ready."
      : existing.length === 1
        ? "Local receipt signing key pair repaired and authority manifest signed."
        : "Local development receipt signing keys generated and authority manifest signed."
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
