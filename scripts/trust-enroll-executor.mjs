#!/usr/bin/env node
// trust-enroll-executor — issue a short-lived executor credential (Design A).
//
// Generates a NEW Ed25519 keypair for one executor, writes the PRIVATE key to an
// out-of-repository directory (fails closed if the path is inside the tree), and
// issues an authority-signed credential using the custody authority bundle's root
// key. The root private key is supplied by the operator from OUTSIDE the repo and
// is never persisted or printed. No private material is ever written into the
// repository or echoed to stdout.
//
// Usage:
//   node scripts/trust-enroll-executor.mjs \
//     --executor-id mnde:local:prod:executor:codex:01 \
//     --environment prod \
//     --bundle   /secure/authority-bundle.json \
//     --root-key /secure/root_private.pem \
//     --out-dir  /secure/executors \
//     [--capability sign_execution_receipt] [--ttl-hours 24] [--issued-at ISO]
//
// Outputs (in --out-dir): <id>.key (0600), <id>.pub.pem, <id>.credential.json.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { generateAuthorityKeyPair } from "../src/custody/bundle.mjs";
import { issueExecutorCredential, executorKeyId } from "../src/custody/executor-credential.mjs";
import { isRepoContainedPath, EXECUTOR_RECEIPT_CAPABILITY } from "../src/custody/executor-identity.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const value = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[(i += 1)] : "true";
      args[key] = value;
    }
  }
  return args;
}

function die(message) {
  console.error(`trust-enroll-executor: ${message}`);
  process.exit(1);
}

function sanitizeFileStem(executorId) {
  return executorId.replace(/[^A-Za-z0-9._-]/g, "_");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const executorId = args["executor-id"];
  const environment = args.environment;
  const bundlePath = args.bundle;
  const rootKeyPath = args["root-key"];
  const outDir = args["out-dir"];
  const capability = args.capability ?? EXECUTOR_RECEIPT_CAPABILITY;
  const ttlHours = Number(args["ttl-hours"] ?? 24);

  if (!executorId) die("--executor-id is required");
  if (!environment) die("--environment is required");
  if (!bundlePath) die("--bundle is required");
  if (!rootKeyPath) die("--root-key is required");
  if (!outDir) die("--out-dir is required");
  if (!Number.isFinite(ttlHours) || ttlHours <= 0) die("--ttl-hours must be a positive number");

  // Fail closed: executor private keys and the root key must live OUTSIDE the repo.
  if (isRepoContainedPath(outDir, repoRoot)) die("--out-dir must be OUTSIDE the repository; refusing to write key material into the tree");
  if (isRepoContainedPath(rootKeyPath, repoRoot)) die("--root-key must be OUTSIDE the repository (production root material never lives in the tree)");

  let bundle;
  try {
    bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
  } catch (error) {
    die(`cannot read/parse authority bundle at ${bundlePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (bundle?.schema_version !== "mnde.authority.bundle.v1" || !bundle.root_key) {
    die("bundle is not a valid mnde.authority.bundle.v1");
  }

  let rootPrivatePem;
  try {
    rootPrivatePem = readFileSync(rootKeyPath, "utf8");
  } catch (error) {
    die(`cannot read root key at ${rootKeyPath}: ${error instanceof Error ? error.message : String(error)}`);
  }

  const issuedAt = args["issued-at"] ?? new Date().toISOString();
  const issuedMs = Date.parse(issuedAt);
  if (Number.isNaN(issuedMs)) die("--issued-at is not a valid timestamp");
  const expiresAt = new Date(issuedMs + ttlHours * 3600 * 1000).toISOString();

  // Generate the executor's OWN keypair. The private key never leaves this host.
  const { publicPem, privatePem } = generateAuthorityKeyPair();

  let credential;
  try {
    credential = await issueExecutorCredential({
      authorityBundle: bundle,
      rootPrivatePem,
      executorId,
      publicPem,
      environmentId: environment,
      capabilities: [capability],
      issuedAt,
      notBefore: issuedAt,
      expiresAt
    });
  } catch (error) {
    die(`issuance failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  mkdirSync(resolve(outDir), { recursive: true });
  const stem = sanitizeFileStem(executorId);
  const keyPath = join(resolve(outDir), `${stem}.key`);
  const pubPath = join(resolve(outDir), `${stem}.pub.pem`);
  const credPath = join(resolve(outDir), `${stem}.credential.json`);

  writeFileSync(keyPath, privatePem, { mode: 0o600 });
  writeFileSync(pubPath, publicPem, { mode: 0o644 });
  writeFileSync(credPath, `${JSON.stringify(credential, null, 2)}\n`, { mode: 0o644 });

  // Summary only — never the private key.
  console.log(JSON.stringify({
    executor_id: executorId,
    key_id: executorKeyId(publicPem),
    credential_id: credential.credential_id,
    environment_id: environment,
    capabilities: credential.capabilities,
    issued_at: issuedAt,
    expires_at: expiresAt,
    private_key_path: keyPath,
    public_key_path: pubPath,
    credential_path: credPath
  }, null, 2));
}

main().catch((error) => die(error instanceof Error ? error.message : String(error)));
