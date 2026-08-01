// Executor identity — explicit Codex/Claude configuration + runtime signer load.
//
// Phase 0 / Design A: an executor is a distinct agent instance that signs the
// execution receipt with its OWN Ed25519 key before the custody receipt-role key
// countersigns. Identities are explicit and stable; private keys live OUTSIDE
// tracked repository paths and are loaded fail-closed at runtime.
//
// This module holds NO key material and imports NO node:crypto directly — all
// cryptography goes through the provider seam (src/crypto). It defines the
// canonical identities and loads a signer from operator-supplied, out-of-repo
// paths.

import { readFileSync } from "node:fs";
import { resolve, sep } from "node:path";

import { sign as providerSign, verify as providerVerify } from "../crypto/provider.mjs";
import { verifyExecutorCredential } from "./executor-credential.mjs";

// The capability an executor credential must grant to sign execution receipts.
export const EXECUTOR_RECEIPT_CAPABILITY = "sign_execution_receipt";

// Canonical, explicit executor identities. Codex and Claude are configured
// separately and never share key material. The concrete organization/environment
// components may be overridden per deployment, but the two agents stay distinct.
export const EXECUTOR_IDENTITIES = Object.freeze({
  codex: Object.freeze({ agent: "codex", executor_id: "mnde:local:prod:executor:codex:01" }),
  claude: Object.freeze({ agent: "claude", executor_id: "mnde:local:prod:executor:claude:01" })
});

export const EXECUTOR_IDENTITY_ERRORS = Object.freeze({
  MISSING: "ERR_EXECUTOR_KEY_MISSING",
  CREDENTIAL_MISSING: "ERR_EXECUTOR_CREDENTIAL_MISSING",
  KEY_MISMATCH: "ERR_EXECUTOR_KEY_MISMATCH",
  IDENTITY_MISMATCH: "ERR_EXECUTOR_IDENTITY_MISMATCH",
  KEY_PATH_UNSAFE: "ERR_EXECUTOR_KEY_PATH_UNSAFE",
  INVALID: "ERR_EXECUTOR_CREDENTIAL_INVALID"
});

// Reject any executor private-key path that resolves inside the repository. An
// empty/invalid path is treated as unsafe (fail closed).
export function isRepoContainedPath(candidatePath, repoRoot) {
  if (typeof candidatePath !== "string" || candidatePath.length === 0) return true;
  if (typeof repoRoot !== "string" || repoRoot.length === 0) return false;
  const resolved = resolve(candidatePath);
  const root = resolve(repoRoot);
  return resolved === root || resolved.startsWith(root + sep);
}

function fail(code, detail) {
  return { ok: false, code, detail };
}

// Load an executor signer from explicit, out-of-repo material. Fails closed on
// anything missing, mismatched, or key material located inside the repository.
// Async because the provider sign/verify round-trip (key-match proof) is async.
//
// options:
//   executorId       expected stable executor id (explicit configuration)
//   privateKeyPath    path to the executor Ed25519 private key PEM (outside repo)
//   credential        the authority-signed executor credential object
//   repoRoot          repository root, to reject in-repo key paths
//   authorityBundle        issuing custody bundle (to verify the credential)
//   trustedRootFingerprint out-of-band root anchor
//   environmentId          expected runtime environment
//   now                    ISO-8601 verification time
//
// Error results carry only stable codes and paths/reasons — never key material.
export async function loadExecutorSigner(options = {}) {
  const {
    executorId,
    privateKeyPath,
    credential,
    repoRoot,
    authorityBundle,
    trustedRootFingerprint,
    environmentId,
    now
  } = options;

  if (typeof executorId !== "string" || executorId.length === 0) {
    return fail(EXECUTOR_IDENTITY_ERRORS.IDENTITY_MISMATCH, "executorId is required");
  }
  if (typeof privateKeyPath !== "string" || privateKeyPath.length === 0) {
    return fail(EXECUTOR_IDENTITY_ERRORS.MISSING, "executor private key path is required");
  }
  if (repoRoot && isRepoContainedPath(privateKeyPath, repoRoot)) {
    return fail(EXECUTOR_IDENTITY_ERRORS.KEY_PATH_UNSAFE, "executor private key must not live inside the repository");
  }
  if (credential === null || credential === undefined) {
    return fail(EXECUTOR_IDENTITY_ERRORS.CREDENTIAL_MISSING, "executor credential is required");
  }

  // Fully verify the credential against the authority BEFORE trusting the key:
  // issuer signature, expiry, environment, executor identity, and capability.
  // Fail closed with the credential's own stable error code (e.g. EXPIRED).
  const credRes = await verifyExecutorCredential(credential, {
    authorityBundle,
    trustedRootFingerprint,
    environmentId,
    expectedExecutorId: executorId,
    requiredCapability: EXECUTOR_RECEIPT_CAPABILITY,
    now
  });
  if (!credRes.ok) return fail(credRes.code, credRes.detail);

  let privatePem;
  try {
    privatePem = readFileSync(privateKeyPath, "utf8");
  } catch {
    return fail(EXECUTOR_IDENTITY_ERRORS.MISSING, `cannot read executor private key at ${privateKeyPath}`);
  }

  // Prove the loaded private key corresponds to the credential's public key with
  // a sign/verify round-trip through the provider seam (no direct node:crypto).
  const probe = `mnde-executor-keycheck:${credRes.credential_id}`;
  let signature;
  try {
    signature = await providerSign(probe, privatePem);
  } catch (error) {
    return fail(EXECUTOR_IDENTITY_ERRORS.INVALID, `executor private key invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  const matches = await providerVerify(probe, signature, credRes.public_key);
  if (!matches) {
    return fail(EXECUTOR_IDENTITY_ERRORS.KEY_MISMATCH, "executor private key does not match credential public key");
  }

  return {
    ok: true,
    executorId,
    keyId: credRes.key_id,
    credentialId: credRes.credential_id,
    privatePem,
    credential
  };
}
