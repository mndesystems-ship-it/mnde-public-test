// Builder for mnde.execution_ledger_entry.v1.

import { createHash } from "node:crypto";

import { canonicalizeJson } from "../../shared/json.ts";
import { findBundleKey, fingerprintOf, signCanonical, verifyAuthorityBundle } from "../custody/index.mjs";
import {
  canonicalLedgerSignaturePayload,
  LEDGER_ENTRY_TYPES,
  LEDGER_SCHEMA,
  ledgerEntryHash,
  ledgerSignaturePayloadHash,
  validateLedgerEntry
} from "./ledger.mjs";
import { verifySignedExecutionReceipt } from "./verify-signed-receipt.mjs";
import { verifySignedExecutionResult } from "./verify-signed-result.mjs";

function sha256Tagged(value) {
  return `sha256:${createHash("sha256").update(canonicalizeJson(value), "utf8").digest("hex")}`;
}

function policyHashFromReceipt(receipt) {
  return receipt?.policy_hash ?? receipt?.policy_provenance?.policy_hash ?? null;
}

function defaultLedgerKeyId(bundle) {
  const ledgerKeys = bundle?.keys?.ledger;
  return Array.isArray(ledgerKeys) ? ledgerKeys[0]?.key_id : undefined;
}

function signerFromOptions(options, keyId) {
  if (options?.custody?.signLedger) return options.custody;
  if (options?.signLedger) return { signLedger: options.signLedger };
  if (options?.signingPrivateKeyPem) {
    return {
      signLedger(payload) {
        return { key_id: keyId, value: signCanonical(payload, options.signingPrivateKeyPem) };
      }
    };
  }
  return null;
}

// Build a signed execution ledger entry.
export function buildSignedLedgerEntry(options = {}) {
  const {
    authorityBundle,
    trustedRootFingerprint,
    signedReceipt,
    signedExecutionResult = options.signedResult,
    ledgerId,
    sequenceNumber,
    previousEntryHash = null,
    createdAt,
    executorId,
    environment,
    metadata = {},
    now = createdAt
  } = options;

  if (!authorityBundle || !trustedRootFingerprint) {
    throw new Error("buildSignedLedgerEntry: authorityBundle and trustedRootFingerprint are required");
  }
  if (!signedReceipt) throw new Error("buildSignedLedgerEntry: signedReceipt is required");
  if (!signedExecutionResult) throw new Error("buildSignedLedgerEntry: signedExecutionResult is required");

  const signingKeyId = options.signingKeyId ?? defaultLedgerKeyId(authorityBundle);
  if (typeof signingKeyId !== "string" || signingKeyId.length === 0) {
    throw new Error("buildSignedLedgerEntry: signingKeyId or authorityBundle.keys.ledger[0] is required");
  }
  const signer = signerFromOptions(options, signingKeyId);
  if (!signer) throw new Error("buildSignedLedgerEntry: custody.signLedger is required");

  const bundleCheck = verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now });
  if (!bundleCheck.ok) throw new Error(`buildSignedLedgerEntry: authority bundle invalid: ${bundleCheck.reason}`);

  const keyResult = findBundleKey(authorityBundle, "ledger", signingKeyId, createdAt);
  if (!keyResult.ok) throw new Error(`buildSignedLedgerEntry: ledger signing key not usable: ${keyResult.reason}`);

  const receiptCheck = verifySignedExecutionReceipt(signedReceipt, { authorityBundle, trustedRootFingerprint, now });
  if (!receiptCheck.verified) throw new Error(`buildSignedLedgerEntry: signed receipt invalid: ${receiptCheck.reason}`);

  const resultCheck = verifySignedExecutionResult(signedExecutionResult, {
    authorityBundle,
    trustedRootFingerprint,
    signedReceipt,
    now
  });
  if (!resultCheck.valid) throw new Error(`buildSignedLedgerEntry: signed result invalid: ${resultCheck.code}`);

  if (signedExecutionResult.execution_result?.execution_request_hash !== signedReceipt.request_hash) {
    throw new Error("buildSignedLedgerEntry: signed result request hash does not match signed receipt");
  }

  const ledgerEntry = {
    ledger_id: ledgerId,
    sequence_number: sequenceNumber,
    previous_entry_hash: previousEntryHash,
    entry_type: LEDGER_ENTRY_TYPES.values().next().value,
    execution_request_hash: signedReceipt.request_hash,
    receipt_hash: sha256Tagged(signedReceipt),
    result_hash: sha256Tagged(signedExecutionResult),
    policy_hash: policyHashFromReceipt(signedReceipt),
    executor_id: executorId,
    environment,
    created_at: createdAt,
    metadata
  };

  const validation = validateLedgerEntry(ledgerEntry);
  if (!validation.ok) {
    throw new Error(`buildSignedLedgerEntry: ledger_entry invalid: ${validation.code}: ${validation.errors.join("; ")}`);
  }

  const authority = {
    authority_id: authorityBundle.authority_id,
    authority_bundle_fingerprint: authorityBundle.root_key.fingerprint,
    signing_key_fingerprint: fingerprintOf(keyResult.publicKey),
    key_id: signingKeyId,
    key_role: "ledger",
    algorithm: "ED25519"
  };
  const partial = { schema: LEDGER_SCHEMA, ledger_entry: ledgerEntry, authority };
  const signaturePayloadHash = ledgerSignaturePayloadHash(partial);
  const signaturePayload = canonicalLedgerSignaturePayload({ ...partial, signature_payload_hash: signaturePayloadHash });
  const signature = signer.signLedger(signaturePayload);
  if (!signature || typeof signature.value !== "string" || signature.value.length === 0) {
    throw new Error("buildSignedLedgerEntry: custody.signLedger returned no signature value");
  }
  if (signature.key_id !== undefined && signature.key_id !== signingKeyId) {
    throw new Error("buildSignedLedgerEntry: custody.signLedger returned the wrong key_id");
  }

  return {
    ...partial,
    entry_hash: ledgerEntryHash(ledgerEntry),
    signature_payload_hash: signaturePayloadHash,
    verifiable_signature: {
      algorithm: "ED25519",
      key_id: signingKeyId,
      value: signature.value
    }
  };
}

export const buildLedgerEntry = buildSignedLedgerEntry;
