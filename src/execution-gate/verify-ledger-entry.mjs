// Offline verifier for mnde.execution_ledger_entry.v1.

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";
import { findBundleKey, fingerprintOf, verifyAuthorityBundle, verifyCanonical } from "../custody/index.mjs";
import {
  canonicalLedgerSignaturePayload,
  LEDGER_ERROR_CODES,
  LEDGER_SCHEMA,
  ledgerEntryHash,
  ledgerSignaturePayloadHash,
  validateLedgerEntry
} from "./ledger.mjs";
import { verifySignedExecutionReceipt } from "./verify-signed-receipt.mjs";
import { verifySignedExecutionResult } from "./verify-signed-result.mjs";

export { LEDGER_ERROR_CODES };

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sha256Tagged(value) {
  return `sha256:${sha256(canonicalizeJson(value))}`;
}

function policyHashFromReceipt(receipt) {
  return receipt?.policy_hash ?? receipt?.policy_provenance?.policy_hash ?? null;
}

function check(checks, name, ok, detail) {
  checks[name] = { ok, ...(detail !== undefined ? { detail } : {}) };
  return ok;
}

function fail(checks, code, message) {
  return { valid: false, code, message, checks };
}

function pass(checks, envelope) {
  return {
    valid: true,
    schema: LEDGER_SCHEMA,
    ledger_id: envelope.ledger_entry.ledger_id,
    sequence_number: envelope.ledger_entry.sequence_number,
    entry_hash: ledgerEntryHash(envelope.ledger_entry),
    entry_type: envelope.ledger_entry.entry_type,
    executor_id: envelope.ledger_entry.executor_id,
    environment: envelope.ledger_entry.environment,
    created_at: envelope.ledger_entry.created_at,
    key_id: envelope.authority.key_id,
    key_role: "ledger",
    checks
  };
}

function mapKeyReason(reason) {
  if (reason === "KEY_REVOKED") return "LEDGER_KEY_REVOKED";
  if (reason === "KEY_EXPIRED") return "LEDGER_KEY_EXPIRED";
  if (reason === "KEY_MALFORMED") return "LEDGER_KEY_MALFORMED";
  return "LEDGER_KEY_NOT_FOUND";
}

// Verify a signed execution ledger entry.
export async function verifyLedgerEntry(envelope, options = {}) {
  const checks = {};
  try {
    const {
      authorityBundle,
      trustedRootFingerprint,
      signedReceipt,
      previousLedgerEntry,
      previousSignedReceipt = signedReceipt,
      now = new Date().toISOString(),
      nowMs = Date.parse(now),
      maxClockSkewMs = options.verifierPolicy?.maxClockSkewMs ?? 300_000
    } = options;
    const signedExecutionResult = options.signedExecutionResult ?? options.signedResult;
    const previousSignedExecutionResult = options.previousSignedExecutionResult ?? options.previousSignedResult ?? signedExecutionResult;
    const expectedLedgerId = options.expectedLedgerId ?? options.verifierPolicy?.expectedLedgerId;
    const expectedEnvironment = options.expectedEnvironment ?? options.verifierPolicy?.expectedEnvironment;
    const requirePreviousEntry = options.requirePreviousEntry ?? options.verifierPolicy?.requirePreviousEntry;

    if (!isObject(envelope) || envelope.schema !== LEDGER_SCHEMA) {
      check(checks, "schema", false, `expected ${LEDGER_SCHEMA}, got ${JSON.stringify(envelope?.schema)}`);
      return fail(checks, "LEDGER_SCHEMA_INVALID", "schema is missing or unsupported");
    }
    check(checks, "schema", true);

    if (!isObject(envelope.ledger_entry)) {
      check(checks, "ledger_entry", false, "ledger_entry must be an object");
      return fail(checks, "LEDGER_ENTRY_REQUIRED", "ledger_entry is required");
    }
    check(checks, "ledger_entry", true);

    if (!isObject(envelope.authority)) {
      check(checks, "authority", false, "authority must be an object");
      return fail(checks, "LEDGER_AUTHORITY_REQUIRED", "authority is required");
    }
    check(checks, "authority", true);

    const le = envelope.ledger_entry;
    const auth = envelope.authority;

    const validation = validateLedgerEntry(le);
    if (!validation.ok) {
      check(checks, "ledger_entry_shape", false, validation.errors.join("; "));
      return fail(checks, validation.code, validation.errors.join("; "));
    }
    check(checks, "ledger_entry_shape", true);

    if (expectedLedgerId !== undefined && le.ledger_id !== expectedLedgerId) {
      check(checks, "expected_ledger_id", false, `expected ${expectedLedgerId}, got ${le.ledger_id}`);
      return fail(checks, "LEDGER_ID_MISMATCH", "ledger_id does not match expectedLedgerId");
    }
    check(checks, "expected_ledger_id", true);

    if (expectedEnvironment !== undefined && le.environment !== expectedEnvironment) {
      check(checks, "expected_environment", false, `expected ${expectedEnvironment}, got ${le.environment}`);
      return fail(checks, "LEDGER_ENVIRONMENT_MISMATCH", "environment does not match expectedEnvironment");
    }
    check(checks, "expected_environment", true);

    const createdAtMs = Date.parse(le.created_at);
    if (Number.isNaN(nowMs) || createdAtMs > nowMs + maxClockSkewMs) {
      check(checks, "created_at_future", false, `created_at=${le.created_at}, nowMs=${nowMs}, maxClockSkewMs=${maxClockSkewMs}`);
      return fail(checks, "LEDGER_CREATED_AT_FUTURE", "created_at is too far in the future");
    }
    check(checks, "created_at_future", true);

    const authorityFields = [];
    for (const field of ["authority_id", "authority_bundle_fingerprint", "signing_key_fingerprint", "key_id", "key_role", "algorithm"]) {
      if (typeof auth[field] !== "string" || auth[field].length === 0) authorityFields.push(field);
    }
    if (authorityFields.length > 0) {
      check(checks, "authority_fields", false, `missing: ${authorityFields.join(", ")}`);
      return fail(checks, "LEDGER_AUTHORITY_REQUIRED", "authority is missing required fields");
    }
    if (auth.key_role !== "ledger") {
      check(checks, "key_role", false, `got ${auth.key_role}`);
      return fail(checks, "LEDGER_KEY_ROLE_INVALID", "authority.key_role must be ledger");
    }
    if (auth.algorithm !== "ED25519") {
      check(checks, "authority_algorithm", false, `got ${auth.algorithm}`);
      return fail(checks, "LEDGER_AUTHORITY_INVALID", "authority.algorithm must be ED25519");
    }
    check(checks, "authority_fields", true);

    if (!authorityBundle) {
      check(checks, "authority_bundle", false, "authorityBundle is required");
      return fail(checks, "LEDGER_AUTHORITY_INVALID", "authorityBundle is required");
    }
    const bundleCheck = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now });
    if (!bundleCheck.ok) {
      check(checks, "authority_bundle", false, bundleCheck.reason);
      if (bundleCheck.reason === "KEY_MALFORMED") return fail(checks, "LEDGER_KEY_MALFORMED", "ledger key has malformed public key");
      return fail(checks, "LEDGER_AUTHORITY_INVALID", `authority bundle invalid: ${bundleCheck.reason}`);
    }
    if (auth.authority_id !== authorityBundle.authority_id) {
      check(checks, "authority_bundle", false, "authority_id mismatch");
      return fail(checks, "LEDGER_AUTHORITY_INVALID", "authority_id does not match bundle");
    }
    if (auth.authority_bundle_fingerprint !== authorityBundle.root_key.fingerprint) {
      check(checks, "authority_bundle", false, "root fingerprint mismatch");
      return fail(checks, "LEDGER_AUTHORITY_INVALID", "authority_bundle_fingerprint does not match trusted bundle");
    }
    check(checks, "authority_bundle", true);

    const keyResult = findBundleKey(authorityBundle, "ledger", auth.key_id, le.created_at);
    if (!keyResult.ok) {
      const code = mapKeyReason(keyResult.reason);
      check(checks, "key_lookup", false, keyResult.reason);
      return fail(checks, code, `ledger signing key not usable: ${keyResult.reason}`);
    }
    check(checks, "key_lookup", true);

    let keyFingerprint;
    try {
      keyFingerprint = fingerprintOf(keyResult.publicKey);
    } catch {
      check(checks, "key_fingerprint", false, "malformed ledger public key");
      return fail(checks, "LEDGER_KEY_MALFORMED", "ledger key has malformed public key");
    }
    if (auth.signing_key_fingerprint !== keyFingerprint) {
      check(checks, "key_fingerprint", false, `claimed ${auth.signing_key_fingerprint}, derived ${keyFingerprint}`);
      return fail(checks, "LEDGER_AUTHORITY_INVALID", "signing_key_fingerprint does not match bundle key");
    }
    check(checks, "key_fingerprint", true);

    if (!signedReceipt) {
      check(checks, "signed_receipt", false, "signedReceipt is required");
      return fail(checks, "LEDGER_RECEIPT_INVALID", "signedReceipt is required");
    }
    const receiptCheck = await verifySignedExecutionReceipt(signedReceipt, { authorityBundle, trustedRootFingerprint, now });
    if (!receiptCheck.verified) {
      check(checks, "signed_receipt", false, receiptCheck.reason);
      return fail(checks, "LEDGER_RECEIPT_INVALID", `signed receipt invalid: ${receiptCheck.reason}`);
    }
    check(checks, "signed_receipt", true);

    if (!signedExecutionResult) {
      check(checks, "signed_result", false, "signedExecutionResult is required");
      return fail(checks, "LEDGER_RESULT_INVALID", "signedExecutionResult is required");
    }
    const preflightResultRequestHash = signedExecutionResult?.execution_result?.execution_request_hash;
    if (typeof preflightResultRequestHash === "string" && preflightResultRequestHash !== signedReceipt.request_hash) {
      check(checks, "execution_request_hash", false, `receipt=${signedReceipt.request_hash}, result=${preflightResultRequestHash}`);
      return fail(checks, "LEDGER_REQUEST_HASH_MISMATCH", "signed result request hash does not match signed receipt");
    }
    const resultCheck = await verifySignedExecutionResult(signedExecutionResult, {
      authorityBundle,
      trustedRootFingerprint,
      signedReceipt,
      now
    });
    if (!resultCheck.valid) {
      check(checks, "signed_result", false, `${resultCheck.code}: ${resultCheck.message}`);
      return fail(checks, "LEDGER_RESULT_INVALID", `signed execution result invalid: ${resultCheck.code}`);
    }
    check(checks, "signed_result", true);

    const expectedReceiptHash = sha256Tagged(signedReceipt);
    if (le.receipt_hash !== expectedReceiptHash) {
      check(checks, "receipt_hash", false, `stored ${le.receipt_hash}, computed ${expectedReceiptHash}`);
      return fail(checks, "LEDGER_RECEIPT_HASH_MISMATCH", "receipt_hash does not match supplied signed receipt");
    }
    check(checks, "receipt_hash", true);

    const expectedResultHash = sha256Tagged(signedExecutionResult);
    if (le.result_hash !== expectedResultHash) {
      check(checks, "result_hash", false, `stored ${le.result_hash}, computed ${expectedResultHash}`);
      return fail(checks, "LEDGER_RESULT_HASH_MISMATCH", "result_hash does not match supplied signed execution result");
    }
    check(checks, "result_hash", true);

    const resultRequestHash = signedExecutionResult.execution_result?.execution_request_hash;
    if (le.execution_request_hash !== signedReceipt.request_hash || resultRequestHash !== signedReceipt.request_hash || le.execution_request_hash !== resultRequestHash) {
      check(checks, "execution_request_hash", false, `ledger=${le.execution_request_hash}, receipt=${signedReceipt.request_hash}, result=${resultRequestHash}`);
      return fail(checks, "LEDGER_REQUEST_HASH_MISMATCH", "execution_request_hash does not match receipt and result");
    }
    check(checks, "execution_request_hash", true);

    const receiptPolicyHash = policyHashFromReceipt(signedReceipt);
    if (receiptPolicyHash !== null && le.policy_hash !== receiptPolicyHash) {
      check(checks, "policy_hash", false, `ledger=${le.policy_hash}, receipt=${receiptPolicyHash}`);
      return fail(checks, "LEDGER_POLICY_HASH_MISMATCH", "policy_hash does not match receipt policy hash");
    }
    check(checks, "policy_hash", true);

    const recomputedPayloadHash = ledgerSignaturePayloadHash(envelope);
    if (envelope.signature_payload_hash !== recomputedPayloadHash) {
      check(checks, "signature_payload_hash", false, `stored ${envelope.signature_payload_hash}, recomputed ${recomputedPayloadHash}`);
      return fail(checks, "LEDGER_SIGNATURE_PAYLOAD_HASH_INVALID", "signature_payload_hash does not match recomputed payload hash");
    }
    check(checks, "signature_payload_hash", true);

    const sig = envelope.verifiable_signature;
    if (!isObject(sig) || sig.algorithm !== "ED25519" || sig.key_id !== auth.key_id || typeof sig.value !== "string" || sig.value.length === 0) {
      check(checks, "signature", false, "verifiable_signature is missing or malformed");
      return fail(checks, "LEDGER_SIGNATURE_INVALID", "verifiable_signature is missing or malformed");
    }
    const sigOk = await verifyCanonical(canonicalLedgerSignaturePayload(envelope), sig.value, keyResult.publicKey);
    if (!sigOk) {
      check(checks, "signature", false, "Ed25519 signature verification failed");
      return fail(checks, "LEDGER_SIGNATURE_INVALID", "Ed25519 signature verification failed");
    }
    check(checks, "signature", true);

    if (le.sequence_number > 1 && !previousLedgerEntry && requirePreviousEntry !== false) {
      check(checks, "previous_entry", false, "previousLedgerEntry is required");
      return fail(checks, "LEDGER_PREVIOUS_REQUIRED", "previousLedgerEntry is required for sequence_number > 1");
    }
    if (previousLedgerEntry) {
      const previousCheck = await verifyLedgerEntry(previousLedgerEntry, {
        authorityBundle,
        trustedRootFingerprint,
        signedReceipt: previousSignedReceipt,
        signedExecutionResult: previousSignedExecutionResult,
        expectedLedgerId,
        expectedEnvironment,
        requirePreviousEntry: false,
        now,
        nowMs,
        maxClockSkewMs
      });
      if (!previousCheck.valid) {
        check(checks, "previous_entry", false, previousCheck.code);
        return fail(checks, "LEDGER_PREVIOUS_INVALID", `previous ledger entry invalid: ${previousCheck.code}`);
      }
      const previous = previousLedgerEntry.ledger_entry;
      if (previous.ledger_id !== le.ledger_id) {
        check(checks, "previous_ledger_id", false, `previous=${previous.ledger_id}, current=${le.ledger_id}`);
        return fail(checks, "LEDGER_ID_MISMATCH", "ledger_id does not match previous entry");
      }
      if (le.sequence_number !== previous.sequence_number + 1) {
        check(checks, "sequence_gap", false, `previous=${previous.sequence_number}, current=${le.sequence_number}`);
        return fail(checks, "LEDGER_SEQUENCE_GAP", "sequence_number must increment by exactly 1");
      }
      const expectedPreviousHash = ledgerEntryHash(previous);
      if (le.previous_entry_hash !== expectedPreviousHash) {
        check(checks, "previous_hash", false, `stored ${le.previous_entry_hash}, computed ${expectedPreviousHash}`);
        return fail(checks, "LEDGER_PREVIOUS_HASH_MISMATCH", "previous_entry_hash does not match previous entry");
      }
      check(checks, "previous_entry", true);
    } else {
      check(checks, "previous_entry", true, "genesis or isolated verification");
    }

    return pass(checks, envelope);
  } catch (error) {
    check(checks, "exception", false, error?.message ?? String(error));
    return fail(checks, "LEDGER_AUTHORITY_INVALID", "ledger verification failed closed");
  }
}
