// Shared primitives for mnde.execution_ledger_entry.v1.
//
// A ledger entry records one authority-signed execution result in an ordered
// chain. The chain link is the hash of the inner ledger_entry object:
//
//   entry_hash = "sha256:" + sha256(canonicalLedgerEntry(ledger_entry))

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import { EVIDENCE_FORBIDDEN_FIELDS as RESULT_EVIDENCE_FORBIDDEN_FIELDS } from "./result.mjs";

export const LEDGER_SCHEMA = "mnde.execution_ledger_entry.v1";
export const LEDGER_ENTRY_TYPES = new Set(["EXECUTION_RESULT"]);

export const LEDGER_ERROR_CODES = new Set([
  "LEDGER_SCHEMA_INVALID",
  "LEDGER_ENTRY_REQUIRED",
  "LEDGER_AUTHORITY_REQUIRED",
  "LEDGER_FIELD_REQUIRED",
  "LEDGER_SEQUENCE_INVALID",
  "LEDGER_CREATED_AT_INVALID",
  "LEDGER_CREATED_AT_FUTURE",
  "LEDGER_AUTHORITY_INVALID",
  "LEDGER_KEY_ROLE_INVALID",
  "LEDGER_KEY_NOT_FOUND",
  "LEDGER_KEY_EXPIRED",
  "LEDGER_KEY_REVOKED",
  "LEDGER_KEY_MALFORMED",
  "LEDGER_METADATA_FORBIDDEN_FIELD",
  "LEDGER_RECEIPT_INVALID",
  "LEDGER_RESULT_INVALID",
  "LEDGER_RECEIPT_HASH_MISMATCH",
  "LEDGER_RESULT_HASH_MISMATCH",
  "LEDGER_REQUEST_HASH_MISMATCH",
  "LEDGER_POLICY_HASH_MISMATCH",
  "LEDGER_GENESIS_PREVIOUS_HASH_INVALID",
  "LEDGER_PREVIOUS_REQUIRED",
  "LEDGER_PREVIOUS_INVALID",
  "LEDGER_ID_MISMATCH",
  "LEDGER_ENVIRONMENT_MISMATCH",
  "LEDGER_SEQUENCE_GAP",
  "LEDGER_PREVIOUS_HASH_MISMATCH",
  "LEDGER_SIGNATURE_PAYLOAD_HASH_INVALID",
  "LEDGER_SIGNATURE_INVALID"
]);

export const EVIDENCE_FORBIDDEN_FIELDS = RESULT_EVIDENCE_FORBIDDEN_FIELDS;

const UTC_ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const SHA256_TAGGED_RE = /^sha256:[a-f0-9]{64}$/;

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUtcTimestamp(value) {
  return typeof value === "string" && UTC_ISO_RE.test(value) && !Number.isNaN(Date.parse(value));
}

export function collectMetadataForbiddenFields(value, found = [], seen = new WeakSet()) {
  if (value === null || value === undefined) return found;
  if (Array.isArray(value)) {
    if (seen.has(value)) return found;
    seen.add(value);
    for (const item of value) collectMetadataForbiddenFields(item, found, seen);
    return found;
  }
  if (!isObject(value)) return found;
  if (seen.has(value)) return found;
  seen.add(value);
  for (const [field, child] of Object.entries(value)) {
    if (EVIDENCE_FORBIDDEN_FIELDS.has(field.toLowerCase())) found.push(field);
    collectMetadataForbiddenFields(child, found, seen);
  }
  return found;
}

export function validateLedgerEntry(entry) {
  if (!isObject(entry)) return { ok: false, code: "LEDGER_ENTRY_REQUIRED", errors: ["ledger_entry must be an object"] };

  const errors = [];
  const missing = [];
  for (const field of [
    "ledger_id",
    "sequence_number",
    "previous_entry_hash",
    "entry_type",
    "execution_request_hash",
    "receipt_hash",
    "result_hash",
    "policy_hash",
    "executor_id",
    "environment",
    "created_at",
    "metadata"
  ]) {
    if (!(field in entry)) missing.push(field);
  }
  if (missing.length > 0) {
    return { ok: false, code: "LEDGER_FIELD_REQUIRED", errors: [`missing required fields: ${missing.join(", ")}`] };
  }

  if (typeof entry.ledger_id !== "string" || entry.ledger_id.length === 0) errors.push("ledger_id must be a non-empty string");
  if (!Number.isInteger(entry.sequence_number) || entry.sequence_number < 1) {
    return { ok: false, code: "LEDGER_SEQUENCE_INVALID", errors: ["sequence_number must be a positive integer"] };
  }
  if (entry.sequence_number === 1 && entry.previous_entry_hash !== null) {
    return { ok: false, code: "LEDGER_GENESIS_PREVIOUS_HASH_INVALID", errors: ["sequence 1 requires previous_entry_hash null"] };
  }
  if (entry.sequence_number > 1 && !SHA256_TAGGED_RE.test(entry.previous_entry_hash)) {
    return { ok: false, code: "LEDGER_SEQUENCE_INVALID", errors: ["sequence > 1 requires previous_entry_hash sha256:<64-hex>"] };
  }
  if (!LEDGER_ENTRY_TYPES.has(entry.entry_type)) errors.push("entry_type must be EXECUTION_RESULT");
  if (typeof entry.execution_request_hash !== "string" || entry.execution_request_hash.length === 0) errors.push("execution_request_hash must be a non-empty string");
  if (!SHA256_TAGGED_RE.test(entry.receipt_hash)) errors.push("receipt_hash must be sha256:<64-hex>");
  if (!SHA256_TAGGED_RE.test(entry.result_hash)) errors.push("result_hash must be sha256:<64-hex>");
  if (entry.policy_hash !== null && (typeof entry.policy_hash !== "string" || entry.policy_hash.length === 0)) errors.push("policy_hash must be a string or null");
  if (typeof entry.executor_id !== "string" || entry.executor_id.length === 0) errors.push("executor_id must be a non-empty string");
  if (typeof entry.environment !== "string" || entry.environment.length === 0) errors.push("environment must be a non-empty string");
  if (!isUtcTimestamp(entry.created_at)) {
    return { ok: false, code: "LEDGER_CREATED_AT_INVALID", errors: ["created_at must be an ISO-8601 UTC datetime"] };
  }
  if (entry.metadata !== null && !isObject(entry.metadata)) {
    return { ok: false, code: "LEDGER_FIELD_REQUIRED", errors: ["metadata must be an object or null"] };
  }
  const forbidden = collectMetadataForbiddenFields(entry.metadata ?? {});
  if (forbidden.length > 0) {
    return { ok: false, code: "LEDGER_METADATA_FORBIDDEN_FIELD", errors: [`metadata contains forbidden fields: ${forbidden.join(", ")}`] };
  }

  return errors.length === 0 ? { ok: true } : { ok: false, code: "LEDGER_FIELD_REQUIRED", errors };
}

export function canonicalLedgerEntry(entry) {
  return canonicalizeJson(entry);
}

export function ledgerEntryHash(entry) {
  return `sha256:${sha256(canonicalLedgerEntry(entry))}`;
}

export function ledgerSignaturePayloadHash(envelope) {
  const body = {
    schema: envelope.schema,
    ledger_entry: envelope.ledger_entry,
    authority: envelope.authority
  };
  return sha256(canonicalizeJson(body));
}

export function canonicalLedgerSignaturePayload(envelope) {
  return canonicalizeJson({
    schema: envelope.schema,
    ledger_entry: envelope.ledger_entry,
    authority: envelope.authority,
    signature_payload_hash: envelope.signature_payload_hash
  });
}
