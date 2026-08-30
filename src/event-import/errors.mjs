export const EVENT_IMPORT_ERRORS = Object.freeze({
  INPUT_INVALID: "ERR_IMPORT_INPUT_INVALID",
  TENANT_INVALID: "ERR_IMPORT_TENANT_INVALID",
  SOURCE_INVALID: "ERR_IMPORT_SOURCE_INVALID",
  DUPLICATE: "ERR_IMPORT_DUPLICATE",
  HASH_MISMATCH: "ERR_IMPORT_HASH_MISMATCH",
  SIGNATURE_INVALID: "ERR_IMPORT_SIGNATURE_INVALID",
  MANIFEST_INVALID: "ERR_IMPORT_MANIFEST_INVALID",
  EVIDENCE_TAMPERED: "ERR_IMPORT_EVIDENCE_TAMPERED",
  ENCODING_UNSUPPORTED: "ERR_IMPORT_ENCODING_UNSUPPORTED",
  COMPRESSION_UNSUPPORTED: "ERR_IMPORT_COMPRESSION_UNSUPPORTED",
  FORMAT_UNSUPPORTED: "ERR_IMPORT_FORMAT_UNSUPPORTED",
  PARSE: "ERR_IMPORT_PARSE",
  NORMALIZATION: "ERR_IMPORT_NORMALIZATION",
  CANONICAL_INVALID: "ERR_IMPORT_CANONICAL_INVALID",
  TENANT_MISMATCH: "ERR_IMPORT_TENANT_MISMATCH",
  REFERENCE_INVALID: "ERR_IMPORT_REFERENCE_INVALID",
  PARENT_CYCLE: "ERR_IMPORT_PARENT_CYCLE",
  STATE_INVALID: "ERR_IMPORT_STATE_INVALID",
  QUERY_INVALID: "ERR_EVENT_QUERY_INVALID",
  CONNECTOR_CONTRACT: "ERR_CONNECTOR_CONTRACT",
  REPLAY_POLICY_INVALID: "ERR_REPLAY_POLICY_INVALID"
});

const DEFAULT_ACTIONS = Object.freeze({
  [EVENT_IMPORT_ERRORS.DUPLICATE]: "Use the existing import or verify that the evidence is genuinely distinct.",
  [EVENT_IMPORT_ERRORS.HASH_MISMATCH]: "Re-export the source evidence and compare it with the signed manifest.",
  [EVENT_IMPORT_ERRORS.SIGNATURE_INVALID]: "Verify the source signing key and provide an authenticated export.",
  [EVENT_IMPORT_ERRORS.MANIFEST_INVALID]: "Restore the original generated manifest or quarantine the import directory.",
  [EVENT_IMPORT_ERRORS.EVIDENCE_TAMPERED]: "Quarantine the evidence store and restore the original content-addressed object.",
  [EVENT_IMPORT_ERRORS.ENCODING_UNSUPPORTED]: "Export as UTF-8, UTF-16, or ASCII.",
  [EVENT_IMPORT_ERRORS.COMPRESSION_UNSUPPORTED]: "Extract the archive or provide a gzip stream.",
  [EVENT_IMPORT_ERRORS.FORMAT_UNSUPPORTED]: "Register a parser for this format without adding source logic to the core.",
  [EVENT_IMPORT_ERRORS.PARSE]: "Correct the source export or select the matching parser.",
  [EVENT_IMPORT_ERRORS.NORMALIZATION]: "Update the source adapter; the raw evidence has been preserved.",
  [EVENT_IMPORT_ERRORS.CANONICAL_INVALID]: "Correct the adapter output to satisfy the canonical event schema.",
  [EVENT_IMPORT_ERRORS.TENANT_MISMATCH]: "Reject cross-tenant data and correct the source adapter or import tenant.",
  [EVENT_IMPORT_ERRORS.REFERENCE_INVALID]: "Import the referenced event first or correct the relationship.",
  [EVENT_IMPORT_ERRORS.PARENT_CYCLE]: "Remove the cyclic parent relationship in the adapter output."
});

export class EventImportError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = "EventImportError";
    this.reason_code = code;
    this.severity = options.severity ?? "ERROR";
    this.suggested_action = options.suggestedAction ?? DEFAULT_ACTIONS[code] ?? "Inspect the attached evidence and retry safely.";
    this.evidence = options.evidence ?? null;
    this.import_id = options.importId ?? null;
  }
}

export function failImport(code, message, options) {
  throw new EventImportError(code, message, options);
}
