import { readFileSync } from "node:fs";

import { validateCanonicalBatch } from "./canonical.mjs";
import { EVENT_IMPORT_ERRORS, EventImportError, failImport } from "./errors.mjs";
import { createPassthroughAdapter, normalizeEvents, validateAdapter } from "./normalizer.mjs";
import { parseEvidence } from "./parsers.mjs";
import { readAndVerifyManifest, readAndVerifyRawEvidence, writeRawEvidence } from "./raw-store.mjs";
import { deterministicUuid, isSafeSegment, isUuid, isoTimestamp, randomUuid } from "./util.mjs";
import { inspectEvidence, inspectEvidenceForStaging } from "./validation.mjs";

export const IMPORT_MANIFEST_VERSION = "mnde.import.manifest.v1";

function withImport(error, importId) {
  if (error instanceof EventImportError) {
    error.import_id ??= importId;
    return error;
  }
  return new EventImportError(EVENT_IMPORT_ERRORS.STATE_INVALID, error.message ?? String(error), { cause: error, importId });
}

function inputBytes(options) {
  if (options.filePath) return readFileSync(options.filePath);
  if (Buffer.isBuffer(options.input) || options.input instanceof Uint8Array) return Buffer.from(options.input);
  if (typeof options.input === "string") return Buffer.from(options.input, "utf8");
  failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "Provide input bytes, text, or filePath");
}

export function stageEvidence(options) {
  const {
    store,
    rawRoot,
    tenantId,
    source,
    format,
    filename,
    operator,
    receivedFrom = null,
    mediaType = "application/octet-stream",
    signatures = [],
    signatureVerifier = null,
    requireSignature = false,
    warnings = [],
    schemaVersion = null,
    expectedHash = null,
    now = new Date(),
    importId = randomUuid()
  } = options;
  if (!store || typeof store.stageImport !== "function") failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "An open event store is required");
  if (typeof rawRoot !== "string" || rawRoot.length === 0) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "rawRoot is required");
  if (!isSafeSegment(tenantId)) failImport(EVENT_IMPORT_ERRORS.TENANT_INVALID, "tenantId must be a safe, non-empty identifier");
  if (!isSafeSegment(source)) failImport(EVENT_IMPORT_ERRORS.SOURCE_INVALID, "source must be a safe, non-empty identifier");
  if (!isUuid(importId)) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "importId must be a UUID");
  if (typeof format !== "string" || format.length === 0) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "format is required");
  if (typeof filename !== "string" || filename.length === 0) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "filename is required");
  if (typeof operator !== "string" || operator.length === 0) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "operator is required");
  const receivedAt = isoTimestamp(now);
  if (receivedAt === null) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "now must be a valid timestamp");

  const inspected = inspectEvidenceForStaging(inputBytes(options), { expectedHash, filename });
  const duplicate = store.findDuplicate(tenantId, source, inspected.evidenceHash);
  if (duplicate) {
    failImport(EVENT_IMPORT_ERRORS.DUPLICATE, `Evidence already exists as import ${duplicate.import_id}`, {
      importId: duplicate.import_id,
      evidence: { evidence_hash: inspected.evidenceHash, existing_status: duplicate.status }
    });
  }
  let signatureStatus = signatures.length === 0 ? "NOT_PROVIDED" : "UNVERIFIED";
  let signatureWarning = null;
  if (signatureVerifier !== null && signatures.length > 0) {
    if (typeof signatureVerifier !== "function") failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "signatureVerifier must be a function");
    try {
      const verdict = signatureVerifier(inspected.bytes, signatures);
      if (verdict && typeof verdict.then === "function") failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "signatureVerifier must be synchronous");
      signatureStatus = verdict?.verified === true ? "VERIFIED" : "INVALID";
      if (signatureStatus === "INVALID") signatureWarning = verdict?.reason ?? "Source signature did not verify";
    } catch (error) {
      signatureStatus = "INVALID";
      signatureWarning = error.message ?? "Source signature verifier failed";
    }
  }
  const manifestWarnings = [...warnings, ...(signatureWarning ? [signatureWarning] : [])];
  const { chainPosition, previousEvidenceHash } = store.nextEvidencePosition(tenantId);
  const evidenceId = deterministicUuid(`${tenantId}:${source}:${inspected.evidenceHash}`);
  const manifest = {
    manifest_version: IMPORT_MANIFEST_VERSION,
    tenant_id: tenantId,
    source,
    import_id: importId,
    hash: inspected.evidenceHash,
    expected_hash: expectedHash,
    file_count: 1,
    byte_count: inspected.bytes.length,
    received_at: receivedAt,
    received_from: receivedFrom,
    import_operator: operator,
    original_filename: filename,
    media_type: mediaType,
    encoding: inspected.encoding,
    compression: inspected.compression,
    format,
    schema_version: schemaVersion,
    signature_required: requireSignature,
    verification: { hash_status: inspected.hashStatus, signature_status: signatureStatus },
    signatures,
    warnings: manifestWarnings,
    evidence: { evidence_id: evidenceId, evidence_hash: inspected.evidenceHash, chain_position: chainPosition, previous_evidence_hash: previousEvidenceHash }
  };
  const paths = writeRawEvidence(rawRoot, manifest, inspected.bytes);
  const evidence = {
    evidence_id: evidenceId,
    evidence_hash: inspected.evidenceHash,
    chain_position: chainPosition,
    previous_evidence_hash: previousEvidenceHash,
    size_bytes: inspected.bytes.length,
    raw_path: paths.rawPath,
    manifest_path: paths.manifestPath,
    manifest_hash: paths.manifestHash,
    media_type: mediaType,
    encoding: inspected.encoding,
    compression: inspected.compression,
    signature_status: signatureStatus
  };
  return store.stageImport(manifest, evidence);
}

export function processStagedImport(options) {
  const { store, importId, adapter = createPassthroughAdapter(), now = new Date() } = options;
  const staged = store.getImport(importId);
  if (!staged) failImport(EVENT_IMPORT_ERRORS.STATE_INVALID, `Unknown import ${importId}`, { importId });
  if (staged.status === "COMPLETED") {
    return { import: staged, events: store.queryEvents({ tenant: staged.tenant_id, import_id: importId }, { limit: 1000 }), resumed: true };
  }
  validateAdapter(adapter);
  let rawEvents;
  try {
    const manifest = readAndVerifyManifest(staged);
    const bytes = readAndVerifyRawEvidence(staged.evidence);
    if (manifest.verification?.hash_status === "MISMATCH") {
      failImport(EVENT_IMPORT_ERRORS.HASH_MISMATCH, `Expected ${manifest.expected_hash}, received ${staged.evidence_hash}`, {
        importId,
        evidence: { expected_hash: manifest.expected_hash, actual_hash: staged.evidence_hash }
      });
    }
    if (staged.evidence.signature_status === "INVALID" ||
        (manifest.signature_required === true && staged.evidence.signature_status !== "VERIFIED")) {
      failImport(EVENT_IMPORT_ERRORS.SIGNATURE_INVALID, "Required source signature is absent, unverified, or invalid", {
        importId,
        evidence: { signature_status: staged.evidence.signature_status }
      });
    }
    const inspected = inspectEvidence(bytes, { expectedHash: staged.evidence_hash, filename: staged.original_filename });
    rawEvents = parseEvidence(inspected.text, {
      source: staged.source,
      format: staged.format,
      mediaType: staged.evidence.media_type,
      filename: staged.original_filename,
      importId,
      evidenceHash: staged.evidence_hash
    });
  } catch (cause) {
    const error = withImport(cause, importId);
    store.markFailure(importId, "QUARANTINED", error);
    throw error;
  }

  let events;
  try {
    events = normalizeEvents(rawEvents, {
      adapter,
      tenantId: staged.tenant_id,
      source: staged.source,
      importId,
      signatureStatus: staged.evidence.signature_status,
      manifestPath: staged.evidence.manifest_path
    });
    const nowMs = new Date(now).getTime();
    validateCanonicalBatch(events, {
      tenantId: staged.tenant_id,
      nowMs,
      isKnownReference: (eventId) => store.eventExists(staged.tenant_id, eventId)
    });
    for (const event of events) {
      if (store.eventExists(staged.tenant_id, event.event_id)) {
        failImport(EVENT_IMPORT_ERRORS.CANONICAL_INVALID, `event_id ${event.event_id} already exists`, { evidence: { event_id: event.event_id } });
      }
    }
    const completed = store.finalizeImport(importId, events, adapter);
    return { import: completed, events, resumed: staged.status !== "PENDING" };
  } catch (cause) {
    const error = withImport(cause, importId);
    store.markFailure(importId, "PRESERVED", error);
    throw error;
  }
}

export function importEvidence(options) {
  const staged = stageEvidence(options);
  return processStagedImport({ store: options.store, importId: staged.import_id, adapter: options.adapter, now: options.now });
}

export function resumeImport(options) {
  return processStagedImport(options);
}
