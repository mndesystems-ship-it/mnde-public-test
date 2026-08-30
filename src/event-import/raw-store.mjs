import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import { canonicalizeJson } from "../../shared/json.ts";
import { EVENT_IMPORT_ERRORS, failImport } from "./errors.mjs";
import { isSafeSegment, sha256Tagged } from "./util.mjs";

function safeFilename(filename) {
  const leaf = basename(String(filename).replaceAll("\\", "/"));
  const sanitized = leaf.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "");
  return sanitized.length > 0 ? sanitized.slice(0, 180) : "evidence.bin";
}

function makeReadonly(path) {
  try {
    chmodSync(path, 0o444);
  } catch {
    // Windows ACLs do not always map chmod exactly. Exclusive creation and
    // content-hash verification remain the cross-platform integrity controls.
  }
}

export function writeRawEvidence(root, manifest, bytes) {
  if (!isSafeSegment(manifest.tenant_id)) failImport(EVENT_IMPORT_ERRORS.TENANT_INVALID, "tenant_id is not safe for raw-store paths");
  if (!isSafeSegment(manifest.source)) failImport(EVENT_IMPORT_ERRORS.SOURCE_INVALID, "source is not safe for raw-store paths");
  const received = new Date(manifest.received_at);
  const year = String(received.getUTCFullYear()).padStart(4, "0");
  const month = String(received.getUTCMonth() + 1).padStart(2, "0");
  const day = String(received.getUTCDate()).padStart(2, "0");
  const directory = resolve(root, manifest.tenant_id, manifest.source, year, month, day, manifest.import_id);
  mkdirSync(directory, { recursive: true });
  const rawPath = join(directory, safeFilename(manifest.original_filename));
  const manifestPath = join(directory, "manifest.json");
  const manifestBytes = Buffer.from(`${canonicalizeJson(manifest)}\n`, "utf8");
  try {
    writeFileSync(rawPath, bytes, { flag: "wx" });
    writeFileSync(manifestPath, manifestBytes, { flag: "wx" });
  } catch (cause) {
    failImport(EVENT_IMPORT_ERRORS.STATE_INVALID, "Raw evidence location already exists or is not writable", {
      cause,
      importId: manifest.import_id,
      evidence: { raw_path: rawPath, manifest_path: manifestPath }
    });
  }
  makeReadonly(rawPath);
  makeReadonly(manifestPath);
  return { rawPath, manifestPath, manifestHash: sha256Tagged(manifestBytes) };
}

export function readAndVerifyRawEvidence(evidence) {
  let bytes;
  try {
    bytes = readFileSync(evidence.raw_path);
  } catch (cause) {
    failImport(EVENT_IMPORT_ERRORS.EVIDENCE_TAMPERED, "Raw evidence is missing or unreadable", {
      cause,
      importId: evidence.import_id,
      evidence: { raw_path: evidence.raw_path }
    });
  }
  const actualHash = sha256Tagged(bytes);
  if (actualHash !== evidence.evidence_hash) {
    failImport(EVENT_IMPORT_ERRORS.EVIDENCE_TAMPERED, `Raw evidence hash changed from ${evidence.evidence_hash} to ${actualHash}`, {
      importId: evidence.import_id,
      evidence: { raw_path: evidence.raw_path, expected_hash: evidence.evidence_hash, actual_hash: actualHash }
    });
  }
  return bytes;
}

export function readAndVerifyManifest(staged) {
  let manifestBytes;
  let manifest;
  try {
    manifestBytes = readFileSync(staged.evidence.manifest_path);
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch (cause) {
    failImport(EVENT_IMPORT_ERRORS.MANIFEST_INVALID, "Import manifest is missing or malformed", {
      cause,
      importId: staged.import_id,
      evidence: { manifest_path: staged.evidence.manifest_path }
    });
  }
  const actualManifestHash = sha256Tagged(manifestBytes);
  if (actualManifestHash !== staged.evidence.manifest_hash) {
    failImport(EVENT_IMPORT_ERRORS.MANIFEST_INVALID, "Import manifest hash does not match the staged record", {
      importId: staged.import_id,
      evidence: { expected_hash: staged.evidence.manifest_hash, actual_hash: actualManifestHash }
    });
  }
  const expected = {
    import_id: staged.import_id,
    tenant_id: staged.tenant_id,
    source: staged.source,
    hash: staged.evidence_hash,
    format: staged.format,
    original_filename: staged.original_filename
  };
  for (const [field, value] of Object.entries(expected)) {
    if (manifest[field] !== value) {
      failImport(EVENT_IMPORT_ERRORS.MANIFEST_INVALID, `Import manifest ${field} does not match the staged record`, {
        importId: staged.import_id,
        evidence: { field, expected: value, actual: manifest[field] ?? null }
      });
    }
  }
  if (manifest.evidence?.evidence_id !== staged.evidence.evidence_id ||
      manifest.evidence?.chain_position !== staged.evidence.chain_position ||
      manifest.evidence?.previous_evidence_hash !== staged.evidence.previous_evidence_hash) {
    failImport(EVENT_IMPORT_ERRORS.MANIFEST_INVALID, "Import manifest evidence chain does not match the staged record", { importId: staged.import_id });
  }
  return manifest;
}
