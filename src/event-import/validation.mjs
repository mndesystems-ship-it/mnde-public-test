import { gunzipSync } from "node:zlib";

import { EVENT_IMPORT_ERRORS, failImport } from "./errors.mjs";
import { sha256Tagged } from "./util.mjs";

const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const UTF16_LE_BOM = Buffer.from([0xff, 0xfe]);
const UTF16_BE_BOM = Buffer.from([0xfe, 0xff]);

function startsWith(bytes, prefix) {
  return bytes.length >= prefix.length && bytes.subarray(0, prefix.length).equals(prefix);
}

export function detectCompression(bytes, filename = "") {
  if (startsWith(bytes, Buffer.from([0x1f, 0x8b]))) return "gzip";
  if (startsWith(bytes, Buffer.from([0x50, 0x4b, 0x03, 0x04]))) return "zip";
  if (bytes.length > 262 && bytes.subarray(257, 262).toString("ascii") === "ustar") return "tar";
  const lower = filename.toLowerCase();
  if (lower.endsWith(".gz") || lower.endsWith(".gzip")) return "gzip";
  if (lower.endsWith(".zip")) return "zip";
  if (lower.endsWith(".tar")) return "tar";
  return "none";
}

function decodeUtf16Be(bytes) {
  const body = bytes.subarray(2);
  if (body.length % 2 !== 0) failImport(EVENT_IMPORT_ERRORS.ENCODING_UNSUPPORTED, "UTF-16BE evidence has an incomplete code unit");
  const swapped = Buffer.allocUnsafe(body.length);
  for (let index = 0; index < body.length; index += 2) {
    swapped[index] = body[index + 1];
    swapped[index + 1] = body[index];
  }
  return swapped.toString("utf16le");
}

export function decodeEvidence(bytes) {
  if (startsWith(bytes, UTF8_BOM)) {
    return { encoding: "utf-8", text: new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(3)) };
  }
  if (startsWith(bytes, UTF16_LE_BOM)) return { encoding: "utf-16le", text: bytes.subarray(2).toString("utf16le") };
  if (startsWith(bytes, UTF16_BE_BOM)) return { encoding: "utf-16be", text: decodeUtf16Be(bytes) };
  if (bytes.every((byte) => byte < 0x80)) return { encoding: "ascii", text: bytes.toString("ascii") };
  try {
    return { encoding: "utf-8", text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch (cause) {
    failImport(EVENT_IMPORT_ERRORS.ENCODING_UNSUPPORTED, "Evidence is not valid UTF-8, UTF-16 with a BOM, or ASCII", { cause });
  }
}

export function inspectEvidence(input, options = {}) {
  const bytes = Buffer.isBuffer(input) ? Buffer.from(input) : Buffer.from(input);
  if (bytes.length === 0) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "Evidence must not be empty");
  const evidenceHash = sha256Tagged(bytes);
  if (options.expectedHash && options.expectedHash !== evidenceHash) {
    failImport(EVENT_IMPORT_ERRORS.HASH_MISMATCH, `Expected ${options.expectedHash}, received ${evidenceHash}`, {
      evidence: { expected_hash: options.expectedHash, actual_hash: evidenceHash }
    });
  }
  const compression = detectCompression(bytes, options.filename);
  let decodedBytes = bytes;
  if (compression === "gzip") {
    try {
      decodedBytes = gunzipSync(bytes);
    } catch (cause) {
      failImport(EVENT_IMPORT_ERRORS.PARSE, "Evidence is marked as gzip but cannot be decompressed", { cause });
    }
  } else if (compression !== "none") {
    failImport(EVENT_IMPORT_ERRORS.COMPRESSION_UNSUPPORTED, `${compression} archives must be extracted before import`, {
      evidence: { compression }
    });
  }
  const decoded = decodeEvidence(decodedBytes);
  return { bytes, evidenceHash, compression, decodedBytes, ...decoded };
}

// Staging is deliberately more permissive than processing: even evidence that
// cannot yet be decoded or decompressed must be preserved before quarantine.
export function inspectEvidenceForStaging(input, options = {}) {
  const bytes = Buffer.isBuffer(input) ? Buffer.from(input) : Buffer.from(input);
  if (bytes.length === 0) failImport(EVENT_IMPORT_ERRORS.INPUT_INVALID, "Evidence must not be empty");
  const evidenceHash = sha256Tagged(bytes);
  const hashStatus = options.expectedHash && options.expectedHash !== evidenceHash ? "MISMATCH" : "VERIFIED";
  const compression = detectCompression(bytes, options.filename);
  let encoding = "unknown";
  try {
    const decodedBytes = compression === "gzip" ? gunzipSync(bytes) : (compression === "none" ? bytes : null);
    if (decodedBytes !== null) encoding = decodeEvidence(decodedBytes).encoding;
  } catch {
    // Processing records the precise failure after immutable staging.
  }
  return { bytes, evidenceHash, compression, encoding, hashStatus };
}
