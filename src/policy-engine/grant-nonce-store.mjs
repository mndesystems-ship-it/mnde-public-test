// Single-use nonce store for authority grants (runtime replay protection).
//
// The policy engine is a PURE, deterministically-replayable function: it can
// verify that a grant is bound to this exact request (subject/tenant/tool/
// resource/request_id), but it cannot "consume" a nonce, because offline receipt
// verification re-runs the engine and must reproduce the same decision. Nonce
// single-use is therefore enforced HERE, at the stateful decision layer, and is
// deliberately NOT part of the receipt's deterministic replay.
//
// Mechanism mirrors sidecar/auth_authority.mjs: one file per nonce, created with
// O_EXCL ("wx") — a single atomic syscall on POSIX and Windows that either
// creates the file or fails EEXIST. Two workers racing on the same nonce can
// never both win. With no directory configured, an in-process Map is used
// (single-process dev/test). No third-party dependencies.

import { mkdirSync, openSync, closeSync, writeSync } from "node:fs";
import { join } from "node:path";

// URL-safe so the nonce can be used directly as a filename (no path traversal).
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

const memory = new Map(); // nonce -> expiresAt (ms); used only when no dir is set

// Reserve a grant nonce. Returns { ok: true } exactly once per nonce; every
// later attempt returns { ok: false, reason: "AUTHORITY_NONCE_REUSED" }. A
// malformed nonce or an unwritable store fails closed with a distinct reason.
export function reserveGrantNonce(nonce, { dir = null, now = Date.now(), ttlMs = DEFAULT_TTL_MS } = {}) {
  if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) return { ok: false, reason: "AUTHORITY_NONCE_INVALID" };
  const expiresAt = now + ttlMs;

  if (!dir) {
    for (const [key, exp] of memory) if (exp <= now) memory.delete(key);
    if (memory.has(nonce)) return { ok: false, reason: "AUTHORITY_NONCE_REUSED" };
    memory.set(nonce, expiresAt);
    return { ok: true };
  }

  try {
    mkdirSync(dir, { recursive: true });
  } catch {
    return { ok: false, reason: "AUTHORITY_NONCE_STORE_UNAVAILABLE" };
  }
  let fd;
  try {
    fd = openSync(join(dir, nonce), "wx"); // O_WRONLY | O_CREAT | O_EXCL
  } catch {
    // EEXIST (already reserved by any process) or unwritable → refuse.
    return { ok: false, reason: "AUTHORITY_NONCE_REUSED" };
  }
  try {
    writeSync(fd, String(expiresAt));
  } finally {
    closeSync(fd);
  }
  return { ok: true };
}

export function _resetGrantNonceMemoryForTest() {
  memory.clear();
}
