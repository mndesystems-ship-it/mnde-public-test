// Content-based private-key detector.
//
// Replaces an earlier extension-based check (`file.endsWith(".pem")`) that an
// independent review reproduced bypassing four ways: a private key saved with
// a .key extension, no extension at all, a misleading nested filename, and a
// key embedded inside an otherwise-ordinary JSON file — every case shipped
// into the built package undetected, because the scan never looked at any
// file that wasn't literally named *.pem.
//
// This scans file CONTENT, not file names, so none of those bypasses apply:
// a private key is a private key regardless of what the file is called, how
// deep it's nested, or what other content surrounds it. A key pasted inside
// a JSON string still contains its literal PEM header/footer text unescaped
// (JSON only escapes the internal newlines, not the header/footer strings
// themselves), so the same substring search finds it there too.
//
// SCOPE — what this actually detects (do not claim broader coverage):
//   Standard PEM private-key headers only:
//     BEGIN PRIVATE KEY            (PKCS8, unencrypted)
//     BEGIN RSA PRIVATE KEY        (PKCS1)
//     BEGIN EC PRIVATE KEY
//     BEGIN OPENSSH PRIVATE KEY
//     BEGIN ENCRYPTED PRIVATE KEY  (PKCS8, encrypted)
//   It does NOT detect: raw/non-PEM key material with no textual marker
//   (e.g. a bare base64 or binary blob with no header), non-PEM formats
//   (e.g. JWK, PuTTY .ppk), or secrets that aren't private keys at all
//   (API tokens, passwords) — those are out of scope for this guard.
//
// Files are read as raw bytes and decoded latin1 (one byte -> one char)
// rather than utf8: this guarantees the ASCII marker text is found correctly
// even inside content that isn't valid UTF-8 (e.g. genuine binary), with no
// risk of a multi-byte UTF-8 decode shifting or corrupting a byte-for-byte
// match. Public keys ("BEGIN PUBLIC KEY") and ordinary prose that happens to
// contain the word "private" are deliberately NOT matched — this is scoped
// to the specific marker phrases above, not the word "private" in isolation.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

export const PRIVATE_KEY_MARKER = /BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY/;

// Returns the list of absolute file paths under `rootDir` whose content
// matches PRIVATE_KEY_MARKER. Empty array means clean. Pure function: no
// process.exit, no logging — callers decide what "found something" means.
export function scanForPrivateKeyMaterial(rootDir) {
  const offenders = [];
  function walk(dir) {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        if (entry === "node_modules" || entry === "__pycache__" || entry === ".git") continue;
        walk(full);
      } else {
        const content = readFileSync(full).toString("latin1");
        if (PRIVATE_KEY_MARKER.test(content)) offenders.push(full);
      }
    }
  }
  walk(rootDir);
  return offenders;
}
