#!/usr/bin/env node
// Hostile tests for the content-based private-key detector
// (build/lib/private-key-scan.mjs), added after an independent review
// reproduced four ways to bypass the previous extension-based check
// (file.endsWith(".pem")): a private key saved as .key, with no extension,
// nested under a misleading filename, and embedded inside an ordinary JSON
// file — none of which end in .pem, so none were ever scanned. Each scenario
// here runs against a throwaway scratch directory (never the real repo), so
// nothing here can leak real key material into the working tree.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scanForPrivateKeyMaterial } from "../build/lib/private-key-scan.mjs";

const { privateKey } = generateKeyPairSync("ed25519");
const PRIVATE_PEM = privateKey.export({ type: "pkcs8", format: "pem" });
const { publicKey: unrelatedPublicKey } = generateKeyPairSync("ed25519");
const PUBLIC_PEM = unrelatedPublicKey.export({ type: "spki", format: "pem" });

// Literal marker strings for the four PEM variants not covered by a plain
// generateKeyPairSync export (Node doesn't emit these formats directly) —
// the scanner only looks at marker text, so a synthetic body is sufficient.
const RSA_PEM = "-----BEGIN RSA PRIVATE KEY-----\nZmFrZSBib2R5IGZvciB0ZXN0aW5nIG9ubHk=\n-----END RSA PRIVATE KEY-----\n";
const EC_PEM = "-----BEGIN EC PRIVATE KEY-----\nZmFrZSBib2R5IGZvciB0ZXN0aW5nIG9ubHk=\n-----END EC PRIVATE KEY-----\n";
const OPENSSH_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZSBib2R5IGZvciB0ZXN0aW5nIG9ubHk=\n-----END OPENSSH PRIVATE KEY-----\n";
const ENCRYPTED_PEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZmFrZSBib2R5IGZvciB0ZXN0aW5nIG9ubHk=\n-----END ENCRYPTED PRIVATE KEY-----\n";

const results = [];
function scenario(name, fn) {
  const dir = mkdtempSync(join(tmpdir(), "pkscan-"));
  try {
    fn(dir);
    results.push({ name, ok: true });
    console.log(`  ok - ${name}`);
  } catch (error) {
    results.push({ name, ok: false, error });
    console.log(`FAIL - ${name}: ${error.message}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function assertCaught(dir, relPath) {
  const offenders = scanForPrivateKeyMaterial(dir);
  const abs = join(dir, relPath);
  assert.ok(offenders.includes(abs), `expected ${relPath} to be caught; offenders: ${JSON.stringify(offenders)}`);
}
function assertAllowed(dir) {
  const offenders = scanForPrivateKeyMaterial(dir);
  assert.deepEqual(offenders, [], `expected no offenders; got: ${JSON.stringify(offenders)}`);
}

scenario(".pem extension (PKCS8) is caught", (dir) => {
  writeFileSync(join(dir, "leaked.pem"), PRIVATE_PEM);
  assertCaught(dir, "leaked.pem");
});

scenario(".key extension (RSA) is caught", (dir) => {
  writeFileSync(join(dir, "leaked.key"), RSA_PEM);
  assertCaught(dir, "leaked.key");
});

scenario("no extension at all (EC) is caught", (dir) => {
  writeFileSync(join(dir, "id_ed25519"), EC_PEM);
  assertCaught(dir, "id_ed25519");
});

scenario("misleading filename (OPENSSH) is caught", (dir) => {
  writeFileSync(join(dir, "readme-notes.txt"), OPENSSH_PEM);
  assertCaught(dir, "readme-notes.txt");
});

scenario("nested file, several directories deep (ENCRYPTED) is caught", (dir) => {
  mkdirSync(join(dir, "a", "b", "c"), { recursive: true });
  writeFileSync(join(dir, "a", "b", "c", "backup.dat"), ENCRYPTED_PEM);
  assertCaught(dir, join("a", "b", "c", "backup.dat"));
});

scenario("private key embedded inside a JSON file is caught", (dir) => {
  const content = JSON.stringify({ note: "totally normal config", accidentallyIncluded: PRIVATE_PEM }, null, 2);
  writeFileSync(join(dir, "config.json"), content);
  assertCaught(dir, "config.json");
});

scenario("private key embedded inside ordinary prose text is caught", (dir) => {
  const content = `Meeting notes:\n- remember to rotate creds\n- backup: ${PRIVATE_PEM}\n- ping infra team\n`;
  writeFileSync(join(dir, "notes.txt"), content);
  assertCaught(dir, "notes.txt");
});

scenario("a public key file alone must remain allowed", (dir) => {
  writeFileSync(join(dir, "receipt_signing_public.pem"), PUBLIC_PEM);
  assertAllowed(dir);
});

scenario('harmless text containing the word "private" must remain allowed', (dir) => {
  writeFileSync(join(dir, "notes.txt"), "This is a private matter, please keep it confidential between us.\n");
  assertAllowed(dir);
});

const failed = results.filter((r) => !r.ok);
if (failed.length > 0) {
  console.error(`\nFAIL private key scan hostile tests (${results.length - failed.length}/${results.length} passed)`);
  process.exit(1);
}
console.log(`\nPASS private key scan hostile tests (${results.length}/${results.length})`);
