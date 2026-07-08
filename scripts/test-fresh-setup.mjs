#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, rmSync, renameSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "./bootstrap_dev_receipt_keys.mjs";
import { receiptSigningKeyStatus, signReceiptPayload } from "../shared/receipt-signing.ts";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const keyDir = join(repoRoot, "shared", "receipt_keys");
const localAuthorityDir = join(repoRoot, ".mnde-test", "authority");
const demoAuthorityManifest = join(repoRoot, "authority", "authority-manifest.json");
const validExampleReceipt = join(repoRoot, "examples", "receipts", "valid-receipt.json");
// Backup must be on the SAME device as the repo: the source dirs live under
// repoRoot, and renameSync across devices fails with EXDEV (e.g. CI runners where
// the checkout is on D: and os.tmpdir() is on C:). .mnde-test/ is gitignored.
const backupRoot = join(repoRoot, ".mnde-test", `fresh-setup-backup-${Date.now()}-${process.pid}`);
const keyBackup = join(backupRoot, "receipt_keys");
const localAuthorityBackup = join(backupRoot, "local_authority");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function moveIfExists(source, target) {
  if (existsSync(source)) {
    mkdirSync(backupRoot, { recursive: true });
    renameSync(source, target);
  }
}

function restore() {
  rmSync(keyDir, { recursive: true, force: true });
  rmSync(localAuthorityDir, { recursive: true, force: true });
  if (existsSync(keyBackup)) {
    mkdirSync(join(keyDir, ".."), { recursive: true });
    renameSync(keyBackup, keyDir);
  }
  if (existsSync(localAuthorityBackup)) {
    mkdirSync(join(localAuthorityDir, ".."), { recursive: true });
    renameSync(localAuthorityBackup, localAuthorityDir);
  }
  rmSync(backupRoot, { recursive: true, force: true });
}

try {
  const demoBefore = readFileSync(demoAuthorityManifest, "utf8");
  moveIfExists(keyDir, keyBackup);
  moveIfExists(localAuthorityDir, localAuthorityBackup);

  bootstrapReceiptKeys({ repoRoot });
  assert(existsSync(join(keyDir, "receipt_signing_private.pem")), "private signing key was not created");
  assert(existsSync(join(keyDir, "receipt_signing_public.pem")), "public signing key was not created");
  assert(existsSync(join(localAuthorityDir, "authority-manifest.json")), "local authority manifest was not created");
  assert(readFileSync(demoAuthorityManifest, "utf8") === demoBefore, "tester:init modified demo authority");

  assert(Boolean(signReceiptPayload("{\"ok\":true}")), "generated signing keys were not usable");

  assert(verificationPassed(verifyReceiptFile(validExampleReceipt)), "tester:init invalidated demo example receipt");

  rmSync(keyDir, { recursive: true, force: true });
  rmSync(localAuthorityDir, { recursive: true, force: true });
  const missingKey = receiptSigningKeyStatus();
  assert(!missingKey.ok, "missing signing keys should fail startup guard");
  assert(String(missingKey.reason).includes("ERR_RECEIPT_SIGNING_KEYS_MISSING"), "missing-key error was not clear");

  console.log("PASS fresh setup and missing-key handling tests");
} finally {
  restore();
}
