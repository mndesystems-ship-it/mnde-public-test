#!/usr/bin/env node
// Hostile tests for bootstrapReceiptKeys' keypair-recovery behavior.
//
// An independent review found that a half-missing keypair (e.g. the public
// key file deleted, private key intact) was silently "repaired" by
// regenerating BOTH files — discarding the still-valid, already-in-use
// private key with no warning, permanently invalidating every receipt
// previously signed with it. This suite proves the fixed behavior: only a
// fully-absent pair is generated; anything else (half-missing, corrupt,
// mismatched) fails closed and touches nothing.
//
// Every scenario runs against its own throwaway MNDE_HOME (mkdtempSync), so
// nothing here touches the real repo's shared/receipt_keys/.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bootstrapReceiptKeys, KeypairFailClosedError } from "../scripts/bootstrap_dev_receipt_keys.mjs";

function fresh() {
  return mkdtempSync(join(tmpdir(), "keypair-recovery-"));
}
function paths(dir) {
  return {
    privateKeyPath: join(dir, "shared", "receipt_keys", "receipt_signing_private.pem"),
    publicKeyPath: join(dir, "shared", "receipt_keys", "receipt_signing_public.pem")
  };
}

const results = [];
function scenario(name, fn) {
  const dir = fresh();
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

scenario("fresh empty MNDE_HOME still initializes successfully", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  const result = bootstrapReceiptKeys({ repoRoot: dir });
  assert.equal(result.status, "created");
  assert.ok(existsSync(privateKeyPath), "private key must be created");
  assert.ok(existsSync(publicKeyPath), "public key must be created");
});

scenario("existing valid pair remains unchanged (private and public bytes identical)", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  bootstrapReceiptKeys({ repoRoot: dir });
  const privBefore = readFileSync(privateKeyPath, "utf8");
  const pubBefore = readFileSync(publicKeyPath, "utf8");
  const result = bootstrapReceiptKeys({ repoRoot: dir });
  assert.equal(result.status, "exists");
  assert.equal(readFileSync(privateKeyPath, "utf8"), privBefore, "private key must not change");
  assert.equal(readFileSync(publicKeyPath, "utf8"), pubBefore, "public key must not change");
});

scenario("private present, public missing: fails closed, private key bytes unchanged, no public key written", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  bootstrapReceiptKeys({ repoRoot: dir });
  const privBefore = readFileSync(privateKeyPath, "utf8");
  unlinkSync(publicKeyPath);
  assert.throws(() => bootstrapReceiptKeys({ repoRoot: dir }), KeypairFailClosedError);
  assert.equal(readFileSync(privateKeyPath, "utf8"), privBefore, "private key must remain byte-identical");
  assert.ok(!existsSync(publicKeyPath), "no replacement public key may be written");
});

scenario("public present, private missing: fails closed, public key bytes unchanged, no private key written", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  bootstrapReceiptKeys({ repoRoot: dir });
  const pubBefore = readFileSync(publicKeyPath, "utf8");
  unlinkSync(privateKeyPath);
  assert.throws(() => bootstrapReceiptKeys({ repoRoot: dir }), KeypairFailClosedError);
  assert.equal(readFileSync(publicKeyPath, "utf8"), pubBefore, "public key must remain byte-identical");
  assert.ok(!existsSync(privateKeyPath), "no replacement private key may be written");
});

scenario("corrupt private key file fails closed and touches nothing", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  bootstrapReceiptKeys({ repoRoot: dir });
  const pubBefore = readFileSync(publicKeyPath, "utf8");
  writeFileSync(privateKeyPath, "not a real key at all");
  assert.throws(() => bootstrapReceiptKeys({ repoRoot: dir }), KeypairFailClosedError);
  assert.equal(readFileSync(privateKeyPath, "utf8"), "not a real key at all", "corrupt file must not be silently replaced");
  assert.equal(readFileSync(publicKeyPath, "utf8"), pubBefore, "public key must remain untouched");
});

scenario("corrupt public key file fails closed and touches nothing", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  bootstrapReceiptKeys({ repoRoot: dir });
  const privBefore = readFileSync(privateKeyPath, "utf8");
  writeFileSync(publicKeyPath, "not a real key at all");
  assert.throws(() => bootstrapReceiptKeys({ repoRoot: dir }), KeypairFailClosedError);
  assert.equal(readFileSync(publicKeyPath, "utf8"), "not a real key at all", "corrupt file must not be silently replaced");
  assert.equal(readFileSync(privateKeyPath, "utf8"), privBefore, "private key must remain untouched");
});

scenario("mismatched (individually valid, non-corresponding) pair fails closed and touches nothing", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  bootstrapReceiptKeys({ repoRoot: dir });
  const privBefore = readFileSync(privateKeyPath, "utf8");
  const unrelated = generateKeyPairSync("ed25519");
  const foreignPublicPem = unrelated.publicKey.export({ type: "spki", format: "pem" });
  writeFileSync(publicKeyPath, foreignPublicPem);
  assert.throws(() => bootstrapReceiptKeys({ repoRoot: dir }), KeypairFailClosedError);
  assert.equal(readFileSync(privateKeyPath, "utf8"), privBefore, "private key must remain untouched");
  assert.equal(readFileSync(publicKeyPath, "utf8"), foreignPublicPem, "mismatched public key must not be silently replaced");
});

scenario("force:true intentionally overrides and regenerates both files", (dir) => {
  const { privateKeyPath, publicKeyPath } = paths(dir);
  bootstrapReceiptKeys({ repoRoot: dir });
  const privBefore = readFileSync(privateKeyPath, "utf8");
  const result = bootstrapReceiptKeys({ repoRoot: dir, force: true });
  assert.equal(result.status, "created");
  assert.notEqual(readFileSync(privateKeyPath, "utf8"), privBefore, "force:true is an explicit, deliberate override — it must actually rotate the key");
});

const failed = results.filter((r) => !r.ok);
if (failed.length > 0) {
  console.error(`\nFAIL partial keypair recovery tests (${results.length - failed.length}/${results.length} passed)`);
  process.exit(1);
}
console.log(`\nPASS partial keypair recovery tests (${results.length}/${results.length})`);
