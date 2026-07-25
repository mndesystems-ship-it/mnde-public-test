#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = join(repoRoot, "bin", "mnde-sidecar.mjs");
const home = mkdtempSync(join(tmpdir(), "mnde-data-root-"));
const wrongRoot = mkdtempSync(join(tmpdir(), "mnde-wrong-root-"));

function runCli(command) {
  return spawnSync(process.execPath, [cliPath, command], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 30000,
    env: { ...process.env, MNDE_HOME: home }
  });
}

try {
  const init = runCli("init");
  assert.equal(init.status, 0, `init failed:\n${init.stdout}\n${init.stderr}`);
  const smoke = runCli("smoke");
  assert.equal(smoke.status, 0, `smoke failed:\n${smoke.stdout}\n${smoke.stderr}`);

  const receipt = JSON.parse(readFileSync(join(home, "first-receipt.json"), "utf8"));

  // Load signing/runtime modules while they point at the same data root used to
  // create the receipt, then remove the env override to prove explicit callers
  // can propagate an independently resolved root as well.
  process.env.MNDE_HOME = home;
  const engine = await import("../ram0na/engine.ts");
  const audit = await import("../audit/node_runtime.ts");
  delete process.env.MNDE_HOME;

  assert.equal(engine.verifyReceiptSignature(receipt, { dataRoot: home }), true, "explicit dataRoot must verify");
  assert.equal(engine.verifyReceiptPublicSignature(receipt, { dataRoot: home }), true, "public verification must use dataRoot");
  assert.equal(engine.verifyReceiptReplay(receipt, receipt, { dataRoot: home }).ok, true, "replay verification must use dataRoot");
  assert.equal(audit.verifySignedReceipt(receipt, { dataRoot: home }), true, "audit verification must use dataRoot");
  assert.equal(engine.verifyReceiptSignature(receipt, { dataRoot: wrongRoot }), false, "wrong root must fail closed");

  process.env.MNDE_HOME = home;
  assert.equal(engine.verifyReceiptSignature(receipt), true, "MNDE_HOME must remain the default verification root");
  delete process.env.MNDE_HOME;

  const receiptLog = join(home, "receipt-log.jsonl");
  writeFileSync(receiptLog, `${JSON.stringify(receipt)}\n`);
  const replay = audit.replayReceiptStore(receiptLog, { dataRoot: home });
  assert.equal(replay.total, 1);
  assert.ok(
    replay.exact_matches === 1 || replay.mismatches.every((item) => item.error !== "ERR_RECEIPT_SIGNATURE_INVALID"),
    "receipt-store replay must not reject the original because it looked under the code root"
  );

  console.log("PASS data-root receipt verification across verify, replay, and audit paths");
} finally {
  delete process.env.MNDE_HOME;
  rmSync(home, { recursive: true, force: true });
  rmSync(wrongRoot, { recursive: true, force: true });
}
