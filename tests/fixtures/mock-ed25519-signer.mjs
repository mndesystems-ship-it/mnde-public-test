#!/usr/bin/env node
// Test fixture: a stand-in external signer. Reads canonical bytes on stdin and
// writes a hex Ed25519 signature on stdout, per the external-signer contract.
// Behavior is driven by env so one fixture covers the whole failure matrix:
//
//   MOCK_SIGNER_KEY   path to an Ed25519 private key (PEM) used to sign
//   MOCK_SIGNER_MODE  ok (default) | exit1 | timeout | badhex | short
//
// This is a TEST stand-in for a real PKCS#11/HSM signing wrapper — not shipped.

import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";

const mode = process.env.MOCK_SIGNER_MODE || "ok";
const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const bytes = Buffer.concat(chunks);
  if (mode === "exit1") { process.stderr.write("mock signer: simulated failure\n"); process.exit(1); }
  if (mode === "timeout") { setTimeout(() => {}, 60_000); return; } // never respond
  if (mode === "badhex") { process.stdout.write("not-valid-hex!!\n"); process.exit(0); }
  if (mode === "short") { process.stdout.write("abcd\n"); process.exit(0); }
  try {
    const priv = createPrivateKey(readFileSync(process.env.MOCK_SIGNER_KEY, "utf8"));
    process.stdout.write(sign(null, bytes, priv).toString("hex") + "\n");
    process.exit(0);
  } catch (error) {
    process.stderr.write(`mock signer: ${error.message}\n`);
    process.exit(2);
  }
});
