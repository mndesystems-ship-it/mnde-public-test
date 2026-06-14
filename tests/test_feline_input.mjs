// Tests for the cosmetic feline-input easter egg.
//
//   npm run test:feline
//
// Verifies the detector does not fire on normal text/paths/URLs/identifiers, and
// that the rate-limited watcher gates correctly. The easter egg is cosmetic only
// and has no connection to authority, policy, receipts, or verification.

import assert from "node:assert/strict";

import { looksLikeKeyboardSpam, createFelineWatcher } from "../cosmetic/feline-input.mjs";

const results = [];
function check(name, condition) {
  results.push(Boolean(condition));
  console.log(`  [${condition ? "PASS" : "FAIL"}] ${name}`);
}

// Should detect obvious keyboard spam.
const spam = [
  "aaaaaaaaaa",
  "jjjjjjjjjjjj",
  "asdasdasdasd",
  "jkjkjkjkjk",
  "////////////////",
  ";lkj;lkj;lkjasdf!@#$%^&*()_+qwer",
  "kjghdfkjghdfkjghxcvbnm,./';lkjh"
];
// Should NOT detect normal input.
const normal = [
  "delete_backups",
  "read_status",
  "Please review the policy before deploying.",
  "C:\\Users\\Shadow\\Downloads\\INsol",
  "https://github.com/mndesystems-ship-it/mnde-public-test",
  "hello world this is a normal sentence",
  "supercalifragilisticexpialidocious",
  ""
];

for (const s of spam) check(`detects spam: ${JSON.stringify(s).slice(0, 30)}`, looksLikeKeyboardSpam(s) === true);
for (const s of normal) check(`ignores normal: ${JSON.stringify(s).slice(0, 30)}`, looksLikeKeyboardSpam(s) === false);

// Watcher rate-limits.
const watcher = createFelineWatcher({ minIntervalMs: 999_999, maxPerSession: 1 });
check("watcher returns a message on first spam", typeof watcher.consider("aaaaaaaaaa") === "string");
check("watcher rate-limits the second spam", watcher.consider("jjjjjjjjjj") === null);
check("watcher ignores normal text", createFelineWatcher().consider("read_status") === null);

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL feline-input tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS feline-input tests (${results.length}/${results.length})`);
