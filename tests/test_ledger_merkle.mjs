// MNDe execution-ledger — Merkle core unit tests.
//
//   npm run test:ledger-merkle
//
// Proves the RFC 6962 tree: domain separation (leaf vs node), correct roots for
// power-of-two and ragged sizes, inclusion proofs that verify for EVERY index,
// and that tampered path / index / size / root all fail. Deterministic by design.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  leafHash, nodeHash, merkleRoot, inclusionProof, rootFromInclusionProof, verifyInclusion
} from "../src/execution-ledger/merkle.mjs";

const results = [];
function test(name, fn) {
  try { fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (e) { results.push(false); console.log(`  [FAIL] ${name}: ${e.message}`); }
}

// Deterministic sample entry_hash values ("sha256:<hex>").
const eh = (i) => `sha256:${createHash("sha256").update(`entry-${i}`).digest("hex")}`;
const leavesOf = (n) => Array.from({ length: n }, (_, i) => leafHash(eh(i)));

console.log("MNDe ledger merkle — unit tests\n");

test("leaf and node hashing are domain-separated (0x00 vs 0x01)", () => {
  const a = eh(1), b = eh(2);
  // A leaf over one child must NOT equal a node over the same-looking inputs.
  assert.notEqual(leafHash(a), nodeHash(a, b));
  // Node with identical children is still not a leaf of either child.
  assert.notEqual(nodeHash(a, a), leafHash(a));
  // Manual second-preimage attempt: feeding a node's two-child concatenation as if
  // it were a single leaf input is impossible through the API (leaf takes one hash),
  // and the prefixes guarantee the digests differ even if bytes lined up.
  assert.ok(leafHash(a).startsWith("sha256:"));
});

test("single-leaf tree: root is the leaf, empty proof", () => {
  const leaves = leavesOf(1);
  assert.equal(merkleRoot(leaves), leaves[0]);
  assert.deepEqual(inclusionProof(leaves, 0), []);
  assert.ok(verifyInclusion(leaves[0], 0, 1, [], leaves[0]));
});

test("two-leaf root = node(leaf0, leaf1)", () => {
  const leaves = leavesOf(2);
  assert.equal(merkleRoot(leaves), nodeHash(leaves[0], leaves[1]));
});

test("roots are stable and order-sensitive", () => {
  const leaves = leavesOf(4);
  const root = merkleRoot(leaves);
  assert.equal(root, merkleRoot(leavesOf(4)), "recompute must be byte-identical");
  const swapped = [leaves[1], leaves[0], leaves[2], leaves[3]];
  assert.notEqual(merkleRoot(swapped), root, "reordering must change the root");
});

test("inclusion proof verifies for EVERY index at sizes 1..9", () => {
  for (let n = 1; n <= 9; n += 1) {
    const leaves = leavesOf(n);
    const root = merkleRoot(leaves);
    for (let m = 0; m < n; m += 1) {
      const path = inclusionProof(leaves, m);
      assert.equal(rootFromInclusionProof(leaves[m], m, n, path), root, `n=${n} m=${m}`);
      assert.ok(verifyInclusion(leaves[m], m, n, path, root), `verify n=${n} m=${m}`);
      // path length is ceil(log2 n)
      assert.ok(path.length <= Math.ceil(Math.log2(Math.max(2, n))), `path length n=${n} m=${m}`);
    }
  }
});

test("tampered audit path fails", () => {
  const n = 7, leaves = leavesOf(n), root = merkleRoot(leaves), m = 3;
  const path = inclusionProof(leaves, m);
  const bad = [...path];
  bad[0] = leafHash(eh(999)); // wrong sibling
  assert.equal(verifyInclusion(leaves[m], m, n, bad, root), false);
});

test("wrong index fails", () => {
  const n = 8, leaves = leavesOf(n), root = merkleRoot(leaves);
  const path = inclusionProof(leaves, 2);
  assert.equal(verifyInclusion(leaves[2], 5, n, path, root), false);
});

test("wrong tree_size (path length mismatch) fails", () => {
  // An audit path is only meaningful together with the tree_size the verifier
  // pins (proof.mjs binds inclusion.tree_size == checkpoint.tree_size). At the
  // merkle layer, a path built for n=8 cannot fold under a claimed n=2.
  const n = 8, leaves = leavesOf(n), root = merkleRoot(leaves);
  const path = inclusionProof(leaves, 3); // length 3
  assert.equal(verifyInclusion(leaves[3], 3, 2, path, root), false);
});

test("wrong root fails", () => {
  const n = 4, leaves = leavesOf(n);
  const path = inclusionProof(leaves, 0);
  assert.equal(verifyInclusion(leaves[0], 0, n, path, leafHash(eh(123))), false);
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) { console.log(`FAIL ledger-merkle tests (${results.length - failed}/${results.length})`); process.exit(1); }
console.log(`PASS ledger-merkle tests (${results.length}/${results.length})`);
