#!/usr/bin/env node
// Fast release-identity contract (runs in the default suite).
//
// Detects version drift between the authoritative source (package.json) and the
// release-identity module every CLI + the sidecar report from, and proves the
// module reports truthfully WITHOUT inspecting Git at runtime. The heavy
// end-to-end proof (real pack -> install -> run outside the repo -> checksums ->
// fail-closed) lives in tests/test_release_truth.mjs behind `npm run
// release:verify`, kept out of the default suite so ordinary CI stays cheap.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { getReleaseIdentity, formatReleaseIdentity, PRODUCT_NAME, RELEASE_IDENTITY_SCHEMA } from "../src/release/identity.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`[FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// REL-01 (core): the module's version IS package.json's version — one source.
test("release identity version equals package.json version", () => {
  const id = getReleaseIdentity();
  assert.equal(id.version, pkg.version, "identity.version must equal package.json version");
  assert.equal(id.package, pkg.name, "identity.package must equal package.json name");
});

test("release identity carries the product name and schema", () => {
  const id = getReleaseIdentity();
  assert.equal(id.product, PRODUCT_NAME);
  assert.equal(id.product, "MNDe");
  assert.equal(id.schema, RELEASE_IDENTITY_SCHEMA);
  assert.equal(id.schema, "mnde.release-identity.v1");
});

// No Git at runtime: a source checkout has no embedded build-info.json, so the
// module must report source-checkout truthfully (commit null) rather than
// shelling out to Git or fabricating a commit.
test("source checkout reports source-checkout without inspecting Git", () => {
  const id = getReleaseIdentity();
  // This test file only ever runs from a source checkout (dist/ is never the
  // test root), so the embedded commit must be absent and the source honest.
  assert.equal(id.commit, null, "source checkout must not carry an embedded commit");
  assert.equal(id.source, "source-checkout");
  assert.equal(id.artifact_format, "source-checkout");
  assert.equal(typeof id.node, "string");
});

test("formatReleaseIdentity renders the version and product", () => {
  const text = formatReleaseIdentity();
  assert.match(text, /MNDe/);
  assert.match(text, new RegExp(pkg.version.replace(/[.]/g, "\\.")));
});

// The `mnde` and `mnde-sidecar` source entry points must both surface the same
// version through their `version` command — a cheap cross-bin drift check that
// does not require packing.
test("both CLI entry points report the package version via `version`", () => {
  for (const bin of ["bin/mnde.mjs", "bin/mnde-sidecar.mjs"]) {
    const out = execFileSync(process.execPath, [join(repoRoot, bin), "version"], { encoding: "utf8" });
    assert.match(out, new RegExp(`MNDe ${pkg.version.replace(/[.]/g, "\\.")}`), `${bin} version output must name the package version`);
  }
});

test("`mnde version --json` emits the machine-readable identity", () => {
  const out = execFileSync(process.execPath, [join(repoRoot, "bin/mnde.mjs"), "version", "--json"], { encoding: "utf8" });
  const parsed = JSON.parse(out);
  assert.equal(parsed.version, pkg.version);
  assert.equal(parsed.product, "MNDe");
  assert.equal(parsed.schema, "mnde.release-identity.v1");
});

if (failures > 0) {
  console.error(`\nFAIL release identity contract (${failures} failing)`);
  process.exit(1);
}
console.log("\nPASS release identity contract");
