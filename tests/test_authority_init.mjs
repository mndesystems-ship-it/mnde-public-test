// Production trust-root bootstrap tests.
//
//   npm run test:authority-init
//
// Proves `init-production-authority` builds a real, usable trust root: the
// produced bundle verifies, loads through file-backed-production custody, passes
// the production trust-root pre-flight, and signs a receipt that verifies against
// the bundle. Guards (in-repo path, overwrite, demo authority id) fail closed.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { initProductionAuthority } from "../scripts/init-production-authority.mjs";
import { createFileBackedProductionCustody, verifyAgainstBundle } from "../src/custody/index.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { assertTrustRoot } from "../src/authority-signing/preflight.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NOW = "2026-06-14T00:00:00.000Z";

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

async function main() {
  console.log("MNDe production trust-root bootstrap\n");
  const base = mkdtempSync(join(tmpdir(), "mnde-authinit-"));
  try {
    const outDir = join(base, "root");
    const res = initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });

    await test("creates a verifiable trust root and reports the fingerprint", () => {
      assert.equal(res.ok, true, res.reason);
      assert.ok(/^[0-9a-f]{64}$/.test(res.rootFingerprint), "root fingerprint is a sha256 hex");
      const bundle = JSON.parse(readFileSync(res.paths.bundle, "utf8"));
      assert.equal(bundle.schema_version, "mnde.authority.bundle.v1");
      assert.equal(bundle.authority_id, "acme-prod");
      assert.equal(bundle.root_key.fingerprint, res.rootFingerprint);
      assert.ok(!JSON.stringify(bundle).includes("PRIVATE KEY"), "published bundle carries no private key");
    });

    await test("loads through file-backed-production custody and signs a verifiable receipt", () => {
      const provider = createFileBackedProductionCustody({
        MNDE_AUTHORITY_BUNDLE: res.paths.bundle,
        MNDE_RECEIPT_SIGNING_KEY: res.paths.receiptPrivate,
        MNDE_RECEIPT_KEY_ID: res.receiptKeyId
      });
      const payload = canonicalizeJson({ decision: "ALLOW" });
      const sig = provider.signReceipt(payload);
      const bundle = provider.getPublicBundle();
      assert.equal(verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, NOW, bundle).ok, true);
    });

    await test("passes the production trust-root pre-flight", async () => {
      const trust = await assertTrustRoot({
        MNDE_PROFILE: "production",
        MNDE_RECEIPT_SIGNING_MODE: "custody",
        MNDE_KEY_CUSTODY: "file-backed-production",
        MNDE_AUTHORITY_BUNDLE: res.paths.bundle,
        MNDE_RECEIPT_SIGNING_KEY: res.paths.receiptPrivate,
        MNDE_RECEIPT_KEY_ID: res.receiptKeyId
      }, { repoRoot });
      assert.equal(trust.ok, true, trust.detail || trust.reason_code);
      assert.equal(trust.profile, "production");
    });

    await test("refuses to overwrite an existing trust root", () => {
      const again = initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
      assert.equal(again.ok, false);
      assert.match(again.reason, /overwrite/);
    });

    await test("refuses to write inside the repository", () => {
      const r = initProductionAuthority({ outDir: join(repoRoot, "tmp-root"), authorityId: "acme-prod", now: NOW, repoRoot });
      assert.equal(r.ok, false);
      assert.match(r.reason, /inside the repository/);
    });

    await test("refuses a demo/local authority id", () => {
      const r = initProductionAuthority({ outDir: join(base, "root2"), authorityId: "mnde-local-demo", now: NOW });
      assert.equal(r.ok, false);
      assert.match(r.reason, /local.*demo|demo/);
    });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL authority-init tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS authority-init tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
