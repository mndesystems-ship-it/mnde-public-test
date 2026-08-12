// Production trust-gate hardening — hostile regression suite (F1–F4).
//
//   npm run test:prod-trust-gate-hostile
//
// One command proves all four hostile findings stay closed:
//   F1  explicit-profile enforcement — a missing MNDE_PROFILE is NOT local; the
//       real runtime refuses to start before serving anything.
//   F2  exclusive authority writes    — init never overwrites an existing trust
//       artifact and leaves no partial ceremony behind.
//   F3  cryptographic init probe       — init accepts a signing identity only
//       after its signature verifies against the PUBLISHED public key.
//   F4  canonical containment          — init refuses repo-contained destinations
//       after real path resolution (casing / traversal / symlink / junction).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { parseRuntimeProfile } from "../shared/runtime-profile.mjs";
import { assertTrustRoot } from "../src/authority-signing/preflight.mjs";
import { canonicalizeForContainment, isRepoContained } from "../src/authority-signing/repo-containment.mjs";
import { initProductionAuthority } from "../scripts/init-production-authority.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair, signCanonical, verifyAgainstBundle } from "../src/custody/index.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NOW = "2026-06-14T00:00:00.000Z";
const isWindows = process.platform === "win32";

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}
function skip(name, why) {
  console.log(`  [SKIP] ${name} (${why})`);
}

// Allocate a guaranteed-free ephemeral port so the real-runtime spawn tests never
// collide with a lingering sidecar from another suite/worktree (which would make a
// "did it bind?" check falsely see someone else's server).
function getFreePort() {
  return new Promise((res, rej) => {
    const srv = createServer();
    srv.once("error", rej);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => res(port));
    });
  });
}

// Spawn the REAL sidecar runtime with a given env and resolve with its outcome.
function spawnRuntime(env, port) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, ["mnde-local-sidecar.mjs"], {
      cwd: repoRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
    let stderr = "";
    let stdout = "";
    child.stdout?.on("data", (c) => (stdout += c.toString()));
    child.stderr?.on("data", (c) => (stderr += c.toString()));
    const killer = setTimeout(() => {
      try { child.kill("SIGKILL"); } catch { /* gone */ }
    }, 30000);
    // Resolve on "close" (all stdio drained), NOT "exit": a fast-refusing child
    // can fire "exit" before its stderr is fully read, which would race the
    // reason-code assertions to an empty buffer.
    child.on("close", async (code) => {
      clearTimeout(killer);
      let bound = false;
      try { await fetch(`http://127.0.0.1:${port}/readyz`); bound = true; } catch { bound = false; }
      resolvePromise({ code, stderr, stdout, bound });
    });
  });
}

function buildBundleWith(role, keyId, publicPem, now) {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const roleKeys = [{ keyId, publicPem, validFrom: now, validUntil: "2027-06-14T00:00:00.000Z" }];
  return buildAuthorityBundle({
    authorityId: "hostile-prod",
    issuedAt: now,
    notAfter: "2026-09-12T00:00:00.000Z",
    root,
    receiptKeys: role === "receipt" ? roleKeys : [],
    ledgerKeys: role === "ledger" ? roleKeys : [],
    activationKeys: role === "activation" ? roleKeys : [],
    revocation: []
  });
}

async function main() {
  console.log("MNDe production trust-gate hardening — hostile suite\n");
  const base = mkdtempSync(join(tmpdir(), "mnde-ptgh-"));

  // ─────────────────────────────────────────────────────────────────────────
  console.log("F1 explicit-profile enforcement");
  // ─────────────────────────────────────────────────────────────────────────

  await test("F1: parser — unset/empty/whitespace => ERR_PROFILE_REQUIRED (never local)", () => {
    for (const raw of [undefined, null, "", "   ", "\t\n"]) {
      const r = parseRuntimeProfile(raw);
      assert.equal(r.ok, false, `raw=${JSON.stringify(raw)} must fail`);
      assert.equal(r.reason_code, "ERR_PROFILE_REQUIRED");
      assert.notEqual(r.profile, "local", "a missing profile must never resolve to local");
    }
  });

  await test("F1: parser — typo/garbage => ERR_UNKNOWN_PROFILE", () => {
    for (const raw of ["prod", "production leak", "garbage", "prod-east", "LOCALE"]) {
      const r = parseRuntimeProfile(raw);
      assert.equal(r.ok, false, `raw=${raw} must fail`);
      assert.equal(r.reason_code, "ERR_UNKNOWN_PROFILE");
    }
  });

  await test("F1: parser — canonical names accepted; casing intentionally case-insensitive", () => {
    assert.deepEqual(parseRuntimeProfile("production"), { ok: true, profile: "production" });
    assert.deepEqual(parseRuntimeProfile("local"), { ok: true, profile: "local" });
    // Case-insensitivity is the intentional, documented behavior (not a silent degrade).
    assert.equal(parseRuntimeProfile("Production").ok, true);
    assert.equal(parseRuntimeProfile("Production").profile, "production");
    assert.equal(parseRuntimeProfile("LOCAL").profile, "local");
  });

  await test("F1: assertTrustRoot (load-bearing caller) refuses a missing profile, selects no authority", async () => {
    const r = await assertTrustRoot({});
    assert.equal(r.ok, false);
    assert.equal(r.reason_code, "ERR_PROFILE_REQUIRED");
    assert.ok(!r.profile, "no profile is selected on refusal");
    assert.ok(!("authority_id" in r), "no signing authority is chosen when the profile is missing");
  });

  await test("F1: explicit local still works at the caller", async () => {
    const r = await assertTrustRoot({ MNDE_PROFILE: "local" });
    assert.equal(r.ok, true);
    assert.equal(r.profile, "local");
  });

  // The real sidecar validates dev receipt keys BEFORE the trust-root gate; on a
  // fresh clone they don't exist yet, so it would refuse for a different reason.
  // Bootstrap them (idempotent, gitignored) so these tests deterministically reach
  // — and prove — the profile gate itself. Mirrors the sidecar test harness.
  bootstrapReceiptKeys({ repoRoot });

  await test("F1: REAL runtime — missing MNDE_PROFILE exits non-zero, never binds a port", async () => {
    const port = await getFreePort();
    const env = { ...process.env, MNDE_BIND_PORT: String(port), MNDE_RECEIPT_LOG: join(base, "f1-r.jsonl") };
    delete env.MNDE_PROFILE;
    const out = await spawnRuntime(env, port);
    assert.notEqual(out.code, 0, `expected non-zero exit, got ${out.code}\n${out.stderr}`);
    assert.match(out.stderr, /ERR_PROFILE_REQUIRED/, `expected ERR_PROFILE_REQUIRED in stderr:\n${out.stderr}`);
    assert.equal(out.bound, false, "server must never bind when the profile is missing");
  });

  await test("F1: REAL runtime — explicit production without custody refuses (not local fallback)", async () => {
    const port = await getFreePort();
    const env = { ...process.env, MNDE_PROFILE: "production", MNDE_BIND_PORT: String(port), MNDE_RECEIPT_LOG: join(base, "f1-p.jsonl") };
    const out = await spawnRuntime(env, port);
    assert.notEqual(out.code, 0, `expected refusal, got ${out.code}\n${out.stderr}`);
    assert.match(out.stderr, /ERR_TRUST_ROOT|refused to start|custody/i);
    assert.equal(out.bound, false);
  });

  // ─────────────────────────────────────────────────────────────────────────
  console.log("F2 exclusive authority writes");
  // ─────────────────────────────────────────────────────────────────────────

  await test("F2: clean init succeeds and writes all artifacts", async () => {
    const outDir = join(base, "f2-clean");
    const r = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
    assert.equal(r.ok, true, r.reason);
    for (const p of Object.values(r.paths)) assert.ok(existsSync(p), `${p} written`);
  });

  await test("F2: an existing trust artifact is never overwritten (byte-for-byte preserved)", async () => {
    const outDir = join(base, "f2-collision");
    const first = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
    assert.equal(first.ok, true, first.reason);
    const rootBytes = readFileSync(first.paths.rootPrivate);
    const bundleBytes = readFileSync(first.paths.bundle);
    // Re-run into the same directory: must refuse without touching a thing.
    const second = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
    assert.equal(second.ok, false);
    assert.match(second.reason, /overwrite/i);
    assert.ok(readFileSync(first.paths.rootPrivate).equals(rootBytes), "root key unchanged");
    assert.ok(readFileSync(first.paths.bundle).equals(bundleBytes), "bundle unchanged");
  });

  await test("F2: a pre-existing collision leaves NO partial ceremony (no other files created)", async () => {
    const outDir = join(base, "f2-partial");
    // Pre-place ONLY the bundle path; the five key files do not exist yet.
    mkdirSync(outDir, { recursive: true });
    const bundlePath = join(outDir, "authority.bundle.json");
    writeFileSync(bundlePath, "SENTINEL");
    const r = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
    assert.equal(r.ok, false);
    assert.equal(readFileSync(bundlePath, "utf8"), "SENTINEL", "pre-existing file untouched");
    for (const name of ["root.key.pem", "root.pub.pem", "receipt-signing.key.pem", "ledger-signing.key.pem", "activation-signing.key.pem"]) {
      assert.equal(existsSync(join(outDir, name)), false, `${name} must not be created on a refused ceremony`);
    }
  });

  await test("F2: exclusive-create semantics — wx rejects an existing file (mechanism the writes rely on)", () => {
    const p = join(base, "f2-wx.txt");
    writeFileSync(p, "original", { flag: "wx" });
    assert.throws(
      () => writeFileSync(p, "overwrite", { flag: "wx" }),
      (err) => err && err.code === "EEXIST",
      "second exclusive write must throw EEXIST"
    );
    assert.equal(readFileSync(p, "utf8"), "original");
  });

  if (isWindows) {
    skip("F2: private key files are 0600", "POSIX mode not enforced on Windows");
  } else {
    await test("F2: private key files retain 0600 on POSIX", async () => {
      const outDir = join(base, "f2-mode");
      const r = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
      assert.equal(r.ok, true, r.reason);
      for (const p of [r.paths.rootPrivate, r.paths.receiptPrivate, r.paths.ledgerPrivate, r.paths.activationPrivate]) {
        assert.equal(statSync(p).mode & 0o777, 0o600, `${p} must be 0600`);
      }
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  console.log("F3 cryptographic init probe");
  // ─────────────────────────────────────────────────────────────────────────

  // These exercise the EXACT primitive init now uses (verifyAgainstBundle against
  // the published key), with the exact call shape — proving a non-empty signature
  // is insufficient and a mismatch is rejected.
  await test("F3: correct key pair verifies against its published bundle key", async () => {
    const kp = generateAuthorityKeyPair();
    const bundle = await buildBundleWith("receipt", "receipt-1", kp.publicPem, NOW);
    const payload = canonicalizeJson({ "mnde.init_probe.v1": true, role: "receipt", key_id: "receipt-1" });
    const sig = await signCanonical(payload, kp.privatePem);
    assert.equal((await verifyAgainstBundle(payload, sig, "receipt", "receipt-1", NOW, bundle)).ok, true);
  });

  await test("F3: wrong private key fails (published key is a DIFFERENT pair)", async () => {
    const published = generateAuthorityKeyPair();
    const attacker = generateAuthorityKeyPair();
    const bundle = await buildBundleWith("receipt", "receipt-1", published.publicPem, NOW);
    const payload = canonicalizeJson({ "mnde.init_probe.v1": true, role: "receipt", key_id: "receipt-1" });
    const sig = await signCanonical(payload, attacker.privatePem); // non-empty, but wrong key
    assert.ok(sig.length > 0, "attacker signature is non-empty — length alone would have passed the old check");
    const v = await verifyAgainstBundle(payload, sig, "receipt", "receipt-1", NOW, bundle);
    assert.equal(v.ok, false);
    assert.equal(v.reason, "SIGNATURE_INVALID");
  });

  await test("F3: empty and garbage signatures fail", async () => {
    const kp = generateAuthorityKeyPair();
    const bundle = await buildBundleWith("receipt", "receipt-1", kp.publicPem, NOW);
    const payload = canonicalizeJson({ "mnde.init_probe.v1": true, role: "receipt", key_id: "receipt-1" });
    assert.equal((await verifyAgainstBundle(payload, "", "receipt", "receipt-1", NOW, bundle)).ok, false);
    assert.equal((await verifyAgainstBundle(payload, "deadbeef", "receipt", "receipt-1", NOW, bundle)).ok, false);
    assert.equal((await verifyAgainstBundle(payload, "zz".repeat(64), "receipt", "receipt-1", NOW, bundle)).ok, false);
  });

  await test("F3: a modified probe payload fails against a valid signature", async () => {
    const kp = generateAuthorityKeyPair();
    const bundle = await buildBundleWith("receipt", "receipt-1", kp.publicPem, NOW);
    const signed = canonicalizeJson({ "mnde.init_probe.v1": true, role: "receipt", key_id: "receipt-1" });
    const tampered = canonicalizeJson({ "mnde.init_probe.v1": true, role: "receipt", key_id: "receipt-1", extra: "x" });
    const sig = await signCanonical(signed, kp.privatePem);
    assert.equal((await verifyAgainstBundle(tampered, sig, "receipt", "receipt-1", NOW, bundle)).ok, false);
  });

  await test("F3: key-id mismatch and wrong-role fail (published-key substitution rejected)", async () => {
    const kp = generateAuthorityKeyPair();
    const bundle = await buildBundleWith("receipt", "receipt-1", kp.publicPem, NOW);
    const payload = canonicalizeJson({ "mnde.init_probe.v1": true, role: "receipt", key_id: "receipt-1" });
    const sig = await signCanonical(payload, kp.privatePem);
    assert.equal((await verifyAgainstBundle(payload, sig, "receipt", "receipt-2", NOW, bundle)).reason, "UNKNOWN_KEY");
    assert.equal((await verifyAgainstBundle(payload, sig, "ledger", "receipt-1", NOW, bundle)).reason, "UNKNOWN_KEY");
  });

  await test("F3: init success path yields keys that verify against the published bundle", async () => {
    const outDir = join(base, "f3-init");
    const r = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
    assert.equal(r.ok, true, r.reason);
    const bundle = JSON.parse(readFileSync(r.paths.bundle, "utf8"));
    const priv = readFileSync(r.paths.receiptPrivate, "utf8");
    const payload = canonicalizeJson({ "mnde.check": true });
    const sig = await signCanonical(payload, priv);
    assert.equal((await verifyAgainstBundle(payload, sig, "receipt", r.receiptKeyId, NOW, bundle)).ok, true);
  });

  // ─────────────────────────────────────────────────────────────────────────
  console.log("F4 canonical containment");
  // ─────────────────────────────────────────────────────────────────────────

  const realRepo = realpathSync.native(repoRoot);

  await test("F4: the repo root itself and children are contained", () => {
    assert.equal(isRepoContained(repoRoot, repoRoot), true);
    assert.equal(isRepoContained(join(repoRoot, "keys"), repoRoot), true);
    assert.equal(isRepoContained(join(repoRoot, "a", "b", "c"), repoRoot), true);
  });

  await test("F4: '..' traversal that resolves back INTO the repo is contained", () => {
    const aliased = join(repoRoot, "..", basename(realRepo), "secrets");
    assert.equal(isRepoContained(aliased, repoRoot), true);
  });

  await test("F4: a sibling sharing a textual prefix (<repo>-backup) is NOT contained", () => {
    assert.equal(isRepoContained(realRepo + "-backup", repoRoot), false);
    assert.equal(isRepoContained(join(realRepo + "-backup", "root.key.pem"), repoRoot), false);
  });

  await test("F4: legitimate external absolute and not-yet-existing paths are allowed", () => {
    assert.equal(isRepoContained(base, repoRoot), false); // tmp dir, exists
    assert.equal(isRepoContained(join(base, "does", "not", "exist"), repoRoot), false); // nonexistent, existing parent
  });

  await test("F4: trailing-separator variants are consistent", () => {
    assert.equal(isRepoContained(repoRoot + sep, repoRoot), true);
    assert.equal(isRepoContained(base + sep, repoRoot), false);
  });

  if (isWindows) {
    await test("F4: Windows drive-letter and directory casing resolve into the repo", () => {
      const lowerDrive = realRepo.charAt(0).toLowerCase() + realRepo.slice(1);
      assert.equal(isRepoContained(lowerDrive, repoRoot), true);
      assert.equal(isRepoContained(realRepo.toUpperCase(), repoRoot), true);
    });
    await test("F4: a junction pointing into the repo is contained", () => {
      const link = join(base, "f4-junction");
      try {
        symlinkSync(realRepo, link, "junction");
      } catch (error) {
        return skip("F4 junction", `cannot create junction: ${error.code ?? error.message}`);
      }
      assert.equal(isRepoContained(join(link, "root.key.pem"), repoRoot), true);
    });
  } else {
    skip("F4: Windows drive-letter/dir casing", "not win32");
    await test("F4: a symlink pointing into the repo is contained", () => {
      const link = join(base, "f4-symlink");
      try {
        symlinkSync(realRepo, link, "dir");
      } catch (error) {
        return skip("F4 symlink", `cannot create symlink: ${error.code ?? error.message}`);
      }
      assert.equal(isRepoContained(join(link, "root.key.pem"), repoRoot), true);
    });
  }

  await test("F4: canonicalizeForContainment never creates the probed destination", () => {
    const ghost = join(base, "f4-ghost", "deep", "leaf");
    canonicalizeForContainment(ghost);
    assert.equal(existsSync(join(base, "f4-ghost")), false, "probing must not create directories");
  });

  await test("F4: init end-to-end refuses a repo-contained destination, accepts an external one", async () => {
    const inside = await initProductionAuthority({ outDir: join(repoRoot, "should-not-write"), authorityId: "acme-prod", now: NOW });
    assert.equal(inside.ok, false);
    assert.match(inside.reason, /inside the repository/i);
    assert.equal(existsSync(join(repoRoot, "should-not-write")), false, "no directory created inside the repo");
    const outside = await initProductionAuthority({ outDir: join(base, "f4-external"), authorityId: "acme-prod", now: NOW });
    assert.equal(outside.ok, true, outside.reason);
  });

  // ─────────────────────────────────────────────────────────────────────────
  try { rmSync(base, { recursive: true, force: true }); } catch { /* best effort */ }
  const passed = results.filter(Boolean).length;
  const total = results.length;
  if (passed !== total) {
    console.log(`\nFAIL prod-trust-gate hostile (${passed}/${total})`);
    process.exit(1);
  }
  console.log(`\nPASS prod-trust-gate hostile (${passed}/${total})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
