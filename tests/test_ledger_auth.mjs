// Ledger route authorization regression tests (P0 security hotfix).
//
//   npm run test:ledger-auth
//
// Proves the fix for the authorization bypass on the PR #7 anchoring routes:
//   GET  /ledger/checkpoint   (read  → inspect_receipts)
//   GET  /ledger/proof        (read  → verify_receipts)
//   POST /ledger/anchor       (write → manage_runtime, ADMIN-only)
//
// At commit 3c07011 these three routes were ABSENT from SENSITIVE_PATHS, so
// requiredCapabilityForPath() returned null and authorizeAuthorityAction()
// treated them as "no authority required" — an unauthenticated bypass. Every
// UNAUTHORIZED test below fails against 3c07011 and passes after the fix.
//
// The tests come in two layers:
//   1. Authorization-unit layer — direct calls to the capability map / decision
//      function and the sensitive-namespace helper. Fast, deterministic, no server.
//   2. Live production sidecar — the real request path (routing → capability
//      resolution → enforcement) under MNDE_PROFILE=production, mirroring the
//      production harness used by tests/test_dashboard.mjs.
//
// Non-production (local) behavior — the localhost dev pass-through that keeps the
// round-trip in tests/test_ledger_anchor.mjs working without an authority
// assertion — is intentionally preserved and is covered by that existing suite.

import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";
import { canonicalReceiptHash } from "../src/execution-ledger/index.mjs";
import {
  authorizeAuthorityAction,
  isSensitiveNamespacePath,
  requiredCapabilityForPath
} from "../sidecar/auth_authority.mjs";

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

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

// ── Production sidecar bootstrap (mirrors tests/test_dashboard.mjs) ────────────
async function writeProductionCustody(dir) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "prod-ledger-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "acme-prod-ledger-auth",
    issuedAt: "2026-06-14T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundlePath = join(dir, "authority.bundle.json");
  const keyPath = join(dir, "receipt.key.pem");
  const ledgerKeyPath = join(dir, "ledger.key.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(keyPath, receipt.privatePem, "utf8");
  writeFileSync(ledgerKeyPath, ledger.privatePem, "utf8");
  return {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath,
    MNDE_RECEIPT_SIGNING_KEY: keyPath,
    MNDE_RECEIPT_KEY_ID: receipt.keyId,
    MNDE_LEDGER_SIGNING_KEY: ledgerKeyPath,
    MNDE_LEDGER_KEY_ID: ledger.keyId
  };
}

async function productionEnforcementExtras(dir) {
  const root = { keyId: "pe-root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "mnde-ledger-auth-pe", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundle = await signPolicyBundle({
    bundle_id: "ops-policy-10-10.0.0", policy_id: "ops-policy", serial: 10, issued_at: "2026-06-23T12:00:00.000Z",
    policy_document: { schema_version: "1.0", policy_id: "ops-policy", version: "10.0.0", state: "ACTIVE", rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] }
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const policyBundlePath = join(dir, "policy-bundle.json");
  const authorityBundlePath = join(dir, "pe-authority-bundle.json");
  writeFileSync(policyBundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(authorityBundlePath, JSON.stringify(authorityBundle), "utf8");
  return {
    MNDE_SIDECAR_AUTH: "bearer",
    MNDE_SIDECAR_AUTH_TOKENS: JSON.stringify({ "ledger-caller-token": "ledger-caller" }),
    MNDE_DECISION_ENGINE: "policy-engine",
    MNDE_PE_POLICY_BUNDLE: policyBundlePath,
    MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
    MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "pe-bundle-state.json"),
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: authorityBundle.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: "2026-06-23T12:00:00.000Z"
  };
}

// Mint a signed authority assertion. Caller supplies roles + capabilities so we
// can exercise least-privilege separation (read caps vs. anchor's manage_runtime).
function authorityAssertion(privateKey, { roles, capabilities, subject = "ledger-actor", ...overrides } = {}) {
  const now = Date.now();
  const nonce = `nonce-${now}-${Math.random().toString(36).slice(2).padEnd(24, "x")}`.slice(0, 60);
  const payload = {
    issuer: "mnde-desktop",
    audience: "mnde-sidecar",
    subject,
    nonce,
    session_id: `session-${nonce}`,
    issued_at: now - 1000,
    expires_at: now + 60_000,
    roles,
    capabilities,
    display_name: subject,
    provider: "test",
    ...overrides
  };
  const payloadPart = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signaturePart = sign(null, Buffer.from(payloadPart, "utf8"), privateKey).toString("base64url");
  return `${payloadPart}.${signaturePart}`;
}

function tamperAssertion(assertion) {
  const parts = assertion.split(".");
  const sig = Buffer.from(parts[1], "base64url");
  sig[0] ^= 0x01;
  parts[1] = sig.toString("base64url");
  return parts.join(".");
}

// Every unauthorized failure mode must return the SAME uniform external error,
// never leaking which internal reason (missing/expired/replay/authz) fired.
async function assertUniformAuthRefusal(res) {
  assert.equal(res.status, 403, `expected 403, got ${res.status}`);
  const body = await res.json();
  assert.equal(body.reason_code, "ERR_AUTH_REFUSED");
  assert.equal(body.reason, "ERR_AUTH_REFUSED");
  const text = JSON.stringify(body);
  for (const leaked of ["ERR_AUTH_REQUIRED", "ERR_AUTH_ASSERTION_MALFORMED", "ERR_AUTH_SIGNATURE_INVALID", "ERR_AUTH_EXPIRED", "ERR_AUTH_REPLAY", "ERR_AUTHZ_REFUSED", "manage_runtime", "inspect_receipts", "verify_receipts"]) {
    assert.ok(!text.includes(leaked), `external response leaked internal detail: ${leaked}`);
  }
}

const ROUTE_CAPS = {
  "/ledger/checkpoint": "inspect_receipts",
  "/ledger/proof": "verify_receipts",
  "/ledger/anchor": "manage_runtime"
};

async function main() {
  console.log("MNDe ledger route authorization (P0 hotfix)\n");

  // ── Layer 1: authorization-unit checks (no server) ──────────────────────────

  await test("each anchoring route maps to an explicit, non-null capability", () => {
    for (const [route, cap] of Object.entries(ROUTE_CAPS)) {
      const got = requiredCapabilityForPath(route);
      assert.equal(got, cap, `${route} must require ${cap}, got ${JSON.stringify(got)}`);
    }
  });

  await test("anchor requires a strictly stronger capability than the reads (least privilege)", () => {
    // manage_runtime is ADMIN-only; the read caps are held by AUDITOR/OPERATOR too.
    // They must be distinct so a read authority can never satisfy anchor.
    assert.equal(requiredCapabilityForPath("/ledger/anchor"), "manage_runtime");
    assert.notEqual(requiredCapabilityForPath("/ledger/anchor"), requiredCapabilityForPath("/ledger/checkpoint"));
    assert.notEqual(requiredCapabilityForPath("/ledger/anchor"), requiredCapabilityForPath("/ledger/proof"));
  });

  await test("unauthenticated authorization is refused for all three routes (bypass closed)", () => {
    for (const route of Object.keys(ROUTE_CAPS)) {
      const authz = authorizeAuthorityAction(route, null);
      assert.equal(authz.ok, false, `${route} must not be unauthenticated-reachable`);
      assert.equal(authz.reason, "ERR_AUTH_REQUIRED");
    }
  });

  await test("similar-looking sensitive paths fail closed at the authorization boundary (order-independent)", () => {
    for (const evil of ["/ledger/proofevil", "/ledger/anchor-old", "/ledger/checkpoint-public"]) {
      assert.equal(requiredCapabilityForPath(evil), null, `${evil} must not be an explicitly protected route`);
      assert.equal(isSensitiveNamespacePath(evil), true, `${evil} must fall under the sensitive /ledger/ namespace`);
      // An unmapped path inside a sensitive namespace is refused INSIDE
      // authorizeAuthorityAction, before any handler or the post-dispatch
      // namespace guard can run — so route ordering cannot recreate the bypass.
      const authz = authorizeAuthorityAction(evil, null);
      assert.equal(authz.ok, false, `${evil} must fail closed at the authorization boundary`);
      assert.equal(authz.reason, "ERR_AUTH_CAPABILITY_UNMAPPED", `${evil} must refuse with the unmapped code`);
      assert.equal(authz.status, 403);
      assert.equal(authz.capability, null);
    }
  });

  await test("unmapped SENSITIVE routes fail closed even with an otherwise-valid authority assertion", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    const prevKey = process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64;
    const prevNonce = process.env.MNDE_AUTH_NONCE_CACHE;
    const nonceDir = mkdtempSync(join(tmpdir(), "mnde-unmapped-nonce-"));
    process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64 = Buffer.from(publicDer).subarray(-32).toString("base64url");
    process.env.MNDE_AUTH_NONCE_CACHE = join(nonceDir, "nonces.json");
    try {
      // A fully valid ADMIN assertion holding every capability still cannot reach
      // an unmapped sensitive route: the boundary refuses before capability
      // matching, so a forgotten mapping is never satisfiable by any credential.
      const admin = authorityAssertion(privateKey, { roles: ["ADMIN"], capabilities: ["manage_runtime", "inspect_receipts", "verify_receipts"] });
      const authz = authorizeAuthorityAction("/ledger/future-route", admin);
      assert.equal(authz.ok, false, "unmapped sensitive route must fail closed for a valid admin too");
      assert.equal(authz.reason, "ERR_AUTH_CAPABILITY_UNMAPPED");
      assert.equal(authz.status, 403);
      // Unmapped NON-sensitive paths keep their historical pass-through.
      const nonSensitive = authorizeAuthorityAction("/definitely-not-a-route", null);
      assert.equal(nonSensitive.ok, true, "unmapped non-sensitive path keeps existing behavior");
      assert.equal(nonSensitive.capability, null);
    } finally {
      if (prevKey === undefined) delete process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64; else process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64 = prevKey;
      if (prevNonce === undefined) delete process.env.MNDE_AUTH_NONCE_CACHE; else process.env.MNDE_AUTH_NONCE_CACHE = prevNonce;
      rmSync(nonceDir, { recursive: true, force: true });
    }
  });

  await test("sensitive-namespace matching is segment-boundary-aware", () => {
    assert.equal(isSensitiveNamespacePath("/ledger/"), true);
    assert.equal(isSensitiveNamespacePath("/ledger/anything/deep"), true);
    assert.equal(isSensitiveNamespacePath("/ledgerfoo"), false);   // no boundary → not sensitive
    assert.equal(isSensitiveNamespacePath("/ledger"), false);       // exact, no sub-route
    assert.equal(isSensitiveNamespacePath("/dashboard"), false);
    assert.equal(isSensitiveNamespacePath("/"), false);
    assert.equal(isSensitiveNamespacePath(null), false);
  });

  await test("read-only authority cannot satisfy anchor; anchor authority can (assertion layer)", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    const prevKey = process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64;
    const prevNonce = process.env.MNDE_AUTH_NONCE_CACHE;
    const nonceDir = mkdtempSync(join(tmpdir(), "mnde-ledger-auth-nonce-"));
    process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64 = Buffer.from(publicDer).subarray(-32).toString("base64url");
    process.env.MNDE_AUTH_NONCE_CACHE = join(nonceDir, "nonces.json");
    try {
      // AUDITOR holding only reads must be REFUSED on anchor.
      const readOnly = authorityAssertion(privateKey, { roles: ["AUDITOR"], capabilities: ["inspect_receipts", "verify_receipts"] });
      const refused = authorizeAuthorityAction("/ledger/anchor", readOnly);
      assert.equal(refused.ok, false, "read-only authority must not anchor");
      assert.equal(refused.reason, "ERR_AUTHZ_REFUSED");

      // ADMIN holding manage_runtime is allowed.
      const admin = authorityAssertion(privateKey, { roles: ["ADMIN"], capabilities: ["manage_runtime"] });
      const allowed = authorizeAuthorityAction("/ledger/anchor", admin);
      assert.equal(allowed.ok, true, "manage_runtime authority must anchor");
      assert.equal(allowed.capability, "manage_runtime");

      // The same read authority DOES satisfy the read routes (sanity: caps are wired).
      const readCk = authorizeAuthorityAction("/ledger/checkpoint", authorityAssertion(privateKey, { roles: ["AUDITOR"], capabilities: ["inspect_receipts"] }));
      assert.equal(readCk.ok, true);
      const readPf = authorizeAuthorityAction("/ledger/proof", authorityAssertion(privateKey, { roles: ["AUDITOR"], capabilities: ["verify_receipts"] }));
      assert.equal(readPf.ok, true);
    } finally {
      if (prevKey === undefined) delete process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64; else process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64 = prevKey;
      if (prevNonce === undefined) delete process.env.MNDE_AUTH_NONCE_CACHE; else process.env.MNDE_AUTH_NONCE_CACHE = prevNonce;
      rmSync(nonceDir, { recursive: true, force: true });
    }
  });

  // ── Layer 2: live production sidecar (real request path) ─────────────────────
  const prodDir = mkdtempSync(join(tmpdir(), "mnde-ledger-auth-prod-"));
  let prod = null;
  const PORT = await getFreePort();
  // Observable side effect for the registered-but-unmapped probe route: its
  // handler appends to this file ONLY on an allow result. The file must never
  // appear, proving no handler body executed.
  const probeMutationFile = join(prodDir, "unmapped-probe-mutation.log");
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    const auditLog = join(prodDir, "auth-audit.jsonl");
    prod = await startMndeSidecar({
      url: `http://127.0.0.1:${PORT}`,
      env: {
        ...(await writeProductionCustody(prodDir)),
        ...(await productionEnforcementExtras(prodDir)),
        MNDE_BIND_PORT: String(PORT),
        // Isolate receipt + ledger state to this temp dir. Without this the
        // sidecar harness's SHARED default receipt log is reused, so a ledger
        // written by an earlier suite (signed with a different ledger key) makes
        // anchoring fail SIGNATURE_INVALID here. The ledger path derives from the
        // receipt-log directory (resolveLedgerRuntime).
        MNDE_RECEIPT_LOG: join(prodDir, "receipts.jsonl"),
        MNDE_EXECUTION_LEDGER_PATH: join(prodDir, "execution-ledger.jsonl"),
        MNDE_LEDGER_ANCHOR_TICK_MS: "3600000", // disable the background anchor timer; drive anchoring on-demand
        MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64: Buffer.from(publicDer).subarray(-32).toString("base64url"),
        MNDE_AUTH_AUDIT_LOG: auditLog,
        MNDE_AUTH_NONCE_CACHE: join(prodDir, "auth-nonces.json"),
        // Register the deliberately-unmapped /ledger/__authz_probe handler so the
        // live suite can prove the authorization boundary (not route ordering)
        // rejects it. Inert in real deployments (flag unset).
        MNDE_TEST_UNMAPPED_LEDGER_PROBE: "1",
        MNDE_TEST_UNMAPPED_LEDGER_PROBE_FILE: probeMutationFile
      }
    });
    const url = prod.url;
    const BEARER = { authorization: "Bearer ledger-caller-token" };
    const ck = (caps) => ({ "x-mnde-authority-assertion": authorityAssertion(privateKey, { roles: ["AUDITOR"], capabilities: caps }) });
    const adminAnchor = () => ({ "x-mnde-authority-assertion": authorityAssertion(privateKey, { roles: ["ADMIN"], capabilities: ["manage_runtime"] }) });

    const decide = (tool, id) => fetch(`${url}/v1/decisions`, {
      method: "POST",
      headers: { "content-type": "application/json", ...BEARER },
      body: JSON.stringify({ schema_version: "1.0", request_id: id, timestamp: "2026-06-23T12:00:00.000Z", principal: { id: "alice" }, agent: { id: "a1" }, tool: { tool_name: tool }, parameters: {}, environment: {}, context: {} })
    }).then((r) => r.json());

    await test("production keeps health and readiness open (no auth)", async () => {
      for (const ep of ["/healthz", "/readyz"]) {
        assert.equal((await fetch(`${url}${ep}`)).status, 200, `${ep} must stay open`);
      }
    });

    await test("UNAUTHENTICATED /ledger/checkpoint, /ledger/anchor, /ledger/proof are all denied (403)", async () => {
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/checkpoint`));
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/anchor`, { method: "POST" }));
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/proof?receipt_hash=sha256:whatever`));
    });

    await test("invalid / tampered / expired / wrong-capability assertions are denied uniformly", async () => {
      // Malformed
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/checkpoint`, { headers: { "x-mnde-authority-assertion": "not.valid" } }));
      // Tampered signature
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/checkpoint`, { headers: { "x-mnde-authority-assertion": tamperAssertion(authorityAssertion(privateKey, { roles: ["AUDITOR"], capabilities: ["inspect_receipts"] })) } }));
      // Expired
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/checkpoint`, { headers: { "x-mnde-authority-assertion": authorityAssertion(privateKey, { roles: ["AUDITOR"], capabilities: ["inspect_receipts"], issued_at: Date.now() - 3000, expires_at: Date.now() - 1000 }) } }));
      // Valid token but WRONG capability for the route (view_dashboard cannot read the checkpoint)
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/checkpoint`, { headers: { "x-mnde-authority-assertion": authorityAssertion(privateKey, { roles: ["VIEWER"], capabilities: ["view_dashboard"] }) } }));
    });

    await test("query strings and trailing slashes do not bypass authorization", async () => {
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/checkpoint?public=1&path=/healthz`));
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/proof?receipt_hash=x&trust=yes`));
      // Trailing slash is a different (unknown) path under the sensitive namespace → fail-closed 403.
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/checkpoint/`));
    });

    await test("hostile path normalization cannot dodge the guard (percent-encoding, dot-segments, extra slashes)", async () => {
      // %61 = 'a'; the router leaves it encoded, so this is an unknown /ledger/* → 403.
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/%61nchor`, { method: "POST" }));
      // Dot-segments resolve to /ledger/anchor for BOTH guard and router → the mapped
      // capability is enforced → 403 (never 200/anchored).
      const dotSeg = await fetch(`${url}/ledger/x/../anchor`, { method: "POST" });
      assert.notEqual(dotSeg.status, 200, "dot-segment anchor must not execute");
      // Leading '//' parses the authority away (path becomes /anchor) → not the anchor route.
      const dblSlash = await fetch(`${url}//ledger/anchor`, { method: "POST" });
      assert.notEqual(dblSlash.status, 200, "double-slash must not reach the anchor handler");
    });

    await test("unknown /ledger/* route is denied in production; unknown non-sensitive route keeps 404", async () => {
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/does-not-exist`));
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/anchor2`, { method: "POST" }));
      const nonSensitive = await fetch(`${url}/definitely-not-a-route`);
      assert.equal(nonSensitive.status, 404, "unknown non-sensitive route must retain 404");
    });

    await test("REGISTERED-but-unmapped /ledger/* handler is refused by AUTHORIZATION, not by the namespace guard, and its body never runs", async () => {
      // This route has a real handler wired BEFORE the post-dispatch namespace
      // guard and is deliberately NOT in SENSITIVE_PATHS. If protection depended
      // on route ordering, its body would execute (mutating the probe file). The
      // authorization boundary must refuse it with the unmapped-capability code
      // and no mutation may occur — even under a valid admin assertion.
      assert.equal(existsSync(probeMutationFile), false, "probe file must not exist before the test");

      const unauthed = await fetch(`${url}/ledger/__authz_probe`, { method: "POST" });
      assert.equal(unauthed.status, 403, "unmapped registered route must be 403");
      const body = await unauthed.json();
      assert.equal(body.reason_code, "ERR_AUTH_CAPABILITY_UNMAPPED", `expected unmapped code, got ${JSON.stringify(body)}`);
      assert.equal(body.reason, "ERR_AUTH_CAPABILITY_UNMAPPED");

      // A fully valid ADMIN assertion (every capability) must also be refused —
      // proving the refusal is the missing MAPPING, not a failed credential check.
      const withAdmin = await fetch(`${url}/ledger/__authz_probe`, {
        method: "POST",
        headers: { "x-mnde-authority-assertion": authorityAssertion(privateKey, { roles: ["ADMIN"], capabilities: ["manage_runtime", "inspect_receipts", "verify_receipts"] }) }
      });
      assert.equal(withAdmin.status, 403, "valid admin must not satisfy an unmapped route");
      assert.equal((await withAdmin.json()).reason_code, "ERR_AUTH_CAPABILITY_UNMAPPED");

      assert.equal(existsSync(probeMutationFile), false, "unmapped handler body must NOT have executed (no mutation)");
    });

    // Seed the ledger so checkpoint/proof have real content.
    await test("authenticated decisions append ledger entries", async () => {
      const d1 = await decide("read_status", "req-la-1");
      const d2 = await decide("read_status", "req-la-2");
      assert.equal(d1.ledger?.appended, true, `decision 1 must append: ${JSON.stringify(d1.ledger)}`);
      assert.equal(d2.ledger?.appended, true, "decision 2 must append");
      main._receiptHash = canonicalReceiptHash(d1.receipt);
    });

    await test("unauthorized anchor performs NO ledger mutation (authorization before work)", async () => {
      const before = await fetch(`${url}/ledger/checkpoint`, { headers: ck(["inspect_receipts"]) }).then((r) => r.json());
      const beforeSize = before.checkpoint?.tree_size ?? 0;
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/anchor`, { method: "POST" })); // unauthenticated
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/anchor`, { method: "POST", headers: ck(["inspect_receipts"]) })); // read-only cannot anchor
      const after = await fetch(`${url}/ledger/checkpoint`, { headers: ck(["inspect_receipts"]) }).then((r) => r.json());
      assert.equal(after.checkpoint?.tree_size ?? 0, beforeSize, "unauthorized anchor attempts must not advance the checkpoint");
    });

    await test("AUTHORIZED anchor (manage_runtime) succeeds and advances the checkpoint", async () => {
      const anchored = await fetch(`${url}/ledger/anchor`, { method: "POST", headers: adminAnchor() }).then((r) => r.json());
      assert.equal(anchored.anchored, true, JSON.stringify(anchored));
      assert.ok(anchored.checkpoint.tree_size >= 2, `tree_size ${anchored.checkpoint?.tree_size}`);
    });

    await test("AUTHORIZED checkpoint read (inspect_receipts) succeeds", async () => {
      const head = await fetch(`${url}/ledger/checkpoint`, { headers: ck(["inspect_receipts"]) });
      assert.equal(head.status, 200);
      const body = await head.json();
      assert.ok(body.checkpoint?.tree_size >= 2, `tree_size ${body.checkpoint?.tree_size}`);
    });

    await test("AUTHORIZED proof read (verify_receipts) succeeds and verifies", async () => {
      const res = await fetch(`${url}/ledger/proof?receipt_hash=${encodeURIComponent(main._receiptHash)}`, { headers: ck(["verify_receipts"]) });
      assert.equal(res.status, 200, "authorized proof must not be rejected");
      const body = await res.json();
      assert.equal(body.ok, true, JSON.stringify(body));
      assert.equal(body.proof.schema, "mnde.execution_ledger.inclusion_proof.v1");
    });

    await test("read-only capability (verify_receipts / inspect_receipts) still cannot anchor over the wire", async () => {
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/anchor`, { method: "POST", headers: ck(["verify_receipts"]) }));
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/anchor`, { method: "POST", headers: ck(["inspect_receipts"]) }));
    });

    await test("known public routes remain public; existing protected routes still enforce", async () => {
      assert.equal((await fetch(`${url}/healthz`)).status, 200);
      // A pre-existing protected ledger route is unaffected by the change.
      await assertUniformAuthRefusal(await fetch(`${url}/ledger/head`));
    });

    await test("unauthorized ledger access is audited with a generic reason (no capability leak)", async () => {
      const lines = readFileSync(auditLog, "utf8").trim().split(/\n/).filter(Boolean).map((l) => JSON.parse(l));
      const refusals = lines.filter((r) => r.result === "REFUSE" && String(r.action).startsWith("/ledger/"));
      assert.ok(refusals.length > 0, "ledger refusals must be audited");
      for (const r of refusals) {
        assert.ok(!JSON.stringify(r).includes("manage_runtime"), "audit must not embed capability internals in a way that leaks externally");
      }
    });
  } finally {
    if (prod) await prod.stop();
    rmSync(prodDir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL ledger-auth tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS ledger-auth tests (${results.length}/${results.length})`);
}

main().catch((e) => { console.error(e); process.exit(1); });
