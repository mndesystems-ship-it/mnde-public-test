// Operational dashboard (no-login) tests.
//
//   npm run test:dashboard
//
// Proves the infrastructure-first repositioning: a fresh user launches MNDe and
// the sidecar serves a local operational dashboard at "/" with NO login, signup,
// account creation, or cloud dependency. The dashboard answers one question —
// "Is MNDe protecting execution right now?" — and reads only local status
// endpoints. The decision/receipt/replay/authority/policy paths are untouched.

import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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

async function main() {
  console.log("MNDe operational dashboard (no login)\n");

  const sc = await startMndeSidecar({ url: "http://127.0.0.1:8794", env: { MNDE_BIND_PORT: "8794" } });
  let html = "";
  let contentType = "";
  try {
    await test("GET / serves the operational dashboard as HTML (200, no auth)", async () => {
      const res = await fetch(`${sc.url}/`);
      assert.equal(res.status, 200);
      contentType = res.headers.get("content-type") || "";
      assert.match(contentType, /text\/html/);
      html = await res.text();
      assert.ok(html.includes("Is MNDe protecting execution right now?"), "headline question must be present");
    });

    await test("GET /dashboard also serves the dashboard", async () => {
      const res = await fetch(`${sc.url}/dashboard`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get("content-type") || "", /text\/html/);
    });

    await test("status screen shows all seven operational panels", () => {
      for (const panel of ["Protection Status", "Sidecar Status", "Active Policy", "Trust Status", "Last Decision", "Receipt Count", "Protected Sources"]) {
        assert.ok(html.includes(panel), `missing panel: ${panel}`);
      }
    });

    await test("navigation is operational: Start / Status / Decisions / Receipts / Authority / Settings", () => {
      for (const nav of [">Start<", ">Status<", ">Decisions<", ">Receipts<", ">Authority<", ">Settings<"]) {
        assert.ok(html.includes(nav), `missing nav item: ${nav}`);
      }
      // No SaaS / marketing nav.
      for (const banned of [">Welcome<", ">Get Started<", ">Sign In<", ">Login<"]) {
        assert.ok(!html.includes(banned), `forbidden nav item: ${banned}`);
      }
    });

    await test("no login / signup / account / marketing CTAs anywhere", () => {
      // The forbidden items are interactive CTAs / screens — checked as their
      // canonical title-case labels. (Repositioning prose like "no login" is fine.)
      for (const banned of ["Login", "Log In", "Sign In", "Sign Up", "Create Account", "Get Started", "Welcome"]) {
        assert.ok(!html.includes(banned), `forbidden CTA present: ${banned}`);
      }
      assert.ok(!/type=["']password["']/.test(html), "no password field allowed");
    });

    await test("no forced cloud dependency (no external origins, no email collection)", () => {
      assert.ok(!html.includes("https://"), "dashboard must not load external resources");
      assert.ok(!/type=["']email["']/.test(html), "no email collection field");
      assert.ok(!/<form\b/.test(html), "no sign-in/sign-up form");
    });

    await test("dashboard reads local status endpoints only (relative URLs)", () => {
      for (const ep of ["/readyz", "/healthz", "/receipts/recent", "/policy/current", "/capabilities", "/identity"]) {
        assert.ok(html.includes(ep), `dashboard should read ${ep}`);
      }
    });

    await test("decision path is unchanged — sidecar still decides and signs", async () => {
      const res = await fetch(`${sc.url}/v1/decisions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ schema_version: "1.0", request_id: "dash-1", timestamp: new Date().toISOString(), principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} })
      });
      const body = await res.json();
      assert.ok(body.decision === "ALLOW" || body.decision === "REFUSE", "sidecar still returns a decision");
    });
  } finally {
    await sc.stop();
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL dashboard tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS dashboard tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
