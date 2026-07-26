#!/usr/bin/env node
// Standalone regression tests for the budget-token hold / commit / release
// lifecycle. Covers two review findings on PR #4:
//
//   Thread 1 (P1): committed budget must survive across live requests handled by
//     the same worker process, and must block spending above the remaining cap.
//     The live worker (sidecar/deterministic_worker.mjs) no longer resets budget
//     state per task, so a token accumulates spend across requests. T-LIVE proves
//     it; T-EXHAUST proves the cap still bites.
//
//   Thread 2 (P2): this test is fully self-contained. It stands up an isolated
//     temporary MNDE_HOME, generates its own Ed25519 receipt-signing keypair, and
//     tears the data root down afterwards — it does NOT depend on test execution
//     order or on repository-local (git-ignored) keys.
//
// Run: node --experimental-strip-types tests/test_budget_hold_lifecycle.mjs
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ── Isolated data root + generated signing keys, established BEFORE any signing
//    code is imported. receipt-signing.ts resolves its key paths from MNDE_HOME
//    at module load, so this env + keypair must exist before the dynamic import
//    of the pipeline below.
const MNDE_HOME = mkdtempSync(join(tmpdir(), "mnde-budget-lifecycle-"));
process.env.MNDE_HOME = MNDE_HOME;
process.env.MNDE_RECEIPT_HMAC_SECRET = "test-budget-lifecycle-hmac-secret-000000";
process.env.MNDE_RECEIPT_HMAC_KEY_ID = "budget-lifecycle-hmac-key";

const keyDir = join(MNDE_HOME, "shared", "receipt_keys");
mkdirSync(keyDir, { recursive: true });
{
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(keyDir, "receipt_signing_private.pem"), privateKey.export({ type: "pkcs8", format: "pem" }));
  writeFileSync(join(keyDir, "receipt_signing_public.pem"), publicKey.export({ type: "spki", format: "pem" }));
}

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
function loadPolicy() {
  return JSON.parse(readFileSync(join(repoRoot, "sample-policies", "legacy-gpu-policy.signed.json"), "utf8"));
}

// reviewerRequest() defaults to gpu_count 1 × hours 1 × gpu_hour_cents 500,
// no auto-scale, no retries → a projected cost of exactly 500 cents per request,
// well under the policy caps so cost never interferes with the budget-token math.
const COST_PER_REQUEST = 500;

async function main() {
  // Dynamic imports AFTER MNDE_HOME + keys are in place (see note above).
  const { executeDeterministicPipeline, resetRuntimeState, seedBudgetToken } =
    await import("../audit/node_runtime.ts");
  const { reviewerRequest } = await import("../scripts/reviewer-request.mjs");
  const { budgetTokenStore } = await import("../shared/index.ts");

  function budgetRequest({ id, token, killSwitch = false }) {
    const req = reviewerRequest({ requestId: id, tool: "read_status" });
    req.policy_document = loadPolicy();
    req.execution_request.budget_token = token;
    req.execution_request.runtime_observation.kill_switch_active = killSwitch;
    return req;
  }
  // run() calls the same entry point the live worker uses
  // (executeDeterministicPipeline) and, like the fixed worker, does NOT reset
  // between requests — so consecutive calls share one budget epoch.
  function run(req) {
    const result = executeDeterministicPipeline(JSON.stringify(req));
    assert("receipt" in result, `expected receipt, got ${JSON.stringify(result)}`);
    return {
      decision: result.receipt.decision_output.decision,
      reason: result.receipt.decision_output.reason_code
    };
  }
  function tokenState(token) {
    const state = budgetTokenStore.snapshot().find((t) => t.budget_token === token);
    assert(state, `token ${token} missing from store snapshot`);
    return state;
  }

  // One clean budget epoch; seed a cap of 1200 cents. resetRuntimeState() is the
  // replay/test-isolation reset — used once here to start clean, and deliberately
  // NOT called between the requests below (that is the live-worker behavior).
  resetRuntimeState();
  seedBudgetToken("tok-lifecycle", 1200);

  // ── T-B08: ARM allows, Ramona refuses (kill switch). The hold must be released;
  //           a denied execution must not consume a single cent (no-refund guard).
  {
    const { decision, reason } = run(budgetRequest({ id: "bud-killswitch", token: "tok-lifecycle", killSwitch: true }));
    assert(decision === "REFUSE", `kill-switch request must REFUSE, got ${decision}`);
    assert(reason === "ERR_KILL_SWITCH", `expected kill-switch refusal, got ${reason}`);
    const state = tokenState("tok-lifecycle");
    assert(state.consumed_cents === 0, `NO-REFUND REGRESSION: denied execution consumed ${state.consumed_cents} cents (must be 0)`);
    assert(state.pending_holds.length === 0, `hold from a denied execution must be released, found ${state.pending_holds.length}`);
  }

  // ── T-B01a: a clean final ALLOW commits the hold into consumed_cents.
  {
    const { decision } = run(budgetRequest({ id: "bud-allow-1", token: "tok-lifecycle" }));
    assert(decision === "ALLOW", `clean request should ALLOW, got ${decision}`);
    const state = tokenState("tok-lifecycle");
    assert(state.consumed_cents === COST_PER_REQUEST, `ALLOW should commit ${COST_PER_REQUEST}, got ${state.consumed_cents}`);
    assert(state.pending_holds.length === 0, "committed hold should be cleared");
  }

  // ── T-LIVE (Thread 1 regression): committed spending SURVIVES a second live
  //   request. The live worker no longer resets between requests, so this second
  //   ALLOW accumulates on top of the first instead of starting from zero. If the
  //   per-task budget reset were reintroduced, consumed_cents would fall back to
  //   500 (or the token would be wiped) and this assertion would fail.
  {
    const { decision } = run(budgetRequest({ id: "bud-allow-2", token: "tok-lifecycle" }));
    assert(decision === "ALLOW", `second live request should ALLOW (budget remains), got ${decision}`);
    const state = tokenState("tok-lifecycle");
    assert(
      state.consumed_cents === 2 * COST_PER_REQUEST,
      `THREAD-1 REGRESSION: committed spend must survive a second live request and accumulate to ${2 * COST_PER_REQUEST}, got ${state.consumed_cents}`
    );
  }

  // ── T-EXHAUST (Thread 1 regression): the cap blocks spending above the
  //   remaining budget. 1000 consumed, 200 remaining, request needs 500 → REFUSE,
  //   and an exhausted request must not change the balance.
  {
    const { decision, reason } = run(budgetRequest({ id: "bud-overcap", token: "tok-lifecycle" }));
    assert(decision === "REFUSE", `over-cap request must REFUSE, got ${decision}`);
    assert(reason === "ERR_BUDGET_TOKEN_EXHAUSTED", `expected budget-exhausted refusal, got ${reason}`);
    const state = tokenState("tok-lifecycle");
    assert(state.consumed_cents === 2 * COST_PER_REQUEST, `exhausted request must not change consumed budget, got ${state.consumed_cents}`);
    assert(state.pending_holds.length === 0, "a refused hold must leave no pending hold behind");
  }

  console.log("PASS budget hold/commit/release lifecycle tests");
}

try {
  await main();
} finally {
  // Always tear down the isolated data root.
  try {
    rmSync(MNDE_HOME, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }
}
