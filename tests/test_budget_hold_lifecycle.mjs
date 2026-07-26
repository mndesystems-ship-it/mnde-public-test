#!/usr/bin/env node
// Regression tests for the budget-token "no-refund" defect and the hold /
// commit / release lifecycle that fixes it.
//
// THE BUG (before this change): ARM charged a budget_token the moment it
// reached its ALLOW verdict, by mutating consumed_cents in place. But ARM's
// ALLOW is only provisional — Ramona runs afterwards and can turn the final
// decision into a REFUSE (kill switch, runtime drift). There was no code path
// to give the money back, so a denied execution permanently consumed budget.
//
// THE FIX: ARM places a HOLD (reserved capacity, not a charge). The pipeline
// commits the hold only on the true, post-Ramona ALLOW, and releases it on any
// final REFUSE. These tests prove the release actually happens, that commits
// accumulate across requests, and that the cap is still enforced.
//
// Run: node --experimental-strip-types tests/test_budget_hold_lifecycle.mjs
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { executeDeterministicPipeline, resetRuntimeState, seedBudgetToken } from "../audit/node_runtime.ts";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { budgetTokenStore } from "../shared/index.ts";

// A valid HMAC signing config so buildReceipt produces a complete receipt.
// (Value is a throwaway demo key; the tests never rely on signature validity.)
process.env.MNDE_RECEIPT_HMAC_SECRET = "demo-legacy-signature-key-000000000001";
process.env.MNDE_RECEIPT_HMAC_KEY_ID = "reviewer-kit-hmac-key";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function loadPolicy() {
  return JSON.parse(readFileSync(join(repoRoot, "sample-policies", "legacy-gpu-policy.signed.json"), "utf8"));
}

// reviewerRequest() defaults to gpu_count 1 × hours 1 × gpu_hour_cents 500,
// no auto-scale, no retries → a projected cost of exactly 500 cents per
// request. That is well under the policy's 5000-cent manual-approval threshold
// and 10000-cent cost cap, so cost never interferes with the budget-token math.
const COST_PER_REQUEST = 500;

function budgetRequest({ id, token, killSwitch = false }) {
  const req = reviewerRequest({ requestId: id, tool: "read_status" });
  req.policy_document = loadPolicy();
  req.execution_request.budget_token = token;
  req.execution_request.runtime_observation.kill_switch_active = killSwitch;
  return req;
}

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

// One clean budget epoch shared across the whole scenario. We deliberately do
// NOT reset between requests — the point is to prove cross-request accounting.
resetRuntimeState();
seedBudgetToken("tok-lifecycle", 1200);

// ── T-B08: ARM allows, Ramona refuses (kill switch). The hold must be released;
//           a denied execution must not consume a single cent. This is the
//           direct regression guard for the no-refund defect.
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

// ── T-B01b: a SECOND allow against the same token accumulates. This is the
//            cross-request guarantee the per-task reset used to destroy.
{
  const { decision } = run(budgetRequest({ id: "bud-allow-2", token: "tok-lifecycle" }));
  assert(decision === "ALLOW", `second request should ALLOW (budget remains), got ${decision}`);
  const state = tokenState("tok-lifecycle");
  assert(state.consumed_cents === 2 * COST_PER_REQUEST, `two ALLOWs should accumulate to ${2 * COST_PER_REQUEST}, got ${state.consumed_cents}`);
}

// ── T-B02: the cap still bites. 1000 consumed, 200 remaining, request needs
//           500 → REFUSE, and an exhausted request must not change the balance.
{
  const { decision, reason } = run(budgetRequest({ id: "bud-overcap", token: "tok-lifecycle" }));
  assert(decision === "REFUSE", `over-cap request must REFUSE, got ${decision}`);
  assert(reason === "ERR_BUDGET_TOKEN_EXHAUSTED", `expected budget-exhausted refusal, got ${reason}`);
  const state = tokenState("tok-lifecycle");
  assert(state.consumed_cents === 2 * COST_PER_REQUEST, `exhausted request must not change consumed budget, got ${state.consumed_cents}`);
  assert(state.pending_holds.length === 0, "a refused hold must leave no pending hold behind");
}

console.log("PASS budget hold/commit/release lifecycle tests");
