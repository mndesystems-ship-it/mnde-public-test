// Canonical number-model gate (P0 chunk 3).
//
//   npm run test:number-model
//
// Freezes the integer-only canonical number model and proves both fail-closed
// boundaries reject non-integers with a DISTINCT reason: the wire boundary
// (parseStrictJson -> invalid_json_number) and the library/SDK boundary
// (evaluatePolicyRequest -> NON_INTEGER_NUMBER). Scaled-integer and string
// representations of decimals pass. canonicalizeJson bytes are unchanged.

import assert from "node:assert/strict";

import { parseStrictJson, canonicalizeJson } from "../shared/json.ts";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";

const results = [];
function test(name, fn) {
  try { fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

const EMPTY_POLICY = { schema_version: "1.0", policy_id: "nm", version: "1.0.0", state: "ACTIVE", rules: [] };
const req = (parameters = {}) => ({
  schema_version: "1.0", request_id: "nm", timestamp: "2026-06-25T00:00:00.000Z",
  principal: { id: "p" }, agent: { id: "a" }, tool: { tool_name: "read_status" },
  parameters, environment: {}, context: {}
});
const reasonFor = (parameters) => evaluatePolicyRequest(req(parameters), EMPTY_POLICY, { now: "2026-06-25T00:00:00.000Z" }).reason_code;

console.log("MNDe canonical number model\n");

// ── library boundary: non-integers refused with NON_INTEGER_NUMBER ───────────
test("integer parameter is accepted (not a number error)", () => assert.notEqual(reasonFor({ amount_cents: 1099 }), "NON_INTEGER_NUMBER"));
test("plain decimal -> NON_INTEGER_NUMBER", () => assert.equal(reasonFor({ x: 2.5 }), "NON_INTEGER_NUMBER"));
test("sub-integer decimal -> NON_INTEGER_NUMBER", () => assert.equal(reasonFor({ x: 0.001 }), "NON_INTEGER_NUMBER"));
test("negative decimal -> NON_INTEGER_NUMBER", () => assert.equal(reasonFor({ x: -3.14 }), "NON_INTEGER_NUMBER"));
test("unsafe integer (2^53) -> NON_INTEGER_NUMBER", () => assert.equal(reasonFor({ x: 2 ** 53 }), "NON_INTEGER_NUMBER"));
test("nested decimal anywhere -> NON_INTEGER_NUMBER", () => assert.equal(reasonFor({ a: { b: [1, 2, 2.5] } }), "NON_INTEGER_NUMBER"));
test("non-integer in POLICY -> NON_INTEGER_NUMBER", () => {
  const r = evaluatePolicyRequest(req({}), { ...EMPTY_POLICY, limits: { max_depth: 1.5 } }, { now: "2026-06-25T00:00:00.000Z" });
  assert.equal(r.reason_code, "NON_INTEGER_NUMBER");
});

// ── decimals represented the supported way are accepted ──────────────────────
test("scaled-integer decimal (cents) is accepted", () => assert.notEqual(reasonFor({ amount_cents: 1099, rate_bps: 125 }), "NON_INTEGER_NUMBER"));
test("string decimal is accepted", () => assert.notEqual(reasonFor({ amount: "10.99", temperature: "0.7" }), "NON_INTEGER_NUMBER"));
test("-0 is a safe integer and is accepted", () => assert.notEqual(reasonFor({ x: -0 }), "NON_INTEGER_NUMBER"));
test("integer-valued exponent literal (1e3 === 1000) is accepted at the library", () => assert.notEqual(reasonFor({ x: 1e3 }), "NON_INTEGER_NUMBER"));

// ── fuzz: fixed edge sets (no RNG; deterministic) ────────────────────────────
test("fuzz: every non-integer is refused", () => {
  for (const n of [0.1, -0.1, 1.0000001, 3.333, 1e-6, 9007199254740993, Number.MAX_SAFE_INTEGER + 2, 1.5e2 + 0.5]) {
    assert.equal(reasonFor({ x: n }), "NON_INTEGER_NUMBER", `expected NON_INTEGER_NUMBER for ${n}`);
  }
});
test("fuzz: every safe integer is accepted", () => {
  for (const n of [0, 1, -1, 42, -42, 1000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1e3]) {
    assert.notEqual(reasonFor({ x: n }), "NON_INTEGER_NUMBER", `expected non-error for ${n}`);
  }
});

// ── wire boundary: parseStrictJson rejects non-integer literals ──────────────
test("wire: integer literal parses", () => assert.equal(parseStrictJson('{"x":1}').ok, true));
test("wire: decimal literal -> invalid_json_number", () => {
  const r = parseStrictJson('{"x":1.5}');
  assert.equal(r.ok, false); assert.equal(r.reason, "invalid_json_number");
});
test("wire: exponent literal -> invalid_json_number", () => {
  const r = parseStrictJson('{"x":1e3}');
  assert.equal(r.ok, false); assert.equal(r.reason, "invalid_json_number");
});
test("wire: -0 literal parses (safe integer)", () => assert.equal(parseStrictJson('{"x":-0}').ok, true));
test("wire: string decimal parses (opaque, not a number)", () => assert.equal(parseStrictJson('{"x":"10.99"}').ok, true));

// ── canonicalizeJson invariant unchanged ─────────────────────────────────────
test("canonicalizeJson: integers serialize; -0 -> 0; non-integer throws", () => {
  assert.equal(canonicalizeJson(5), "5");
  assert.equal(canonicalizeJson(-0), "0");
  assert.throws(() => canonicalizeJson(2.5));
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) { console.log(`FAIL number-model tests (${results.length - failed}/${results.length})`); process.exit(1); }
console.log(`PASS number-model tests (${results.length}/${results.length})`);
