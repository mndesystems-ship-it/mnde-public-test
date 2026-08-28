#!/usr/bin/env node
// M1 — normalized execution envelope (`mnde.execution.request.v1`) + adapter equivalence.
//
// Proves: (1) the envelope maps deterministically into the existing policy-engine
// request; (2) two DIFFERENTLY-SHAPED adapters for the same semantic execution
// receive identical policy treatment; (3) malformed/incomplete envelopes fail closed;
// (4) existing request formats are unaffected (the engine is untouched); (5) the M1
// non-goals (nonce/expires_at not enforced, authorities passed through) hold.

import assert from "node:assert/strict";

import { canonicalizeJson } from "../shared/json.ts";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";
import {
  EXECUTION_ENVELOPE_SCHEMA,
  ENVELOPE_REASONS,
  validateExecutionEnvelope,
  normalizeExecutionEnvelope,
  decideFromEnvelope
} from "../src/execution-envelope/index.mjs";
import { mcpToolCallToEnvelope } from "../src/execution-envelope/adapters/mcp-tool-call.mjs";
import { httpJsonToEnvelope } from "../src/execution-envelope/adapters/http-json.mjs";

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

const policy = {
  schema_version: "1.0",
  policy_id: "policy_envelope_test",
  version: "0.1.0",
  state: "ACTIVE",
  rules: [
    {
      rule_id: "allow_purchase",
      effect: "ALLOW",
      match: {
        all: [
          { field: "tool.tool_name", op: "eq", value: "payments.purchase" },
          { field: "context.resource.type", op: "eq", value: "merchant_checkout" },
          { field: "parameters.currency", op: "eq", value: "USD" }
        ]
      }
    },
    {
      rule_id: "refuse_refund",
      effect: "REFUSE",
      match: { all: [{ field: "tool.tool_name", op: "eq", value: "payments.refund" }] }
    }
  ],
  limits: { max_depth: 8 }
};

const RID = "req_env_001";
const TS = "2026-08-26T12:00:00.000Z";

// One semantic execution: agent purchases USD 320 of a merchant checkout.
function validEnvelope(overrides = {}) {
  return {
    schema: EXECUTION_ENVELOPE_SCHEMA,
    request_id: RID,
    timestamp: TS,
    principal: { id: "agent://acme/purchasing", type: "agent" },
    action: { namespace: "payments", operation: "purchase" },
    resource: { type: "merchant_checkout", id: "checkout_1" },
    parameters: { amount: 320, currency: "USD", merchant: "vendor-a" },
    context: {},
    ...overrides
  };
}

// --- Normalization ---------------------------------------------------------

test("valid envelope normalizes into a schema_version 1.0 request", () => {
  const n = normalizeExecutionEnvelope(validEnvelope());
  assert.equal(n.ok, true);
  assert.equal(n.request.schema_version, "1.0");
  assert.equal(n.request.tool.tool_name, "payments.purchase");
  assert.equal(n.request.tool.namespace, "payments");
  assert.equal(n.request.tool.operation, "purchase");
  // Spread to a normal-prototype object before comparing: normalized free-form
  // objects are null-prototype by design (see the prototype-safety tests below).
  assert.deepEqual({ ...n.request.context.resource }, { type: "merchant_checkout", id: "checkout_1" });
  assert.equal(n.request.principal.id, "agent://acme/purchasing");
});

test("valid envelope ALLOWs under a matching policy", () => {
  const res = decideFromEnvelope(validEnvelope(), policy);
  assert.equal(res.envelope_ok, true);
  assert.equal(res.decision, "ALLOW");
  assert.equal(res.reason_code, "OK_ALLOW");
});

// --- Adapter equivalence (the core M1 property) ----------------------------

test("two adapters for the same execution produce a byte-identical request", () => {
  const mcpEnv = mcpToolCallToEnvelope({
    id: RID,
    ts: TS,
    name: "payments.purchase",
    arguments: { amount: 320, currency: "USD", merchant: "vendor-a" },
    principal: { id: "agent://acme/purchasing", type: "agent" },
    resource: { type: "merchant_checkout", id: "checkout_1" }
  });
  const httpEnv = httpJsonToEnvelope({
    request_id: RID,
    requested_at: TS,
    actor: { id: "agent://acme/purchasing", kind: "agent" },
    operation: { domain: "payments", name: "purchase" },
    target: { type: "merchant_checkout", id: "checkout_1" },
    payload: { amount: 320, currency: "USD", merchant: "vendor-a" }
  });

  const a = normalizeExecutionEnvelope(mcpEnv);
  const b = normalizeExecutionEnvelope(httpEnv);
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  assert.equal(canonicalizeJson(a.request), canonicalizeJson(b.request), "normalized requests must be canonically identical");

  const da = decideFromEnvelope(mcpEnv, policy);
  const db = decideFromEnvelope(httpEnv, policy);
  assert.equal(da.decision, db.decision);
  assert.equal(da.reason_code, db.reason_code);
  assert.equal(da.decision_hash, db.decision_hash, "identical semantic execution -> identical decision_hash");
  assert.equal(da.decision, "ALLOW");
});

test("same action via two adapters gets the same treatment even with different request ids", () => {
  const mcpEnv = mcpToolCallToEnvelope({
    id: "mcp-1",
    ts: TS,
    name: "payments.purchase",
    arguments: { amount: 320, currency: "USD", merchant: "vendor-a" },
    principal: { id: "agent://acme/purchasing", type: "agent" },
    resource: { type: "merchant_checkout", id: "checkout_1" }
  });
  const httpEnv = httpJsonToEnvelope({
    request_id: "http-1",
    requested_at: TS,
    actor: { id: "agent://acme/purchasing", kind: "agent" },
    operation: { domain: "payments", name: "purchase" },
    target: { type: "merchant_checkout", id: "checkout_1" },
    payload: { amount: 320, currency: "USD", merchant: "vendor-a" }
  });
  const da = decideFromEnvelope(mcpEnv, policy);
  const db = decideFromEnvelope(httpEnv, policy);
  assert.equal(da.decision, db.decision);
  assert.equal(da.reason_code, db.reason_code);
  assert.notEqual(da.decision_hash, db.decision_hash, "different request ids -> different decision_hash (identity is bound in)");
});

// --- Review checkpoint: derived fields + input immutability ----------------

test("caller-supplied context cannot shadow derived identity/action/resource", () => {
  const env = validEnvelope({
    resource: { type: "merchant_checkout", id: "real" },
    context: {
      resource: { type: "spoof", id: "spoof" },
      tool: { tool_name: "spoofed" },
      principal: { id: "spoof" }
    }
  });
  const n = normalizeExecutionEnvelope(env);
  assert.equal(n.ok, true);
  // Derived fields come from their own envelope fields, never from context:
  assert.equal(n.request.tool.tool_name, "payments.purchase");
  assert.equal(n.request.principal.id, "agent://acme/purchasing");
  assert.deepEqual({ ...n.request.context.resource }, { type: "merchant_checkout", id: "real" });
  // The caller's context extras survive as inert context.* keys (different attribute
  // paths than the derived roots), proving they never overwrote the derived fields:
  assert.equal(n.request.context.tool.tool_name, "spoofed");
  assert.equal(n.request.context.principal.id, "spoof");
});

test("normalization does not mutate the input envelope", () => {
  const env = validEnvelope({ authority: [{ authority_id: "g" }], nonce: "n-1", expires_at: TS });
  const before = structuredClone(env);
  normalizeExecutionEnvelope(env);
  assert.deepEqual(env, before);
});

// --- Security hardening: prototype pollution / dangerous keys --------------
// `parameters` and `context` are free-form untrusted input. These payloads are built
// from RAW JSON strings so that keys like "__proto__" are genuine own data
// properties (exactly how JSON.parse materializes them on the wire).

function envWithRawJson(field, rawJson) {
  return validEnvelope({ [field]: JSON.parse(rawJson) });
}

for (const [label, field, rawJson] of [
  ["__proto__ in parameters", "parameters", '{"amount": 1, "__proto__": {"polluted": true}}'],
  ["__proto__ nested deep in context", "context", '{"a": {"b": {"__proto__": {"polluted": true}}}}'],
  ["constructor in parameters", "parameters", '{"constructor": {"x": 1}}'],
  ["prototype in context", "context", '{"prototype": {"x": 1}}'],
  ["__proto__ in principal", "principal", '{"id": "p", "__proto__": {"polluted": true}}']
]) {
  test(`fail closed on dangerous key: ${label}`, () => {
    const env = envWithRawJson(field, rawJson);
    assert.equal(validateExecutionEnvelope(env), ENVELOPE_REASONS.MALFORMED);
    const n = normalizeExecutionEnvelope(env);
    assert.equal(n.ok, false);
    assert.equal(n.reason, ENVELOPE_REASONS.MALFORMED);
    const res = decideFromEnvelope(env, policy);
    assert.equal(res.decision, "REFUSE"); // MUST NOT be ALLOW
    assert.equal(res.envelope_ok, false);
    assert.equal(res.envelope_reason, ENVELOPE_REASONS.MALFORMED);
  });
}

test("dangerous-key payloads never pollute Object.prototype", () => {
  // Drive the rejection paths, then confirm no attacker-controlled inherited
  // property exists on the global prototype afterwards.
  decideFromEnvelope(envWithRawJson("parameters", '{"__proto__": {"polluted": true}}'), policy);
  decideFromEnvelope(envWithRawJson("context", '{"a": {"__proto__": {"polluted": true}}}'), policy);
  normalizeExecutionEnvelope(envWithRawJson("principal", '{"id": "p", "__proto__": {"polluted": true}}'));
  assert.equal(({}).polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
});

test("normalized free-form objects are prototype-safe (null prototype)", () => {
  const n = normalizeExecutionEnvelope(validEnvelope());
  assert.equal(Object.getPrototypeOf(n.request.parameters), null);
  assert.equal(Object.getPrototypeOf(n.request.context), null);
  assert.equal(Object.getPrototypeOf(n.request.principal), null);
  assert.equal(Object.getPrototypeOf(n.request.tool), null);
});

test("no inherited property can satisfy a policy `exists` match", () => {
  // On an ORDINARY object an inherited method name IS visible to `in`...
  assert.equal("hasOwnProperty" in {}, true);
  // ...but the normalized request's free-form objects are null-prototype, so a
  // policy keyed off an inherited name matches nothing and fails closed.
  const inheritedPolicy = {
    schema_version: "1.0", policy_id: "p_inherit", version: "0.1.0", state: "ACTIVE",
    rules: [{
      rule_id: "allow_if_inherited",
      effect: "ALLOW",
      match: { all: [{ field: "parameters.hasOwnProperty", op: "exists" }] }
    }],
    limits: { max_depth: 8 }
  };
  const res = decideFromEnvelope(validEnvelope(), inheritedPolicy);
  assert.equal(res.decision, "REFUSE");
  assert.equal(res.reason_code, "NO_MATCHING_RULE");
});

// --- Fail closed on malformed / incomplete input ---------------------------

const malformed = [
  ["missing schema", (() => { const e = validEnvelope(); delete e.schema; return e; })(), ENVELOPE_REASONS.SCHEMA_UNSUPPORTED],
  ["wrong schema", validEnvelope({ schema: "something.else" }), ENVELOPE_REASONS.SCHEMA_UNSUPPORTED],
  ["unknown top-level key", validEnvelope({ extra: 1 }), ENVELOPE_REASONS.MALFORMED],
  ["non-object envelope", "nope", ENVELOPE_REASONS.MALFORMED],
  ["missing request_id", (() => { const e = validEnvelope(); delete e.request_id; return e; })(), ENVELOPE_REASONS.MALFORMED],
  ["bad timestamp", validEnvelope({ timestamp: "not-a-time" }), ENVELOPE_REASONS.MALFORMED],
  ["missing principal.id", validEnvelope({ principal: { type: "agent" } }), ENVELOPE_REASONS.MALFORMED],
  ["empty principal.type", validEnvelope({ principal: { id: "x", type: "" } }), ENVELOPE_REASONS.MALFORMED],
  ["missing action.operation", validEnvelope({ action: { namespace: "payments" } }), ENVELOPE_REASONS.MALFORMED],
  ["dotted action token (collision guard)", validEnvelope({ action: { namespace: "a.b", operation: "c" } }), ENVELOPE_REASONS.MALFORMED],
  ["parameters not object", validEnvelope({ parameters: [] }), ENVELOPE_REASONS.MALFORMED],
  ["context not object", validEnvelope({ context: "x" }), ENVELOPE_REASONS.MALFORMED],
  ["resource missing id", validEnvelope({ resource: { type: "merchant_checkout" } }), ENVELOPE_REASONS.MALFORMED],
  ["authority not array", validEnvelope({ authority: {} }), ENVELOPE_REASONS.MALFORMED],
  ["empty nonce", validEnvelope({ nonce: "" }), ENVELOPE_REASONS.MALFORMED],
  ["bad expires_at", validEnvelope({ expires_at: "soon" }), ENVELOPE_REASONS.MALFORMED]
];

for (const [label, envelope, expectedReason] of malformed) {
  test(`fail closed: ${label}`, () => {
    assert.equal(validateExecutionEnvelope(envelope), expectedReason);
    const n = normalizeExecutionEnvelope(envelope);
    assert.equal(n.ok, false);
    assert.equal(n.reason, expectedReason);
    assert.equal(n.request, undefined, "no partial request is ever produced");
  });
}

test("decideFromEnvelope on a malformed envelope REFUSES through the engine", () => {
  const e = validEnvelope();
  delete e.schema;
  const res = decideFromEnvelope(e, policy);
  assert.equal(res.envelope_ok, false);
  assert.equal(res.envelope_reason, ENVELOPE_REASONS.SCHEMA_UNSUPPORTED);
  assert.equal(res.decision, "REFUSE");
});

test("a rejected envelope that also looks like a native request still REFUSES (no fail-open)", () => {
  // This object FAILS envelope validation (unknown top-level key `schema_version`,
  // plus `tool`), yet it is simultaneously a well-formed NATIVE policy-engine
  // request that a matching policy would ALLOW. decideFromEnvelope must NOT hand it
  // to the engine as-is; it must fail closed.
  const hybrid = {
    schema: EXECUTION_ENVELOPE_SCHEMA,
    schema_version: "1.0",
    request_id: "hybrid-1",
    timestamp: TS,
    principal: { id: "attacker" },
    agent: { id: "attacker" },
    tool: { tool_name: "payments.purchase" },
    parameters: { currency: "USD" },
    environment: {},
    context: { resource: { type: "merchant_checkout", id: "checkout_1" } }
  };
  assert.equal(normalizeExecutionEnvelope(hybrid).ok, false);
  const res = decideFromEnvelope(hybrid, policy);
  assert.equal(res.envelope_ok, false);
  assert.equal(res.envelope_reason, ENVELOPE_REASONS.MALFORMED);
  assert.equal(res.decision, "REFUSE"); // MUST NOT be ALLOW
});

test("non-integer number in parameters fails closed at the engine", () => {
  const res = decideFromEnvelope(validEnvelope({ parameters: { amount: 3.5, currency: "USD" } }), policy);
  assert.equal(res.envelope_ok, true); // structurally valid envelope...
  assert.equal(res.decision, "REFUSE"); // ...but the integer-only number model refuses it
  assert.equal(res.reason_code, "NON_INTEGER_NUMBER");
});

test("refund action maps and is REFUSED by policy", () => {
  const res = decideFromEnvelope(validEnvelope({ action: { namespace: "payments", operation: "refund" } }), policy);
  assert.equal(res.envelope_ok, true);
  assert.equal(res.decision, "REFUSE");
  assert.equal(res.reason_code, "RULE_REFUSE");
});

// --- M1 non-goals hold -----------------------------------------------------

test("authorities pass through unchanged; absent means empty array (never wildcard)", () => {
  const withAuth = normalizeExecutionEnvelope(validEnvelope({ authority: [{ authority_id: "grant-x" }] }));
  assert.deepEqual(withAuth.authorities, [{ authority_id: "grant-x" }]);
  const withoutAuth = normalizeExecutionEnvelope(validEnvelope());
  assert.deepEqual(withoutAuth.authorities, []);
});

test("nonce/expires_at are carried as metadata but NOT enforced in M1", () => {
  const past = "2000-01-01T00:00:00.000Z";
  const n = normalizeExecutionEnvelope(validEnvelope({ nonce: "n-123", expires_at: past }));
  assert.equal(n.meta.nonce, "n-123");
  assert.equal(n.meta.expires_at, past);
  // An already-expired envelope still ALLOWs, proving expiry is not a decision input yet.
  const res = decideFromEnvelope(validEnvelope({ nonce: "n-123", expires_at: past }), policy);
  assert.equal(res.decision, "ALLOW");
});

// --- Backward compatibility (the engine is untouched) ----------------------

test("existing native policy-engine request format still evaluates unchanged", () => {
  const nativeRequest = {
    schema_version: "1.0",
    request_id: "native-1",
    timestamp: TS,
    principal: { id: "agent://acme/purchasing" },
    agent: { id: "agent://acme/purchasing" },
    tool: { tool_name: "payments.purchase" },
    parameters: { currency: "USD" },
    environment: {},
    context: { resource: { type: "merchant_checkout", id: "checkout_1" } }
  };
  const res = evaluatePolicyRequest(nativeRequest, policy, {});
  assert.equal(res.decision, "ALLOW");
  assert.equal(res.reason_code, "OK_ALLOW");
});

const passed = results.filter(Boolean).length;
const total = results.length;
console.log(`\n${passed === total ? "PASS" : "FAIL"} execution-envelope (${passed}/${total})`);
process.exit(passed === total ? 0 : 1);
