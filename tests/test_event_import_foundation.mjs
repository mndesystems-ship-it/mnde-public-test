#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  importedExecutionId,
  normalizeImportedEvent
} from "../src/event-import/index.mjs";
import { evaluateExecutionGate } from "../src/execution-gate/index.mjs";
import { validateExecutionRequest } from "../src/execution-gate/schema.mjs";
import {
  _resetInProcessCacheForTest,
  reserveExecutionId
} from "../sidecar/execution_id_store.mjs";

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

function sourceEvent(overrides = {}) {
  const base = {
    source_type: "github",
    source_event_id: "evt-001",
    occurred_at: "2026-08-08T16:00:00Z",
    actor: {
      id: "andrew",
      type: "github_actor",
      issuer: "github"
    },
    action: {
      type: "deploy",
      name: "deploy-api",
      command: "deploy --service api"
    },
    resource: {
      kind: "service",
      id: "api",
      name: "API",
      owner: "platform"
    },
    environment: "production",
    evidence: {
      repo: "mndesystems-ship-it/mnde-public-test",
      commit_sha: "abc123",
      branch: "main"
    }
  };
  return { ...base, ...overrides };
}

console.log("MNDe generic event import foundation\n");

await test("normalizes a generic event into a valid execution request", () => {
  const normalized = normalizeImportedEvent(sourceEvent());
  assert.equal(normalized.schema_version, "mnde.execution_request.v1");
  assert.match(normalized.execution_id, /^import-[a-f0-9]{64}$/);
  assert.equal(normalized.requested_at, "2026-08-08T16:00:00Z");
  assert.equal(normalized.action.command, "deploy --service api");
  assert.equal(normalized.resource.owner, "platform");
  const validation = validateExecutionRequest(normalized);
  assert.equal(validation.ok, true, validation.errors?.join(", "));
});

await test("execution IDs are stable, unambiguous, and accepted by durable replay protection", () => {
  assert.equal(importedExecutionId("github", "evt-001"), importedExecutionId("github", "evt-001"));
  assert.notEqual(importedExecutionId("a-b", "c"), importedExecutionId("a", "b-c"));

  const dir = mkdtempSync(join(tmpdir(), "mnde-event-import-id-"));
  process.env.MNDE_EXEC_ID_CACHE = dir;
  _resetInProcessCacheForTest();
  try {
    const id = importedExecutionId("github", "evt-001");
    assert.equal(reserveExecutionId(id), true, "first imported event must reserve successfully");
    assert.equal(reserveExecutionId(id), false, "the same imported event must be refused as a replay");
  } finally {
    delete process.env.MNDE_EXEC_ID_CACHE;
    _resetInProcessCacheForTest();
    rmSync(dir, { recursive: true, force: true });
  }
});

await test("unclassified imported security attributes default fail closed", () => {
  const hostileSource = sourceEvent({
    risk: { level: "low", destructive: false },
    approval: { required: false, approval_id: "attacker-controlled" }
  });
  hostileSource.actor.verified = true;
  hostileSource.actor.claims = { role: "admin" };
  const normalized = normalizeImportedEvent(hostileSource);
  assert.equal(normalized.principal.verified, false);
  assert.deepEqual(normalized.principal.claims, {});
  assert.deepEqual(normalized.risk, {
    level: "critical",
    destructive: true,
    reversible: false,
    touches_secrets: true,
    touches_customer_data: true,
    blast_radius: "global"
  });
  assert.equal(normalized.cost.estimated_cents, Number.MAX_SAFE_INTEGER);
  assert.deepEqual(normalized.approval, { required: true });

  const unverified = evaluateExecutionGate(normalized);
  assert.equal(unverified.ok, true);
  assert.equal(unverified.receipt.decision, "REFUSE");
  assert.equal(unverified.receipt.refusal_reason, "PRINCIPAL_NOT_VERIFIED");

  const identityVerified = structuredClone(normalized);
  identityVerified.principal.verified = true;
  const stillUnclassified = evaluateExecutionGate(identityVerified);
  assert.equal(stillUnclassified.ok, true);
  assert.equal(stillUnclassified.receipt.decision, "REFUSE");
  assert.equal(stillUnclassified.receipt.refusal_reason, "APPROVAL_REQUIRED");
});

await test("malformed source shapes fail before normalization", () => {
  assert.throws(() => normalizeImportedEvent(null), /source must be an object/);
  assert.throws(() => normalizeImportedEvent(sourceEvent({ actor: null })), /actor must be an object/);
  assert.throws(() => normalizeImportedEvent(sourceEvent({ source_event_id: "" })), /source_event_id must be a non-empty string/);
});

await test("unsupported execution-gate values fail during normalization", () => {
  assert.throws(
    () => normalizeImportedEvent(sourceEvent({ environment: "moon" })),
    /environment\.name must be one of/
  );
  assert.throws(
    () => normalizeImportedEvent(sourceEvent({ action: { type: "destroy", name: "bad" } })),
    /action\.type must be one of/
  );
});

const passed = results.filter(Boolean).length;
const failed = results.length - passed;

console.log(`\n${passed} passed, ${failed} failed`);

if (failed > 0) process.exit(1);
