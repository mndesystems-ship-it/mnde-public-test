#!/usr/bin/env node

import assert from "node:assert/strict";

import {
normalizeImportedEvent
} from "../src/event-import/index.mjs";

import {
validateExecutionRequest
} from "../src/execution-gate/schema.mjs";

const results = [];

function test(name, fn) {
try {
fn();
results.push(true);
console.log(" [PASS] " + name);
} catch (error) {
results.push(false);
console.log(" [FAIL] " + name + ": " + error.message);
}
}

console.log("MNDe generic event import foundation\n");

test("normalizes a generic GitHub deployment event into mnde.execution_request.v1", () => {
const source = {
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
name: "deploy-api"
},
resource: {
kind: "service",
id: "api",
name: "API"
},
environment: "production",
evidence: {
repo: "mndesystems-ship-it/mnde-public-test",
commit_sha: "abc123",
branch: "main"
}
};

const normalized = normalizeImportedEvent(source);

assert.equal(normalized.schema_version, "mnde.execution_request.v1");
assert.equal(normalized.execution_id, "github:evt-001");
assert.equal(normalized.requested_at, "2026-08-08T16:00:00Z");

const validation = validateExecutionRequest(normalized);
assert.equal(validation.ok, true, validation.errors?.join(", "));
});

const passed = results.filter(Boolean).length;
const failed = results.length - passed;

console.log("\n" + passed + " passed, " + failed + " failed");

if (failed > 0) process.exit(1);
