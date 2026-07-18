// Schema adapters: normalize any known receipt shape into one flat envelope
// for indexing. Extraction is best-effort and never throws — a field that
// cannot be read is null. Extraction feeds the UNTRUSTED index only; nothing
// here participates in verification.

const HEX64 = /^[0-9a-f]{64}$/;

export const KNOWN_SCHEMAS = [
  "mnde.pe.receipt.v1",
  "ecs.receipt.v2",
  "mnde.execution_gate.receipt.v1",
  "mnde.receipt.v2_5",
  "mnde.signed-receipt.v1"
];

function str(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function hex64(value) {
  return typeof value === "string" && HEX64.test(value) ? value : null;
}

function int(value) {
  return Number.isSafeInteger(value) ? value : null;
}

function parseCanonicalRequest(receipt) {
  if (typeof receipt?.canonical_request !== "string") return null;
  try {
    return JSON.parse(receipt.canonical_request);
  } catch {
    return null;
  }
}

function toolsOf(toolCalls) {
  if (!Array.isArray(toolCalls)) return [];
  return toolCalls.map((call) => str(call?.tool)).filter((tool) => tool !== null);
}

function emptyEnvelope() {
  return {
    schema_version: null,
    request_hash: null,
    request_id: null,
    decision: null,
    reason_code: null,
    tenant_id: null,
    actor: null,
    tools: [],
    region: null,
    policy_hash: null,
    policy_version: null,
    key_id: null,
    timestamp: null,
    cost_micro_usd: null
  };
}

function extractPolicyEngineV1(receipt, envelope) {
  const decisionOutput = receipt.decision_output ?? {};
  envelope.decision = str(decisionOutput.decision);
  envelope.reason_code = str(decisionOutput.reason_code) ?? str(decisionOutput.reason);
  envelope.timestamp = str(decisionOutput.timestamp) ?? str(decisionOutput.decided_at);
  const request = parseCanonicalRequest(receipt);
  if (request) {
    envelope.request_id = str(request.request_id);
    envelope.actor = str(request.principal?.id) ?? str(request.actor?.user_id);
    envelope.tools = request.tool?.tool_name ? [request.tool.tool_name] : toolsOf(request.tool_calls);
    envelope.region = str(request.environment?.region) ?? str(request.submitted_region);
    envelope.timestamp = envelope.timestamp ?? str(request.timestamp);
  }
  envelope.key_id = str(receipt.verifiable_signature?.key_id);
}

function extractEcsV2(receipt, envelope) {
  const decisionOutput = receipt.decision_output ?? {};
  envelope.decision = str(decisionOutput.decision);
  envelope.reason_code = str(decisionOutput.reason_code) ?? str(decisionOutput.reason);
  envelope.timestamp = str(decisionOutput.timestamp) ?? str(decisionOutput.decided_at);
  const request = parseCanonicalRequest(receipt);
  const executionRequest = request?.execution_request ?? request;
  if (executionRequest) {
    envelope.request_id = str(executionRequest.request_id);
    envelope.actor = str(executionRequest.actor?.user_id);
    envelope.tools = toolsOf(executionRequest.tool_calls);
    envelope.region = str(executionRequest.submitted_region);
  }
  envelope.key_id = str(receipt.verifiable_signature?.key_id);
}

function extractExecutionGateV1(receipt, envelope) {
  envelope.request_id = str(receipt.execution_id);
  envelope.decision = str(receipt.decision);
  envelope.reason_code = str(receipt.reason_code) ?? str(receipt.risk?.reason_code);
  envelope.timestamp = str(receipt.decided_at);
  envelope.actor = str(receipt.principal?.id) ?? str(receipt.principal);
  envelope.tools = receipt.action ? [str(receipt.action?.name) ?? str(receipt.action)].filter(Boolean) : [];
  envelope.region = str(receipt.environment?.region);
  envelope.key_id = str(receipt.signing_key_id) ?? str(receipt.verifiable_signature?.key_id);
}

function extractCustodyV25(receipt, envelope) {
  envelope.tenant_id = str(receipt.tenant_id);
  envelope.decision = str(receipt.decision);
  envelope.reason_code = str(receipt.reason_code);
  envelope.timestamp = str(receipt.timestamp);
  envelope.policy_version = str(receipt.policy_version);
  envelope.key_id = str(receipt.key_id);
  envelope.cost_micro_usd = int(receipt.projected_cost_micro_usd);
}

// Normalize one parsed receipt into the flat index envelope.
export function extractEnvelope(receipt) {
  const envelope = emptyEnvelope();
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) return envelope;

  envelope.schema_version = str(receipt.schema_version);
  envelope.request_hash = hex64(receipt.request_hash);
  envelope.policy_hash = hex64(receipt.policy_hash);

  switch (envelope.schema_version) {
    case "mnde.pe.receipt.v1":
      extractPolicyEngineV1(receipt, envelope);
      break;
    case "ecs.receipt.v2":
      extractEcsV2(receipt, envelope);
      break;
    case "mnde.execution_gate.receipt.v1":
      extractExecutionGateV1(receipt, envelope);
      break;
    case "mnde.receipt.v2_5":
      extractCustodyV25(receipt, envelope);
      break;
    case "mnde.signed-receipt.v1": {
      // Custody attestation envelope: index the inner receipt's fields.
      const inner = extractEnvelope(receipt.receipt);
      inner.schema_version = envelope.schema_version;
      inner.request_hash = inner.request_hash ?? envelope.request_hash;
      return inner;
    }
    default:
      // Unknown schema: envelope-only fields extracted above. The finder
      // reports these as UNVERIFIABLE(schema_unknown); they are never dropped.
      envelope.decision = str(receipt.decision);
      envelope.reason_code = str(receipt.reason_code);
      envelope.timestamp = str(receipt.timestamp);
      break;
  }
  return envelope;
}

export function isKnownSchema(schemaVersion) {
  return KNOWN_SCHEMAS.includes(schemaVersion);
}
