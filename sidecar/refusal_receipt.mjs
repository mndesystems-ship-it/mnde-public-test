import { createHash, createHmac } from "node:crypto";
import {
  RECEIPT_PUBLIC_KEY_FINGERPRINT,
  RECEIPT_PUBLIC_KEY_PEM,
  RECEIPT_SIGNATURE_ALGORITHM,
  RECEIPT_SIGNATURE_KEY_ID,
  canonicalizeJson,
  signReceiptPayload
} from "../shared/index.ts";

const SIGNING_SECRET = "ecs-prod-signing-secret-v2";
const SIGNING_KEY_ID = "ecs-prod-key-v2";
const RECEIPT_KEY_SET_VERSION = "receipt-key-set-v1";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseBoundaryDecisionHash(requestHash, reasonCode) {
  return sha256(canonicalizeJson({
    request_hash: requestHash,
    decision: "REFUSE",
    reason_code: reasonCode
  }));
}

function signPayload(payload) {
  const canonicalPayload = canonicalizeJson(payload);
  return {
    ...payload,
    signature: {
      algorithm: "HMAC-SHA256",
      key_id: SIGNING_KEY_ID,
      value: createHmac("sha256", SIGNING_SECRET).update(canonicalPayload).digest("hex")
    },
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      key_id: RECEIPT_SIGNATURE_KEY_ID,
      public_key_fingerprint: RECEIPT_PUBLIC_KEY_FINGERPRINT,
      public_key_pem: RECEIPT_PUBLIC_KEY_PEM,
      value: signReceiptPayload(canonicalPayload)
    }
  };
}

function safeTimingSnapshot(timings) {
  const safe = {};
  for (const [key, value] of Object.entries(timings ?? {})) {
    if (typeof value === "number" && Number.isFinite(value)) {
      safe[key] = Math.max(0, Math.round(value));
    }
  }
  return safe;
}

export function buildSidecarRefusalReceipt({
  raw_body = "",
  reason_code,
  policy_hash,
  policy_version,
  timings = {},
  request_id = null,
  request_hash = null,
  decision_hash = null
}) {
  const safeTimings = safeTimingSnapshot(timings);
  const canonicalRequest = canonicalizeJson({
    sidecar_refusal: reason_code,
    request_id,
    raw_body_sha256: typeof raw_body === "string" && raw_body.length > 0 ? sha256(raw_body) : null,
    raw_body_bytes: typeof raw_body === "string" ? Buffer.byteLength(raw_body, "utf8") : 0
  });
  const resolvedRequestHash = sha256(canonicalRequest);
  const resolvedDecisionHash = parseBoundaryDecisionHash(resolvedRequestHash, reason_code);
  const payload = {
    schema_version: "ecs.receipt.v2",
    canonical_request: canonicalRequest,
    request_hash: resolvedRequestHash,
    decision_output: {
      decision: "REFUSE",
      decision_hash: resolvedDecisionHash,
      request_hash: resolvedRequestHash,
      reason_code,
      total_cost_usd: "0.00",
      allowed_cost_usd: "0.00",
      prevented_cost_usd: "0.00",
      policy_version,
      policy_hash,
      execution_id: request_id ?? "sidecar-refusal",
      key_set_version: RECEIPT_KEY_SET_VERSION
    },
    pipeline_trace: {
      preflight: {
        layer: "preflight",
        request_hash: resolvedRequestHash,
        policy_hash,
        policy_version
      },
      orbit: {
        layer: "orbit",
        decision: "REFUSE",
        reason_code,
        validation_hash: sha256(canonicalizeJson({ reason_code, timings: safeTimings }))
      },
      arm: {
        layer: "arm",
        decision: "REFUSE",
        reason_code,
        projected_total_cost_cents: 0,
        allowed_cost_cents: 0,
        prevented_cost_cents: 0,
        execution_id: request_id ?? "sidecar-refusal"
      },
      ramona: {
        layer: "ramona",
        decision: "REFUSE",
        reason_code,
        runtime_hash: sha256(canonicalizeJson({ sidecar_refusal: reason_code }))
      }
    }
  };
  return signPayload(payload);
}
