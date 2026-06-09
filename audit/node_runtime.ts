import { createHash } from "crypto";
import { readFileSync } from "fs";
import { performance } from "perf_hooks";
import {
  canonicalizeJson,
  hashCanonicalJson,
  REASON_CODES,
  type CanonicalExecutionInput,
  type JsonValue,
  type ExecutionResult,
  type SignedReceipt,
  type TypedFailure
} from "../shared/index.ts";
import { runStrictPreflight } from "../preflight/engine.ts";
import { runStrictOrbit } from "../orbit/engine.ts";
import { commitArmAllow, defineBudgetToken, resetArmStores, runStrictArm } from "../arm/engine.ts";
import { buildReceipt, runStrictRamona, verifyReceiptReplay, verifyReceiptSignature } from "../ram0na/engine.ts";

export type PipelineTimingKey =
  | "preflight_ms"
  | "orbit_ms"
  | "arm_ms"
  | "ramona_ms"
  | "canonicalize_ms"
  | "receipt_build_ms"
  | "signing_ms";

export type PipelineTimings = Partial<Record<PipelineTimingKey, number>>;
type PipelineOptions = { timings?: PipelineTimings };

function measure<T>(timings: PipelineTimings | undefined, key: PipelineTimingKey, fn: () => T): T {
  const started = performance.now();
  try {
    return fn();
  } finally {
    if (timings) {
      timings[key] = Math.max(0, Math.round(performance.now() - started));
    }
  }
}

function typedFailureFromReceipt(receipt: SignedReceipt): TypedFailure {
  return {
    decision: "REFUSE",
    request_hash: receipt.request_hash,
    decision_hash: receipt.decision_output.decision_hash,
    reason_code: receipt.decision_output.reason_code,
    parse_boundary: true
  };
}

export function executeDeterministicPipeline(rawInput: string, options: PipelineOptions = {}): ExecutionResult | TypedFailure {
  const timings = options.timings;
  const preflight = measure(timings, "preflight_ms", () => runStrictPreflight(rawInput));
  if ("parse_boundary" in preflight) {
    return preflight;
  }

  const preflightTrace = {
    layer: "preflight" as const,
    request_hash: preflight.request_hash,
    policy_hash: preflight.policy_hash,
    policy_version: preflight.parsed_input.policy_document.policy_version
  };
  const orbit = measure(timings, "orbit_ms", () => runStrictOrbit(preflight.parsed_input));
  const arm = measure(timings, "arm_ms", () => runStrictArm(preflight.parsed_input, orbit, preflight.request_hash));
  const ramona = measure(timings, "ramona_ms", () => runStrictRamona(preflight.parsed_input, arm));
  const receipt = measure(timings, "receipt_build_ms", () => buildReceipt({
    canonical_request: preflight.canonical_input,
    request_hash: preflight.request_hash,
    policy_hash: preflight.policy_hash,
    preflight: preflightTrace,
    orbit,
    arm,
    ramona,
    policy_version: preflight.parsed_input.policy_document.policy_version,
    timings
  }));

  if (receipt.decision_output.decision === "ALLOW") {
    commitArmAllow(arm.execution_id, preflight.request_hash, receipt.decision_output.decision_hash);
  }

  return {
    receipt,
    receipt_bytes: measure(timings, "canonicalize_ms", () => canonicalizeJson(receipt as unknown as JsonValue))
  };
}

export function verifySignedReceipt(receipt: SignedReceipt): boolean {
  return verifyReceiptSignature(receipt);
}

export function replayReceiptStore(receiptPath: string): {
  total: number;
  exact_matches: number;
  mismatches: Array<Record<string, string>>;
} {
  const source = readFileSync(receiptPath, "utf8").trim();
  const lines = source.length === 0 ? [] : source.split(/\r?\n/);
  const mismatches: Array<Record<string, string>> = [];
  let exactMatches = 0;

  for (const line of lines) {
    let parsed: SignedReceipt;
    try {
      parsed = JSON.parse(line) as SignedReceipt;
    } catch {
      mismatches.push({ request_hash: "unparseable_receipt", error: REASON_CODES.InvalidJsonSyntax });
      continue;
    }
    if (!verifySignedReceipt(parsed)) {
      mismatches.push({ request_hash: parsed.request_hash, error: REASON_CODES.ReceiptSignatureInvalid });
      continue;
    }

    resetRuntimeState();
    const rerun = executeDeterministicPipeline(parsed.canonical_request);
    if ("parse_boundary" in rerun) {
      mismatches.push({ request_hash: parsed.request_hash, error: rerun.reason_code });
      continue;
    }

    const replay = verifyReceiptReplay(parsed, rerun.receipt);
    if (!replay.ok) {
      mismatches.push({ request_hash: parsed.request_hash, error: replay.reason_code });
      continue;
    }
    exactMatches += 1;
  }

  return {
    total: lines.length,
    exact_matches: exactMatches,
    mismatches
  };
}

export function hashFileArtifact(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function resetRuntimeState(): void {
  resetArmStores();
}

export function seedBudgetToken(token: string, maxBudgetCents: number): void {
  defineBudgetToken(token, maxBudgetCents);
}

export function decisionHashForRawInput(rawInput: string): string {
  return hashCanonicalJson(JSON.parse(rawInput) as JsonValue);
}
