import { REASON_CODES, budgetTokenStore, executionAuthorityStore, type ArmTrace, type CanonicalExecutionInput, type OrbitTrace } from "../shared/index.ts";

function multiplyChecked(left: number, right: number): number | null {
  const result = left * right;
  if (!Number.isSafeInteger(result)) {
    return null;
  }
  return result;
}

function projectedCost(input: CanonicalExecutionInput): number | null {
  const execution = input.execution_request.execution;
  const resources = input.execution_request.resources;
  const base = multiplyChecked(resources.gpu_count, resources.hours);
  if (base === null) {
    return null;
  }
  const priced = multiplyChecked(base, input.pricing_data.gpu_hour_cents);
  if (priced === null) {
    return null;
  }
  const scaled = multiplyChecked(priced, execution.auto_scale ? execution.max_scale_multiplier : 1);
  if (scaled === null) {
    return null;
  }
  return multiplyChecked(scaled, execution.retry_on_fail ? execution.max_retries + 1 : 1);
}

export function resetArmStores(): void {
  executionAuthorityStore.reset();
  budgetTokenStore.reset();
}

export function defineBudgetToken(token: string, maxBudgetCents: number): void {
  budgetTokenStore.define(token, maxBudgetCents);
}

export function runStrictArm(input: CanonicalExecutionInput, orbit: OrbitTrace, requestHash: string): ArmTrace {
  const projected = projectedCost(input);
  if (projected === null) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.IntegerOverflow,
      projected_total_cost_cents: 0,
      allowed_cost_cents: 0,
      prevented_cost_cents: 0,
      execution_id: input.execution_request.release_request.execution_id,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }

  const allowedCost = Math.min(projected, input.policy_document.rules.max_total_cost_cents);
  const preventedCost = Math.max(projected - allowedCost, 0);
  const executionId = input.execution_request.release_request.execution_id;
  const beginStatus = executionAuthorityStore.begin(executionId, requestHash);
  if (beginStatus === "inflight_exists") {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.ExecutionIdAlreadyConsumed,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (beginStatus === "allowed_exists") {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.ExecutionIdReplayed,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }

  if (orbit.decision === "REFUSE") {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: orbit.reason_code,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }

  if (input.execution_request.execution.auto_scale && !input.policy_document.rules.allow_auto_scale) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.AutoScaleDenied,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (input.execution_request.resources.gpu_count > input.policy_document.rules.max_gpu_count) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.GpuLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (input.execution_request.resources.hours > input.policy_document.rules.max_hours) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.HoursLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (input.execution_request.execution.max_retries > input.policy_document.rules.max_retry_count) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.RetryLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (projected > input.policy_document.rules.max_total_cost_cents) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.CostLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }

  const budgetToken = input.execution_request.budget_token;
  if (budgetToken !== undefined) {
    const budgetStatus = budgetTokenStore.reserve(budgetToken, projected);
    if (budgetStatus === "exhausted") {
      return {
        layer: "arm",
        decision: "REFUSE",
        reason_code: REASON_CODES.BudgetTokenExhausted,
        projected_total_cost_cents: projected,
        allowed_cost_cents: allowedCost,
        prevented_cost_cents: preventedCost,
        execution_id: executionId,
        budget_token: budgetToken
      };
    }
  }

  return {
    layer: "arm",
    decision: "ALLOW",
    reason_code: REASON_CODES.OkArm,
    projected_total_cost_cents: projected,
    allowed_cost_cents: allowedCost,
    prevented_cost_cents: preventedCost,
    execution_id: executionId,
    ...(budgetToken === undefined ? {} : { budget_token: budgetToken })
  };
}

export function commitArmAllow(executionId: string, requestHash: string, decisionHash: string): void {
  executionAuthorityStore.commitAllow(executionId, requestHash, decisionHash);
}
