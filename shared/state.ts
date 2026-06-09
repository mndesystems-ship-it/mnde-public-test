export type ExecutionAuthorityState = {
  execution_id: string;
  status: "inflight" | "allowed";
  request_hash: string;
  decision_hash?: string;
};

export type BudgetTokenState = {
  budget_token: string;
  max_budget_cents: number;
  consumed_cents: number;
};

export interface ExecutionAuthorityStore {
  begin(executionId: string, requestHash: string): "created" | "inflight_exists" | "allowed_exists";
  commitAllow(executionId: string, requestHash: string, decisionHash: string): void;
  snapshot(): ExecutionAuthorityState[];
  reset(): void;
}

export interface BudgetTokenStore {
  define(token: string, maxBudgetCents: number): void;
  reserve(token: string, projectedCostCents: number): "reserved" | "exhausted";
  snapshot(): BudgetTokenState[];
  reset(): void;
}

class InMemoryExecutionAuthorityStore implements ExecutionAuthorityStore {
  private readonly records = new Map<string, ExecutionAuthorityState>();

  begin(executionId: string, requestHash: string): "created" | "inflight_exists" | "allowed_exists" {
    const existing = this.records.get(executionId);
    if (!existing) {
      this.records.set(executionId, {
        execution_id: executionId,
        status: "inflight",
        request_hash: requestHash
      });
      return "created";
    }
    return existing.status === "allowed" ? "allowed_exists" : "inflight_exists";
  }

  commitAllow(executionId: string, requestHash: string, decisionHash: string): void {
    this.records.set(executionId, {
      execution_id: executionId,
      status: "allowed",
      request_hash: requestHash,
      decision_hash: decisionHash
    });
  }

  snapshot(): ExecutionAuthorityState[] {
    return [...this.records.values()];
  }

  reset(): void {
    this.records.clear();
  }
}

class InMemoryBudgetTokenStore implements BudgetTokenStore {
  private readonly records = new Map<string, BudgetTokenState>();

  define(token: string, maxBudgetCents: number): void {
    this.records.set(token, {
      budget_token: token,
      max_budget_cents: maxBudgetCents,
      consumed_cents: 0
    });
  }

  reserve(token: string, projectedCostCents: number): "reserved" | "exhausted" {
    const existing = this.records.get(token);
    if (!existing) {
      return "exhausted";
    }
    if (existing.consumed_cents + projectedCostCents > existing.max_budget_cents) {
      return "exhausted";
    }
    existing.consumed_cents += projectedCostCents;
    this.records.set(token, existing);
    return "reserved";
  }

  snapshot(): BudgetTokenState[] {
    return [...this.records.values()];
  }

  reset(): void {
    this.records.clear();
  }
}

export const executionAuthorityStore = new InMemoryExecutionAuthorityStore();
export const budgetTokenStore = new InMemoryBudgetTokenStore();
