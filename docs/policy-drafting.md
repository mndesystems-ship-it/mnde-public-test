# Policy Drafting

Policy drafting gives a starting point after onboarding discovers tools. It is intentionally conservative and never activates a policy.

## Output

`mnde init --apply` writes:

```text
policy.draft.json
```

The draft uses schema:

```text
mnde.policy.draft.v1
```

The draft includes:

- discovered clients
- discovered servers
- tool categories
- recommended decisions
- review notes
- `default_decision: REFUSE`
- `review_required: true`

## Categories

Policy drafting classifies discovered tools into simple categories:

- read-only actions are suggested as `ALLOW`
- mutating actions are suggested as `APPROVAL_REQUIRED`
- destructive actions are suggested as `REFUSE`
- unknown actions are suggested as `REFUSE`

The classification is deterministic and based on tool names, descriptions, and capability hints.

## What The Draft Is For

The draft is for human review. It helps an evaluator understand what MNDe found and what an initial policy might look like.

## What The Draft Is Not

The draft is not an active production policy.

It does not:

- change sidecar policy
- activate authority
- grant approval rights
- prove a tool is safe
- override MNDe decisions

## Production Use

Before production use, an operator should replace the generated draft with an organization-specific policy reviewed by the people responsible for the systems being protected.

The draft exists to reduce blank-page setup work, not to make authority decisions on its own.
