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

## From Draft To Policy

The draft is a starting point, not an active policy. To turn it into one, load it
into the Policy Editor, which converts each recommendation into an editable rule.
The full path:

```text
mnde init --apply            # discovers tools, writes policy.draft.json
  -> open policy-editor/mnde-policy-editor.html
  -> Load draft               # (or Import…) select policy.draft.json
  -> review recommendations   # allow -> ALLOW, approval -> APPROVAL, deny -> REFUSE
  -> edit rules               # tighten conditions, rename rule IDs, add authority
  -> compile                  # editor emits a schema_version "1.0" policy
  -> Download                 # policy.json for MNDE_PE_POLICY (dev/test), or
  -> sign                     # policy-bundle:sign for MNDE_PE_POLICY_BUNDLE (prod)
```

On import the editor is deliberately conservative: `allow` becomes an `ALLOW`
rule, `approval` becomes `APPROVAL`, and `deny` — plus any unclassified or
unrecognized recommendation — becomes `REFUSE`. It never upgrades an unknown
recommendation to `ALLOW`. Servers whose tools were not enumerated
(`tools_enumerated: false`) are skipped, with a notice to re-run discovery with
`--probe` or add those rules by hand.

The imported rules are only the tool recommendations. The draft's own
`default_decision: REFUSE` is not imported as a rule because the engine already
denies by default — every tool you do not explicitly allow is refused.

The same **Load draft** / **Import…** picker also accepts an already-compiled
`schema_version "1.0"` policy or a signed `mnde.policy.bundle.v1` (unwrapped to
its policy document for editing; re-sign before activating).

## Production Use

Before production use, an operator should replace the generated draft with an organization-specific policy reviewed by the people responsible for the systems being protected.

The draft exists to reduce blank-page setup work, not to make authority decisions on its own.
