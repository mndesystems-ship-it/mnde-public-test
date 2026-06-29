# MNDe Canonical Number Model (frozen for v1)

MNDe's canonical JSON form — the bytes that are hashed and signed — supports
**integers only**. This is a deliberate, frozen part of the v1 contract: it keeps
canonicalization deterministic across languages and runtimes and avoids the
ambiguity of floating-point serialization in signed artifacts.

## The rule

A canonical JSON number MUST be a safe integer:

- range: `-(2^53 - 1)` … `2^53 - 1` (`Number.isSafeInteger`)
- no fractional part, no exponent, no `NaN`/`Infinity`
- `-0` canonicalizes to `0`

Any other number is rejected. This is enforced in two places, both fail-closed:

1. **Wire boundary** — `shared/json.ts` `parseStrictJson` rejects a non-integer
   number while parsing a request body. The sidecar surfaces it as
   `ERR_INVALID_JSON_NUMBER` (`mnde-local-sidecar.mjs`), before any engine runs.
2. **Library / SDK boundary** — the policy engine (`src/policy-engine/index.mjs`,
   `evaluatePolicyRequest`) refuses a request or policy that contains a non-integer
   number with the distinct reason `NON_INTEGER_NUMBER`, rather than conflating it
   with a generic shape error. Receipts are unaffected (a non-integer request is
   not representable in canonical form and therefore never produces a receipt).

`canonicalizeJson` itself throws on a non-safe-integer; the checks above sit
**above** it so callers get a clear, typed refusal instead of an opaque throw.

## How to represent decimals

Because canonical numbers are integers, represent any decimal value as one of:

- **Scaled integer** — carry the value in its smallest unit. Example: money in
  cents (`"amount_cents": 1099` for `$10.99`); a ratio in basis points
  (`"rate_bps": 125` for `1.25%`); a probability in parts-per-million.
  *Prefer this* when you will compare or threshold the value in a policy rule.
- **String** — carry the exact decimal text (`"amount": "10.99"`,
  `"temperature": "0.7"`). Use this when the value is opaque to policy logic and
  only needs to be recorded/matched exactly.

Do **not** send raw floating-point numbers in a decision request or policy.

## Why not just add float canonicalization?

Deterministic cross-platform float serialization is a known hazard for signed
artifacts (rounding, shortest-round-trip differences, locale). Adding it would
change every hash and the frozen conformance vectors, and would weaken the
cross-language verification guarantee. v1 therefore freezes the integer-only
model; a future deterministic decimal type, if ever added, would be a versioned,
vector-gated change — never a casual float.

## Conformance

This model is unchanged by the v1 freeze work: `canonicalizeJson` bytes are
untouched, so `npm run test:conformance` vectors remain byte-identical. The
hardening above only makes the *rejection reason* distinct; it does not change
what is accepted.
