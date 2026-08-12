# MNDe Production Trust Model

How a production MNDe receipt becomes independently verifiable by a party who
does not trust the operator. This document describes what the repository
**implements today**, what is **proposed**, and what is **not yet published**.
It does not claim any hosted artifact is live.

## The trust chain

```
pinned root fingerprint            (obtained INDEPENDENTLY of the bundle host)
        │  authenticates
        ▼
mnde.authority.bundle.v1           (public artifact; root-signed)
        │  authorizes
        ▼
receipt-role signing key           (operational; listed in the bundle under keys.receipt)
        │  signs
        ▼
mnde.execution_gate.receipt.v1     (the production receipt)
        │  verifies →
        ▼
     VERIFIED
```

Verification is fully offline and cryptographic at every arrow — not field
equality, not key-id matching. Implemented by
[`src/custody/bundle.mjs`](../src/custody/bundle.mjs) (`verifyAuthorityBundle`,
`findBundleKey`, `verifyAgainstBundle`) and
[`src/execution-gate/verify-signed-receipt.mjs`](../src/execution-gate/verify-signed-receipt.mjs)
(`verifySignedExecutionReceipt`, role `receipt`).

## The five roles, kept distinct

1. **Root key** — offline. Its *only* job is to sign authority bundles (and key
   rotations/revocations). It never signs execution receipts. This is the crown
   jewel; it does not live on the serving host.
2. **Receipt role key** — operational. Signs `mnde.execution_gate.receipt.v1`
   receipts. It is authorized *only* by being present, valid, and non-revoked in a
   root-signed bundle under `keys.receipt`. A key valid under any other role
   (`ledger`, `activation`, …) is **not** accepted as a receipt key — role scope
   is enforced by `findBundleKey(bundle, "receipt", …)`.
3. **Authority bundle** — the public artifact. Carries the root public key +
   fingerprint, the role signing public keys with key ids and validity windows,
   the revocation list, `issued_at` / `not_after`, and the root signature. It
   contains **no private material**.
4. **Root fingerprint / trust anchor** — the sha256 of the root public key (DER
   SPKI). A verifier must obtain this **independently of the bundle host** and
   pin it. `verifyAuthorityBundle` refuses a bundle whose root does not match the
   independently-pinned fingerprint (`UNTRUSTED_ROOT`), so a compromised host
   cannot substitute an attacker root.
5. **Bundle host** — a distribution mechanism only. It is **not** the root of
   trust. Compromising it lets an attacker serve a *different* bundle, but not one
   that authenticates against the pinned root without the offline root private key.

## Security invariant

The root authorizes bundles; online role keys perform operational signing.
Compromise of the bundle hosting location **alone** cannot produce a bundle that a
verifier with the correctly pinned root will accept. The verifier fails closed for
every one of: unknown root, wrong root, invalid root signature, malformed bundle,
expired bundle, key-window-not-yet-valid, revoked signing key, wrong signing role,
unknown signing key, invalid receipt signature, malformed receipt, unsupported
schema, and mismatched authority ids. Each case has a regression test in
[`tests/test_phase1_trust_chain.mjs`](../tests/test_phase1_trust_chain.mjs).

## The ceremony (existing tooling — no new trust system)

All of this uses the tools already in the repository. **Run key generation on an
air-gapped machine.**

1. **Generate the root + operational keys and build the first bundle:**
   ```bash
   npm run authority:init -- --out /secure/offline/path --authority-id mnde-systems-production
   ```
   `scripts/init-production-authority.mjs` generates an Ed25519 root plus receipt,
   ledger, and activation keys, builds a root-signed `mnde.authority.bundle.v1`,
   and **verifies it before writing anything**. It refuses to write inside the
   repository, refuses to overwrite, refuses a `local`/`demo` authority id, writes
   private keys `0600`, and prints the **root fingerprint** to pin. The bundle
   validity defaults to **90 days** (`--bundle-days`, decision below).
2. **Move the root private key offline** (`root.key.pem` — the crown jewel; not
   needed on the serving host) and make encrypted offline backups. Keep only the
   receipt (and ledger) private keys on the serving host.
3. **Publish** the public `authority.bundle.json` (see Publication) and pin the
   root fingerprint out of band.
4. **Rotate / revoke** as an offline root operation — the root only re-signs:
   ```bash
   npm run authority -- rotate --bundle b.json --root-key root.key.pem --key-id receipt-2 --generate --new-private-out receipt-2.key.pem --out next.json
   npm run authority -- revoke --bundle b.json --root-key root.key.pem --key-id receipt-1 --out next.json
   ```
   `bin/mnde-authority.mjs` verifies the output before writing and never overwrites
   the input bundle without `--force` (rollback safety). `--new-public` accepts a
   key generated elsewhere, so the root signing step can run on the offline machine
   with no network.
5. **Run the sidecar** against the trust root:
   `MNDE_PROFILE=production`, `MNDE_RECEIPT_SIGNING_MODE=custody`,
   `MNDE_KEY_CUSTODY=file-backed-production`, `MNDE_AUTHORITY_BUNDLE=…`,
   `MNDE_RECEIPT_SIGNING_KEY=…`, `MNDE_LEDGER_SIGNING_KEY=…`. The production
   preflight ([`src/authority-signing/preflight.mjs`](../src/authority-signing/preflight.mjs))
   fails closed on any dev/demo key material.

## Acceptance gate

[`scripts/verify-published-bundle.mjs`](../scripts/verify-published-bundle.mjs)
(`npm run test:published-bundle` drives it via a fixture test) is the repository
side of the future clean-machine acceptance test. Point it at a published bundle
and receipt with an **independently configured** pinned root:

```bash
MNDE_PINNED_ROOT_FINGERPRINT=<sha256>  MNDE_PUBLISHED_BUNDLE=./authority.bundle.json \
MNDE_PUBLISHED_RECEIPT=./receipt.json  npm run verify-published-bundle
```

It authenticates the bundle against the pinned root, then verifies the receipt
against the authenticated bundle, using the **production verifiers only**. With no
inputs configured it reports `NOT CONFIGURED` and exits 0, so CI never depends on
`trust.mnde.com` until a real bundle is deliberately published.

## Publication model (pin the root through independent channels)

The point of an out-of-band fingerprint is that a verifier can pin the root
**without trusting the same host that serves the bundle.** Publish the root
fingerprint through at least **three channels that do not share one security
boundary**, for example:

- the official MNDe website (a page distinct from the bundle host path),
- the GitHub repository / signed release notes,
- a signed release artifact (e.g. a signed git tag or checksummed release asset),
- package documentation, or another independently controlled channel.

Do **not** count channels that share the same origin/credentials as independent.

## Demo manifest vs. production bundle

The repository contains a separate **demo trust manifest**
(`authority/authority-manifest.json`, consumed by `shared/authority-manifest.mjs`
and the `ecs.receipt.v2` reviewer-kit path). It is **not** an
`mnde.authority.bundle.v1` and is rejected by the production verifier
(`UNSUPPORTED_BUNDLE` — regression-tested). The production receipt path
(`mnde.execution_gate.receipt.v1`) does not depend on the demo manifest.

Follow-up: the standalone HTML counterparty verifier shipped in Phase 2
(`verifier/mnde-receipt-verifier.html`, branch `sellable/framing-and-verifier`)
currently ports the *demo* manifest shape. It must be re-pointed at the
`mnde.authority.bundle.v1` verification path before it is used against production
receipts. Tracked as Phase 1 §7 in `mnde-gtm/phase1-trust-root-spec.md`.

## Phase 1 decisions (frozen)

| Decision | Value | Basis |
|---|---|---|
| `authority_id` | `mnde-systems-production` | stable across rotations; no date/env/version suffix; accepted by the schema (rejects only `local`/`demo`). |
| Root custody | offline Ed25519; signs bundles only; encrypted offline backups | `authority:init` writes root private outside the repo `0600`; never committed/uploaded. |
| Trust URL | `https://trust.mnde.com/authority-bundle.json` **(PROPOSED — not published)** | DNS/hosting/TLS not assumed live; publishing contract only. |
| Bundle validity | 90 days; rotate/republish before day 60 | `authority:init --bundle-days` default is 90; enforced from the signed `not_after`, not hard-coded in crypto. |
| Ledger role | included | **Required** by the running production path: preflight step 6 ("the production ledger is always enabled") fails closed (`ERR_TRUST_ROOT_LEDGER_SIGNER`) without a verifying `ledger` key. The receipt-verification acceptance test alone needs only the `receipt` role. |

## State of publication

**NOT PUBLISHED.** No production root has been generated by this work, and
`https://trust.mnde.com/authority-bundle.json` is not live. The repository is
**ready for a deliberate, human, offline root ceremony**. The README caveat that
MNDe has no published production authority bundle **remains** and must stay until a
real bundle is published and independently verified.
