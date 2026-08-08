# Executor-bound live receipts

MNDe supports executor-bound live signing while preserving the existing authority-only format.

## Signing modes

- Authority-only signing is selected only when no `MNDE_EXECUTOR_*` identity is configured. It retains the existing `mnde.signed-receipt.v1` envelope and attestation bytes and carries no executor verification claim.
- `executor_and_authority` is selected when all four executor settings are present and valid: `MNDE_EXECUTOR_ID`, `MNDE_EXECUTOR_PRIVATE_KEY`, `MNDE_EXECUTOR_CREDENTIAL`, and `MNDE_EXECUTOR_ENVIRONMENT`.

Executor mode also requires custody receipt signing (`MNDE_RECEIPT_SIGNING_MODE=custody` or the supported external-signer equivalent). A configured executor never falls back to authority-only signing. Invalid credentials, missing or unsafe keys, mismatched keys, and unavailable authority signing fail startup before the listener opens. A runtime executor or authority signing failure returns `ERR_EXECUTOR_BOUND_SIGNING_FAILED` without persisting or delivering an authority-only receipt.

The executor credential is revalidated at every executor-bound signing timestamp, so a long-lived process stops issuing receipts at `expires_at` without reloading the private key. Historical verification evaluates credential validity at the authority-authenticated receipt `signed_at`: a receipt produced while the credential was valid remains verifiable after ordinary credential expiry, while a receipt produced before `not_before` or at/after `expires_at` is invalid.

The sidecar constructs one frozen signing context after startup validation. It retains signing capabilities in process memory, passes the context explicitly to every live receipt path, and destroys the executor signer reference on process exit. Keys, signatures, credentials, and sensitive paths are not logged.

## Receipt and verification structure

Executor-bound custody receipts use `mnde.signed-receipt.v2`:

```json
{
  "schema_version": "mnde.signed-receipt.v2",
  "signing_mode": "executor_and_authority",
  "receipt": {},
  "executor": {
    "identity": {},
    "credential": {},
    "signature": {
      "algorithm": "ED25519",
      "key_id": "executor-key-id",
      "value": "base64-or-hex-signature"
    }
  },
  "custody_attestation": {}
}
```

The executor signs a canonical identity body containing its identifiers, environment, credential reference, inner receipt schema, and inner receipt hash. The custody receipt-role key then signs an attestation containing the explicit mode, inner receipt hash, and executor-envelope hash. This ordering prevents replacement of the executor identity, credential, signature, evidence, decision, or policy-bearing inner receipt after countersigning.

The independent verifier requires the declared mode for v2 executor-bound receipts. It verifies the trusted authority bundle, credential issuer, credential validity window, required `sign_execution_receipt` capability, environment, executor identifier, executor signature, custody signature, and both hashes. Success reports `executor_and_authority_verified`; compatible v1 authority-only success reports `authority_only_verified`. A policy or caller that requires executor evidence rejects authority-only receipts with `ERR_EXECUTOR_REQUIRED`.

Example:

```text
node tools/verify.mjs receipt.json \
  --authority-bundle authority.bundle.json \
  --root-fingerprint <trusted-root-fingerprint> \
  --executor-environment prod \
  --expected-executor-id mnde:local:prod:executor:codex:01
```

When executor identity is absent, `mnde.signed-receipt.v1` authority-only envelopes continue to be produced byte-for-byte. The v2 schema is used only when the explicit executor mode and executor envelope are present.

## Private-key storage restrictions

Executor private keys must be regular files outside the repository or installed package tree. Startup validates every existing path component with `lstat`, rejects file and parent symbolic links, rejects Windows junctions and Node-visible reparse indirection, resolves canonical real paths, and compares path segments with platform-correct case handling. Missing paths, directories, unsupported file types, broadly writable files where POSIX permissions are reliable, repository containment, and ambiguous filesystem results fail closed with stable `ERR_EXECUTOR_KEY_*` codes.

The validated file is opened immediately. Metadata from the open descriptor is compared with the pre-open metadata before reading, and the canonical target is checked again, reducing path-replacement risk. Enrollment applies the same fail-closed component and canonical-path checks to `--root-key` and `--out-dir` before reading or writing. Private-key bytes are held only behind the executor signer capability and are never serialized.

## Exact claims and non-claims

This feature proves that a configured, authority-credentialed executor key signed the receipt binding and that the configured MNDe custody authority countersigned it. It does not provide third-party independence, external witnessing, production tenant isolation, a new authentication architecture, a SQLite authoritative ledger, connector runtime support, Simulation Mode, native desktop qualification, or new key-management infrastructure. The existing signed JSONL execution ledger and Merkle proof behavior remain unchanged.
