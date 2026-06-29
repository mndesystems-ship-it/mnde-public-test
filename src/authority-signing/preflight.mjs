// Trust-root pre-flight (S-02 / P-01).
//
// MNDe must never enter production/live enforcement while signing receipts with
// development/demo keys. This is the single, deterministic gate the sidecar runs
// before the decision server accepts traffic.
//
// Runtime profile (`MNDE_PROFILE`):
//   unset / "local"  -> local/demo mode. Anything goes (legacy signing or
//                       local-demo custody). Existing behavior is preserved.
//   "production"     -> live enforcement. Requires an explicitly configured,
//                       valid production custody provider; refuses to start on
//                       any demo/dev key material.
//
// The check is pure (env in, result out) so it is unit-testable without a
// running server. In `local` profile it does NOT import custody — legacy mode
// stays free of the custody subsystem.

import { resolve, sep } from "node:path";

import { parseRuntimeProfile } from "../../shared/runtime-profile.mjs";

function fail(reason_code, detail) {
  return { ok: false, reason_code, detail };
}

// True path (string) of the first env-configured key/bundle that points at known
// development key material in the repository, else null.
export function detectDevKeyPath(env = process.env, repoRoot) {
  const candidates = [
    env.MNDE_AUTHORITY_BUNDLE,
    env.MNDE_RECEIPT_SIGNING_KEY,
    env.MNDE_POLICY_SIGNING_KEY,
    env.MNDE_APPROVAL_SIGNING_KEY,
    env.MNDE_EXTERNAL_SIGNER_PUBLIC_KEY
  ].filter((p) => typeof p === "string" && p.length > 0);

  const devDirs = repoRoot
    ? [resolve(repoRoot, "shared", "receipt_keys"), resolve(repoRoot, ".mnde-test"), resolve(repoRoot, "authority")]
    : [];

  for (const candidate of candidates) {
    const resolved = resolve(candidate);
    if (devDirs.some((dir) => resolved === dir || resolved.startsWith(dir + sep))) return candidate;
    if (/receipt_signing_private\.pem$/.test(resolved)) return candidate;
    if (/(^|[\\/])(local-demo|demo)([\\/]|$)/i.test(resolved)) return candidate;
  }
  return null;
}

// Verify the trust root for the current runtime profile. Returns
// { ok:true, profile } or { ok:false, reason_code, detail }.
export async function assertTrustRoot(env = process.env, options = {}) {
  const profileResult = parseRuntimeProfile(env.MNDE_PROFILE);
  if (!profileResult.ok) return fail(profileResult.reason_code, profileResult.detail);
  const profile = profileResult.profile;
  if (profile !== "production") return { ok: true, profile: "local" };

  // 1) Production must sign through custody — legacy signing uses dev keys.
  //    Accepts "custody" (file-backed) or "external-signer" (HSM / PKCS#11).
  const signingMode = env.MNDE_RECEIPT_SIGNING_MODE;
  if (signingMode !== "custody" && signingMode !== "external-signer") {
    return fail(
      "ERR_TRUST_ROOT_REQUIRES_CUSTODY",
      "MNDE_PROFILE=production requires MNDE_RECEIPT_SIGNING_MODE=custody or external-signer. Legacy signing uses development keys and cannot anchor production trust. Configure a production custody provider, or run with MNDE_PROFILE=local for demo use."
    );
  }

  // 2) For file-backed custody, the provider must be the production one (not
  //    the ephemeral local-demo). External-signer carries no local private key,
  //    so this check does not apply to it.
  if (signingMode === "custody" && env.MNDE_KEY_CUSTODY !== "file-backed-production") {
    return fail(
      "ERR_TRUST_ROOT_DEMO_CUSTODY",
      "MNDE_PROFILE=production with MNDE_RECEIPT_SIGNING_MODE=custody requires MNDE_KEY_CUSTODY=file-backed-production. local-demo custody uses ephemeral, self-asserted development keys and must not anchor production trust."
    );
  }

  // 3) Reject any env path that points at repository dev key material.
  const devPath = detectDevKeyPath(env, options.repoRoot);
  if (devPath) {
    return fail(
      "ERR_TRUST_ROOT_DEV_KEY",
      `MNDE_PROFILE=production refuses development key material: ${devPath}. Point bundle and key paths at production material stored outside the repository.`
    );
  }

  // 4) The custody provider must load and self-verify. For external-signer this
  //    validates the bundle, that the key id exists, is active, is not revoked,
  //    and that the configured public key matches the bundle key.
  //    Imported lazily so local profile never loads the custody subsystem.
  const { loadSigningConfig } = await import("./index.mjs");
  const signing = await loadSigningConfig(env);
  if (!signing.ok) {
    return fail(
      signing.reason_code ?? "ERR_CUSTODY_UNAVAILABLE",
      `MNDE_PROFILE=production custody is not usable (${signing.reason_code ?? "unknown"}: ${signing.detail ?? "no detail"}).`
    );
  }

  // 4b) External-signer: run a real self-test signature through the command and
  //     verify it before accepting the trust root.
  if (signing.signer_mode === "external-signer") {
    try {
      await signing.provider.selfTest();
    } catch (error) {
      return fail(
        "ERR_TRUST_ROOT_SIGNER_SELFTEST",
        `MNDE_PROFILE=production external signer self-test failed: ${error instanceof Error ? error.message : String(error)}.`
      );
    }
  }

  // 5) Guard against pointing custody at an exported demo bundle.
  const bundle = signing.provider.getPublicBundle();
  const authorityId = String(bundle?.authority_id ?? "");
  const rootKeyId = String(bundle?.root_key?.key_id ?? "");
  if (/local|demo/i.test(authorityId) || /local|demo/i.test(rootKeyId)) {
    return fail(
      "ERR_TRUST_ROOT_DEV_KEY",
      `Configured authority bundle '${authorityId}' (root key '${rootKeyId}') is a development/demo bundle. Production must use a published production authority bundle, not an exported local-demo one.`
    );
  }

  return { ok: true, profile: "production", authority_id: authorityId };
}
