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
    env.MNDE_APPROVAL_SIGNING_KEY
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
  const profile = env.MNDE_PROFILE === "production" ? "production" : "local";
  if (profile !== "production") return { ok: true, profile: "local" };

  // 1) Production must sign through custody — legacy signing uses dev keys.
  if (env.MNDE_RECEIPT_SIGNING_MODE !== "custody") {
    return fail(
      "ERR_TRUST_ROOT_REQUIRES_CUSTODY",
      "MNDE_PROFILE=production requires MNDE_RECEIPT_SIGNING_MODE=custody. Legacy signing uses development keys and cannot anchor production trust. Set MNDE_RECEIPT_SIGNING_MODE=custody and configure a production custody provider, or run with MNDE_PROFILE=local for demo use."
    );
  }

  // 2) Custody provider must be the production (file-backed) provider.
  if (env.MNDE_KEY_CUSTODY !== "file-backed-production") {
    return fail(
      "ERR_TRUST_ROOT_DEMO_CUSTODY",
      "MNDE_PROFILE=production requires MNDE_KEY_CUSTODY=file-backed-production. local-demo custody uses ephemeral, self-asserted development keys and must not anchor production trust. Provision a published authority bundle and signing key, then set MNDE_KEY_CUSTODY=file-backed-production."
    );
  }

  // 3) Reject any env path that points at repository dev key material.
  const devPath = detectDevKeyPath(env, options.repoRoot);
  if (devPath) {
    return fail(
      "ERR_TRUST_ROOT_DEV_KEY",
      `MNDE_PROFILE=production refuses development key material: ${devPath}. Point MNDE_AUTHORITY_BUNDLE / MNDE_RECEIPT_SIGNING_KEY at production keys stored outside the repository.`
    );
  }

  // 4) The custody provider must load and self-verify (valid bundle + key).
  //    Imported lazily so local profile never loads the custody subsystem.
  const { loadSigningConfig } = await import("./index.mjs");
  const signing = loadSigningConfig(env);
  if (!signing.ok) {
    return fail(
      signing.reason_code ?? "ERR_CUSTODY_UNAVAILABLE",
      `MNDE_PROFILE=production custody is not usable (${signing.reason_code ?? "unknown"}: ${signing.detail ?? "no detail"}). Configure a valid published authority bundle (MNDE_AUTHORITY_BUNDLE) and signing key (MNDE_RECEIPT_SIGNING_KEY).`
    );
  }

  // 5) Guard against pointing file-backed custody at an exported demo bundle.
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
