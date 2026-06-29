// Export the PUBLIC authority bundle for the active custody provider.
//
//   npm run authority-bundle:export -- --out ./mnde.authority.bundle.json
//
// Writes only public material (root + signing public keys, key ids, validity
// windows, revocation, bundle signature). Verifiers publish/distribute this file
// and verify receipts against it offline. No private keys are read or written.
//
// Provider follows MNDE_KEY_CUSTODY (default local-demo). For production custody
// the public bundle is whatever MNDE_AUTHORITY_BUNDLE already points at — this
// command just re-emits it so the public copy is canonical.

import { writeFileSync } from "node:fs";

import { createCustody, verifyAuthorityBundle } from "../src/custody/index.mjs";

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const { ok, provider, reason } = await createCustody(process.env);
if (!ok) {
  console.error(`custody not available: ${reason}`);
  process.exit(1);
}

const bundle = provider.getPublicBundle();
const check = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: provider.trustedRootFingerprint });
if (!check.ok) {
  console.error(`refusing to export an unverifiable bundle: ${check.reason}`);
  process.exit(1);
}

const out = arg("--out");
const json = `${JSON.stringify(bundle, null, 2)}\n`;
if (out) {
  writeFileSync(out, json, "utf8");
  console.error(`wrote ${provider.mode} authority bundle -> ${out}`);
  console.error(`root fingerprint (trust anchor): ${provider.trustedRootFingerprint}`);
} else {
  process.stdout.write(json);
}
