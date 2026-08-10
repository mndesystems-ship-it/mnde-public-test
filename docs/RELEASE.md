# MNDe release & install contract

This document describes **only behavior proven by automated tests** in this
repository. The end-to-end proof is
[`tests/test_release_truth.mjs`](../tests/test_release_truth.mjs) (`npm run
release:verify`); version-drift is guarded by
[`tests/test_release_identity.mjs`](../tests/test_release_identity.mjs)
(`test:release-identity`, in the default suite).

## Supported installation method

The **npm tarball** (`mnde-public-test-<version>.tgz`), installed into a
dedicated project with `npm install`. No repository clone is required to install
or run. Desktop installers (MSI/NSIS/DMG/PKG/AppImage) are **not** part of this
release and are not published — see [`installer/README.md`](../installer/README.md).

## Supported platform

- **Windows 11 x64** — the CI-verified pilot platform (`.github/workflows/ci.yml`).

The CLIs and sidecar are platform-neutral Node.js, but only Windows is verified
in CI. macOS/Linux are not claimed as supported for the pilot.

## Runtime prerequisites

- Node.js per `package.json` `engines` (`>=20`); CI runs and verifies on
  **24.14.1**. `mnde-sidecar doctor` checks the running Node major version and
  fails closed if it is too old.
- No third-party runtime dependencies: the package installs and runs from the
  tarball alone (verified — REL-16).

## Release identity — one authoritative source

- **Version** is `package.json` `"version"` — the single authoritative source.
- **Source commit / build id / build time** are captured at pack time by
  `build/build-package.mjs` and embedded at `dist/src/release/build-info.json`.
- Everything (`mnde version`, `mnde-sidecar version`, the sidecar `/identity`
  endpoint) reads that one embedded identity via `src/release/identity.mjs`. The
  runtime **never inspects Git** — a packaged install has no `.git` and does not
  need one (verified — REL-02).

Confirm what you installed:

```bash
npx mnde-sidecar version            # human-readable
npx mnde-sidecar version --json     # machine-readable release identity
```

`--json` fields: `schema, product, package, version, commit, commit_short,
build_id, build_time, artifact_format, source, node`.

## Install

```bash
npm init -y
npm install ./mnde-public-test-<version>.tgz
npx mnde-sidecar version
```

## Initial configuration

```bash
npx mnde-sidecar init      # idempotent: receipt keys + local authority + starter policy
```

All state is written under **`MNDE_HOME`** (default `./.mnde` in the current
directory). `init` never writes into the installed package directory (verified —
REL-09) and never overwrites existing keys.

## Start / status / doctor / stop

```bash
npx mnde-sidecar doctor    # fail-closed readiness check; non-zero on any hard failure
npx mnde-sidecar start     # foreground sidecar on 127.0.0.1:8787 (Ctrl+C to stop)
npx mnde-sidecar smoke     # one decision -> signed receipt -> offline-verified
```

- The onboarding CLI additionally offers `mnde status` (shows the installed
  release identity and any wired MCP servers).
- **Stop**: `start` runs in the foreground; Ctrl+C stops it. No background
  service, scheduled task, or OS registration is created.
- The running sidecar exposes its identity at `GET /identity` (open in the local
  profile); its `release` block matches the CLI (verified — REL-18).

## Data location

- **Application files** (immutable): the installed package directory under
  `node_modules/mnde-public-test/`.
- **Customer/mutable data**: `MNDE_HOME` only — receipt signing keys, local
  authority manifest, starter policy, receipts, logs. Nothing mutable is written
  into the application directory (verified — REL-07, REL-09).

## Fail-closed behavior

With `MNDE_PROFILE=production` and no custody configured, the sidecar **refuses
to start** (it will not fall back to the demo/legacy signing default) and no
listener is left behind (verified — REL-06). `start` without `init` fails with a
clear, actionable message and a non-zero exit (verified — REL-17).

> The local/demo signing default (`MNDE_RECEIPT_HMAC_SECRET` fallback in
> `scripts/start-sidecar.mjs`) is a convenience for the zero-config **local**
> experience only. It is env-overridable and is rejected under
> `MNDE_PROFILE=production`. It is not a private key and cannot sign production
> receipts.

## Reinstall

Installing the same version over an existing install is deterministic: the CLI
entry points remain, the reported version is unchanged, and customer data under
`MNDE_HOME` is preserved (verified — REL-10).

## Upgrade

There is **no auto-updater**. To move to a new version, `npm install` the new
tarball. Customer data under `MNDE_HOME` is preserved across a same-version
reinstall (tested). Cross-version data migration is **not** claimed or tested.

## Uninstall

```bash
npm uninstall mnde-public-test      # removes application files + bin shims
```

Uninstall removes the package directory and the `mnde` / `mnde-sidecar` /
`sidecar` bin shims. It **does not** touch `MNDE_HOME` — customer keys,
receipts, and audit data are preserved (verified — REL-11). To also remove local
state, delete the `MNDE_HOME` directory yourself (e.g. `rm -rf ./.mnde`).

## Artifact integrity

Each release is built with `npm run release`, which produces:

- `mnde-public-test-<version>.tgz` — the tarball
- `SHA256SUMS.txt` — SHA-256 digest(s)
- `release-manifest.json` — version, source commit, build id/time, Node/npm/OS,
  and per-artifact size + SHA-256

Verify a download:

```bash
sha256sum -c SHA256SUMS.txt
# PowerShell: (Get-FileHash mnde-public-test-<version>.tgz -Algorithm SHA256).Hash.ToLower()
```

A modified artifact fails verification (verified — REL-13). `release-manifest.json`
binds the artifact digest to the source commit, answering "which artifact, which
version, which commit, does the digest match?".

## Known unsupported / out of scope

- Desktop installers (MSI/NSIS/DMG/PKG/AppImage).
- macOS / Linux / Docker as supported pilot platforms.
- Public npm-registry publication of the pilot (install is from the tarball
  asset, not `npm install mnde-public-test` from the registry).
- Cross-version automatic upgrade / data migration.
