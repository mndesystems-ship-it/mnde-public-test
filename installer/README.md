# MNDe installation

**The supported MNDe pilot artifact is the npm tarball, not a desktop installer.**

There is no MSI, NSIS, DMG, PKG, or AppImage installer in this repository, and
none is published. Earlier drafts pointed here for a desktop `.exe`; that was a
claim ahead of the product. Desktop installers are explicitly out of scope for
the current pilot release and may return as a separate, later effort.

## Install the supported artifact

Download the versioned npm tarball and its `SHA256SUMS.txt` from the project's
GitHub Releases, verify the checksum, then install it into a dedicated project —
no repository clone required:

```bash
# 1. verify the download against the published digest
sha256sum -c SHA256SUMS.txt            # POSIX
# PowerShell: (Get-FileHash mnde-public-test-<version>.tgz -Algorithm SHA256).Hash.ToLower()

# 2. install into a clean project
npm init -y
npm install ./mnde-public-test-<version>.tgz

# 3. confirm what you installed
npx mnde-sidecar version               # product, version, source commit
npx mnde-sidecar init                  # keys + authority + starter policy under MNDE_HOME
npx mnde-sidecar doctor                # fail-closed readiness check
npx mnde-sidecar smoke                 # one decision -> signed receipt -> offline-verified
```

See [`docs/RELEASE.md`](../docs/RELEASE.md) for the full, tested install /
verify / start / stop / reinstall / uninstall contract, data locations, and
checksum verification.

## Command-line reviewer proof (from a source checkout)

The reviewer proof runs from a clone and does not need any installer:

```bash
npm run reviewer-kit
```
