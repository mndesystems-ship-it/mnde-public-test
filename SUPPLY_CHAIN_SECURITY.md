# Supply Chain Security

This document describes the current supply chain posture and gaps for MNDe Public Test. It does not claim SLSA compliance, reproducible builds, or signed-release maturity.

## Current Evidence

- The runtime package has no third-party npm dependencies; TypeScript 5.9.3 is
  pinned as a development-only build dependency in `package-lock.json`.
- `SBOM.md` records current package and asset hashes.
- Tests are enumerated in `tests/expected-test-scripts.json` and run through `scripts/run-all-tests.mjs`.
- The repository license restricts evaluation use.

## Dependency Pinning

The root lockfile pins the development dependency tree. The packaged runtime has
no external dependency tree. If dependencies are added later:

- Commit lockfile updates.
- Record each dependency in [LICENSES.md](LICENSES.md).
- Update [SBOM.md](SBOM.md).
- Review transitive licenses and security advisories.

## Implemented Release Controls

- Local npm release artifact generation.
- SHA-256 checksum generation.
- Release manifest generation.
- Source commit binding in packaged release identity and the release manifest.
- Package identity tests.
- Clean packaged-install verification outside the repository.
- Content-based private-key exclusion during packaging and private-key exclusion tests.

These controls create and verify local release candidates. They do not publish
anything.

## Not Implemented

- Public release publication, including public checksum publication.
- Release artifact signing.
- Public provenance attestation (SLSA, in-toto, Sigstore, or equivalent).
- Reproducible-build proof.
- Desktop installer production.
- Installer signing.

## Dependency Security

The packaged runtime has no third-party npm dependencies. The development build
uses TypeScript, so development dependency vulnerabilities remain in scope. This
does not cover:

- Node.js runtime vulnerabilities.
- Operating system packages.
- External signer commands.
- Upstream MCP servers.
- Any future installer tooling, if introduced.
- Future dependencies.

## Supply Chain Gaps

Remaining gaps before enterprise or government use:

- Signed release artifacts.
- Public release provenance.
- Reproducible-build proof.
- General-purpose automated dependency and repository-wide secret scanning.
- Maintainer access-control documentation.
- Release approval process.
- SBOM generation integrated into release workflow.
- Vulnerability response process for third-party dependencies.
