# Supply Chain Security

This document describes the current supply chain posture and gaps for MNDe Public Test. It does not claim SLSA compliance, reproducible builds, or signed-release maturity.

## Current Evidence

- Root `package-lock.json` lists no third-party npm dependencies.
- `package.json` has no `dependencies` or `devDependencies`.
- `SBOM.md` records current package and asset hashes.
- Tests are enumerated in `tests/expected-test-scripts.json` and run through `scripts/run-all-tests.mjs`.
- The repository license restricts evaluation use.

## Dependency Pinning

The root lockfile pins the root package metadata and currently has no external dependency tree. If dependencies are added later:

- Commit lockfile updates.
- Record each dependency in [LICENSES.md](LICENSES.md).
- Update [SBOM.md](SBOM.md).
- Review transitive licenses and security advisories.

## Signed Releases

Signed release artifacts are not implemented in this repository.

Before public binary distribution, add:

- Release artifact signing.
- Published checksums.
- Verification instructions.
- Release-key custody documentation.
- Procedure for revoking or replacing a compromised release key.

## Reproducible or Repeatable Builds

No reproducible build proof is included. Release builds should at minimum become repeatable from a documented commit, runtime, and command sequence.

Before public launch, document:

- Build environment.
- Build commands.
- Expected artifacts.
- Artifact hashes.
- Verification command.
- Differences between source, package, and installer artifacts.

## Provenance

No SLSA, in-toto, Sigstore, or equivalent provenance attestation is included.

Future release hardening should add:

- Build provenance.
- Source commit binding.
- Test result binding.
- SBOM binding.
- Release approval record.

## Dependency Security

Because the root lockfile has no third-party packages, there is no current third-party npm vulnerability surface in the root project. This does not cover:

- Node.js runtime vulnerabilities.
- Operating system packages.
- External signer commands.
- Upstream MCP servers.
- Installer tooling outside this repository.
- Future dependencies.

## Supply Chain Gaps

Remaining gaps before enterprise or government use:

- Signed release artifacts.
- Release provenance.
- Reproducible or repeatable build documentation.
- Automated dependency and secret scanning.
- Maintainer access-control documentation.
- Release approval process.
- SBOM generation integrated into release workflow.
- Vulnerability response process for third-party dependencies.
