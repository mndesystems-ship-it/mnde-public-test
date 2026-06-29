# Software Bill of Materials

Generated manually from the repository package files on 2026-06-28. No third-party package registry lookup was performed. Do not treat this as a signed release SBOM.

## Components

| Package | Version | License | Supplier | Hash if available | Evidence |
| --- | --- | --- | --- | --- | --- |
| `mnde-public-test` | `0.1.0` | Custom MNDe Public Testing License | MNDe project | `package.json sha256:2c97aee12399ca37ba19467cdc18cd2e863a9598e672a73a19ca44f541a49fc2` | `package.json`, `LICENSE` |
| root lockfile | lockfileVersion `3` | Not applicable | MNDe project | `package-lock.json sha256:937b10825cdde04ca522cf336bec2ab9482c00d1ce3f8cbb7a9ea58ea0348725` | `package-lock.json` |
| `@mnde/executor` | `0.1.0` | MIT in subpackage metadata | MNDe project | `executor/package.json sha256:56edadc3ee101759bc4353640f179b9040f09d1dc91f444f3852d55a0313bcff` | `executor/package.json` |

## Third-Party Dependencies

Root `package-lock.json` contains only the root package entry. No direct or transitive third-party npm dependencies are listed.

## Assets

| Asset | Supplier | License | Hash |
| --- | --- | --- | --- |
| `brand/mnde-wordmark.svg` | MNDe project | Repository license unless separately licensed | `sha256:e80e775bb4fe13b1b22f3761a2a3790d7dac249ee2cac765405113c8d57951e7` |
| `brand/mnde-mark.svg` | MNDe project | Repository license unless separately licensed | `sha256:d5eac8004a4a695c34cef6e5f00dc0519b83223d8e8471433c4d4dcc058687aa` |
| `brand/mnde-mark-mono.svg` | MNDe project | Repository license unless separately licensed | `sha256:3ce8059b68114bb1626fbe3685e2bd9dbb78bc24d2f6b6301af47a9beb19941e` |
| `brand/favicon.svg` | MNDe project | Repository license unless separately licensed | `sha256:5a471dbf0a17e168384f22aa71b23b76482d44a8c24a6fe0a3253d0e4761d442` |

## Missing Information

- No signed release artifact hashes are included.
- No build provenance or SLSA attestation is included.
- No reproducible build proof is included.
- No dependency vulnerability scan is included because no package manager dependencies are present in the root lockfile.

## Regeneration Notes

Recompute file hashes with:

```bash
node --input-type=module -e "import {createHash} from 'node:crypto'; import {readFileSync} from 'node:fs'; for (const f of ['package.json','package-lock.json','executor/package.json','brand/mnde-wordmark.svg','brand/mnde-mark.svg','brand/mnde-mark-mono.svg','brand/favicon.svg']) console.log(f, createHash('sha256').update(readFileSync(f)).digest('hex'));"
```
