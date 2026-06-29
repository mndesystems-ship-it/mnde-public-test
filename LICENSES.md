# License Inventory

This inventory is based on files present in the repository and the root `package-lock.json`. It is not a legal opinion.

## Repository License

| Item | License | Copyright owner | Attribution requirements | NOTICE requirements | Status |
| --- | --- | --- | --- | --- | --- |
| Root repository | Custom MNDe Public Testing License | MNDe Systems / repository owner as stated by project context | Preserve license text when sharing under permitted evaluation terms | No separate NOTICE file identified | Known |

The root [LICENSE](LICENSE) restricts use to evaluation and forbids sale, sublicensing, embedding, and production use without a separate written agreement.

## Packages and Dependencies

| Package | Version | License | Supplier | Copyright owner | Attribution requirements | NOTICE requirements | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mnde-public-test` | `0.1.0` | Custom MNDe Public Testing License | MNDe project | MNDe project | Preserve repository license | None identified | Known |
| `@mnde/executor` | `0.1.0` | Custom MNDe Public Testing License via `../LICENSE` | MNDe project | MNDe project | Preserve repository license | None identified | Known |

Root `package-lock.json` lists no third-party npm packages. `package.json` has no `dependencies` or `devDependencies`.

## Assets

| Asset | License | Copyright owner | Attribution requirements | NOTICE requirements | Hash |
| --- | --- | --- | --- | --- | --- |
| `brand/mnde-wordmark.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:e80e775bb4fe13b1b22f3761a2a3790d7dac249ee2cac765405113c8d57951e7` |
| `brand/mnde-mark.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:d5eac8004a4a695c34cef6e5f00dc0519b83223d8e8471433c4d4dcc058687aa` |
| `brand/mnde-mark-mono.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:3ce8059b68114bb1626fbe3685e2bd9dbb78bc24d2f6b6301af47a9beb19941e` |
| `brand/favicon.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:5a471dbf0a17e168384f22aa71b23b76482d44a8c24a6fe0a3253d0e4761d442` |

## Fonts

No external font files are present. The dashboard uses system monospace fonts in CSS.

## Icons and Images

No third-party icon library or image dependency is present. The dashboard favicon is an inline SVG data URI. Brand SVG files are local repository assets.

## Documentation Sources

Documentation appears to be original repository content. No copied third-party policy, terms, or documentation source is identified. Future documentation imported from external sources must be added to this inventory.

## Unknown or Custom Licenses

| Item | Issue | Required follow-up |
| --- | --- | --- |
| Root license | Custom evaluation-only license | Review before external redistribution or commercial use. |

## NOTICE Status

No third-party dependency currently requires a NOTICE file based on the root package lock. Create `NOTICE` before adding dependencies or assets that require attribution notices.
