# Outreach Process

A workflow for finding MCP-related projects that may need pre-execution authorization, receipts, auditability, or execution controls — and contacting maintainers manually.

This system automates **discovery, scoring, categorization, draft generation, and tracking only**. It does not send messages. Sending is always manual.

## Tooling

`scripts/find-mcp-targets.mjs` queries the public GitHub repository search API and writes:

- `outreach/mcp-targets.csv` — ranked list with the columns `rank, score, repo, owner, url, description, category, whyMndeFits, suggestedMessage, status, notes`.
- `outreach/mcp-targets.json` — the same candidates with the full collected fields (`stars`, `language`, `lastUpdated`, `contactMethod`).

Run it:

```bash
# recommended daily batch:
node scripts/find-mcp-targets.mjs --quality --min-stars 1 --limit 50

# full unfiltered sweep (keeps zero-star fresh repos):
node scripts/find-mcp-targets.mjs

# with a token for full quality checks and higher limits:
GITHUB_TOKEN=<token> node scripts/find-mcp-targets.mjs --quality --min-stars 1 --limit 50
```

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `--min-stars N` | 0 | minimum stars (0 keeps fresh, unknown teams) |
| `--max-stars N` | 100 | maximum stars |
| `--updated-days N` (`--days`) | 30 | pushed within N days |
| `--limit N` | 100 | max rows written |
| `--quality` | off | re-rank by quality signals and verify a shortlist |

Set `GITHUB_TOKEN` (or `GH_TOKEN`) to raise the GitHub rate limit. Without a token the script paces requests to stay under the unauthenticated search limit.

### Quality mode (`--quality`)

Quality mode does not hard-filter; it **re-ranks** so cleaner candidates rise and noise sinks below the `--limit` cut. Fresh zero-star projects are kept. For a shortlist it makes one extra GitHub API call per repo (the repository root tree) to detect a real README and package files.

Signals that raise rank:

- topics include `mcp`, `agent`, `claude`, `openai`, `anthropic`, `langchain`, or `cursor`
- a real README at the repository root
- a package file (`package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, …)
- description longer than 40 characters
- at least one star

Signals that lower rank:

- owner name looks random/generated (e.g. trailing digit runs)
- generic/boilerplate repo name (echoes the protocol name, `-poc`, `-old`, long digit/hex runs)
- short or missing description
- zero stars **and** generic owner **and** short description (the clearest noise — sinks below the cut)

Awesome lists, courses, tutorials, and handbooks are excluded regardless of mode. Without a token, quality enrichment is limited to about 20 repos (the unauthenticated core-API limit); the rest are ranked on metadata alone and left unverified.

### Filters applied

- Pushed within the last 30 days (`--days`).
- Fewer than 100 stars (`--max-stars`).
- Not archived.
- Has a description (proxy for an informative, non-bare repo).
- Excludes list-only / educational repositories by name and description heuristics (awesome lists, tutorials, courses, handbooks).

### Scoring (risk)

| Score | Meaning | Categories |
|---|---|---|
| 5 | executes commands, modifies infrastructure, money, deployments, databases | shell, ssh, docker, filesystem, database, payments, deployment |
| 4 | MCP production tooling, agent orchestration, tool platforms | agent-platform |
| 3 | audit, replay, tracing, signing, observability | audit, replay, observability, signing |
| 2 | memory, retrieval, knowledge systems | memory (and unclassified) |
| 1 | content generation, productivity, educational | productivity |

### Ranking

1. Priority bucket: high (shell, ssh, docker, filesystem, database, payments, deployment) > medium (agent-platform, audit, replay, observability, signing) > low (memory, productivity, other).
2. Then risk score, descending.
3. Then fewer stars first (earlier-stage, more reachable).
4. Then most recently pushed.

## Workflow

1. **Run discovery.** `node scripts/find-mcp-targets.mjs`.
2. **Review the top 20 results manually.** Do not contact anything you have not read.
3. **Verify repo relevance.** Open the repo. Confirm it actually exposes the execution surface the category implies. Correct the category/notes if wrong.
4. **Customize outreach.** The `suggestedMessage` is a starting point. Make it specific to what the repo actually does. Keep it factual, reference the repo, ask a question, do not hard-sell.
5. **Send manually.** Use the maintainer's preferred channel (a GitHub issue/discussion link is in `contactMethod`; prefer their listed contact if they have one). The tool never sends.
6. **Track responses.** Update the `status` column: `new` → `contacted` → `replied` / `no-reply` / `not-a-fit`. Put dates and context in `notes`.
7. **Follow up once after 3–5 days** if there is no reply.
8. **Stop after the second contact.** No third message.

## Status values

- `new` (default) — discovered, not yet contacted.
- `contacted` — first message sent (record the date in `notes`).
- `replied` — maintainer responded.
- `no-reply` — followed up once, no response; stop.
- `not-a-fit` — reviewed and ruled out.

## Message rules

- Reference the actual repository purpose.
- Ask a question.
- Do not hard-sell.
- Do not claim MNDe solves everything.
- No marketing language.

## Limitations

- GitHub search ranking and the 30-day window mean results change between runs; treat each run as a snapshot.
- Category and score are keyword-derived and approximate. Step 3 (manual verification) exists because of this.
- "Has README" is approximated by the presence of a description; verify during review.
- The script reads public metadata only. It does not contact anyone.
