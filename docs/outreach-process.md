# Outreach Process

A workflow for finding MCP-related projects that may need pre-execution authorization, receipts, auditability, or execution controls — and contacting maintainers manually.

This system automates **discovery, scoring, categorization, draft generation, and tracking only**. It does not send messages. Sending is always manual.

## Tooling

`scripts/find-mcp-targets.mjs` queries the public GitHub repository search API and writes:

- `outreach/mcp-targets.csv` — ranked list with the columns `rank, score, repo, owner, url, description, category, whyMndeFits, suggestedMessage, status, notes`.
- `outreach/mcp-targets.json` — the same candidates with the full collected fields (`stars`, `language`, `lastUpdated`, `contactMethod`).

Run it:

```bash
node scripts/find-mcp-targets.mjs
# optional: GITHUB_TOKEN=<token> node scripts/find-mcp-targets.mjs
# flags: --days 30  --max-stars 100  --per-term 30
```

Set `GITHUB_TOKEN` (or `GH_TOKEN`) to raise the GitHub rate limit. Without a token the script paces requests to stay under the unauthenticated search limit.

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
