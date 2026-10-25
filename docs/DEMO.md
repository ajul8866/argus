# End-to-end demonstration

The fixture at `test/fixtures/vulnerable-app` is a deliberately vulnerable
Express-style invoice portal. It is local-only, contains no real data, and is
authorized test material. It includes a prompt-injection sentence to exercise
the platform guard.

## Automated real run

```bash
bun install
bun run build:web
bun run e2e
```

What the script does:

1. Starts an isolated Argus server on port 8912 with its own temporary data dir.
2. Creates an authorized project pointing at the fixture.
3. Imports an immutable repository snapshot and records its git commit.
4. Starts a six-phase audit with 2 areas, 2 candidates per area, 3 confirmation
   slots, and 3 concurrent agents.
5. Uses the default mixed configuration: **Pi** for mapping/discovery/retest and
   **Claude Code** for independent confirmation.
6. Polls durable state (not prompt responses) until the audit terminates.
7. Verifies the evidence chain, all four report formats, and report hashes.
8. Downloads reports into `demo-output/`.

The script fails if either harness is missing, the chain is broken, no finding
is reverified, or fewer than four report formats are generated. It does not
simulate an agent.

## Expected fixture findings

The deliberate weaknesses are:

| Fixture location | Issue |
|---|---|
| `src/lib/db.js` `searchUsers` | string-concatenated SQL LIKE query (CWE-89) |
| `src/routes/invoices.js` detail handler | missing invoice ownership check (CWE-639) |
| `src/routes/files.js` preview | path traversal via `path.join(UPLOAD_DIR, name)` (CWE-22) |
| `src/routes/media.js` convert | command injection via `exec("convert " + source)` (CWE-78) |
| `src/lib/auth.js` | hardcoded JWT signing secret (CWE-798) |

Depending on which areas the mapper chooses, the researcher may report a
different subset. The E2E run requires at least one independently reverified
finding, not a fixed count. The report will show exact quotes and independent
verdicts; candidates that fail the evidence gate or confirmation are retained
in verification history but do not become findings.

## Manual dashboard run

1. `bun run start` (or `bun run dev`).
2. Sign in.
3. **Projects → New project**:
   - name: `ACME Invoice Portal`
   - source: the absolute path to `test/fixtures/vulnerable-app` in your checkout
   - authorization: `Argus demo operator` / `LOCAL-DEMO-2026`
   - include: `**/*.js,**/*.json,README.md`
   - exclude: `.git/**,node_modules/**,uploads/**`
4. Open the project → **Import snapshot**.
5. Open **Explorer** → inspect the architecture map and source after the first
   audit phase.
6. **New audit** → 2–3 areas, 2 candidates per area, 3 concurrent agents, start.
7. Watch **Audits → six-phase timeline**, **Tasks**, and **Activity**.
8. **Findings** → open a finding → inspect source evidence, verifications, and
   provenance.
9. **Reports** → generate all formats.

## What to check in the deliverable

- Both harness names appear in the audit's Sessions and report execution
  summary.
- Verification history shows a confirmation and a reverification with different
  session IDs.
- A `CONFIRMED` claim without a matching source quote would be downgraded to
  `INCONCLUSIVE` by the platform gate.
- Evidence chain status is `intact`.
- Report Markdown contains scope, commit, methodology, coverage limitations,
  verified source excerpts, evidence hashes, and unresolved findings.
- The JSON report has `schema: "argus.audit-report/v1"` and all finding fields.
- HTML opens standalone; PDF starts with `%PDF-`.

## Cost and runtime

A small run typically uses:

- Pi: a few discovery/mapping/retest calls, cents at the configured provider.
- Claude Code: one minimal health call plus one validator call per candidate.

The E2E caps confirmations at 3 and requires 45 minutes maximum. Real elapsed
time depends on provider latency; the local fixture is intentionally tiny.
