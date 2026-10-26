# Contributing to Argus

Argus is open to contributors. Bug reports, reproducible test cases,
documentation, accessibility improvements, and code changes are welcome.

## Set up a development environment

Install [Bun](https://bun.com/docs/installation) 1.3.14 or later and Git, then:

```bash
git clone https://github.com/ajul8866/argus.git
cd argus
bun install --frozen-lockfile --ignore-scripts
bun run build
bun run dev
```

The development server listens on `127.0.0.1:8787`. Initial credentials are written to
`data/bootstrap-admin.txt`. Never commit this file, your database, `.env`,
provider credentials, or private source code.

Pi and Claude Code are optional for ordinary development and automated tests.
Running a real audit requires a configured harness and provider account.
Harness checks and end-to-end audits can consume provider credits.

## Before opening a pull request

1. Start from `main` and create a branch with one clear purpose.
2. Reproduce the problem. Add a regression test for changes to behavior.
3. Keep changes focused and follow the existing strict TypeScript style.
4. Run the checks below and update documentation when behavior changes.
5. Describe the problem, resulting behavior, and validation in your pull request.

```bash
bun run check
bun run build
bash -n install.sh start.sh
```

The default suite uses temporary databases and mocked harness processes. It
does not need API keys and does not contact model providers. Installer tests
use a local Git fixture; dependency installation remains part of the separate
release smoke test.

For browser changes, run the app and inspect the affected flow at desktop and
mobile widths. `bun run scripts/check-local-resources-ui.ts` validates Skills
and MCP with an installed Chrome binary. For Pi's native MCP adapter,
`bun run scripts/check-local-mcp.ts` uses a local fixture server without a
provider request. See [the demo guide](docs/DEMO.md) before running the paid,
real-harness end-to-end workflow.

`bun run test:ui-overlay` builds the committed overlay fixture and runs it in
Chrome, checking nested confirmation focus, Escape layering, backdrop
dismissal, hash cleanup, and the Tab trap. It needs an installed Chrome binary.

## Useful places to start

- Improve installation on different Linux distributions, macOS, and WSL2.
- Extend local Skills/MCP configuration support with redacted test fixtures.
- Add harness protocol regression cases and recovery tests.
- Improve keyboard navigation, responsive layouts, and report readability.
- Clarify setup instructions and translate documentation.

Use [issues](https://github.com/ajul8866/argus/issues) for bugs and feature
proposals. Include your Argus, Bun, OS, and harness versions; reproduction
steps; and expected versus actual behavior. Remove tokens, private source,
customer names, and generated credentials from attachments.

For a large change, open an issue describing the proposed interface and
tradeoffs before investing in an implementation. First contributions can be
small; a well-reproduced bug or a documentation fix is useful.

## Security and review

Read [the security policy](SECURITY.md) before reporting a vulnerability.
Preserve explicit role permissions, evidence verification, session
independence, cancellation behavior, and secret redaction. Do not add silent
fallbacks that bypass these controls.

Be respectful, give specific feedback, and explain technical disagreements
with examples. Maintainers review contributions for correctness, scope,
security, and maintainability.

## License

Contributions are accepted under [AGPL-3.0-only](LICENSE), the same license as
the project. Keep third-party notices and identify the origin and license of
any code or assets you introduce.
