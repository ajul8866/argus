# Design: Argus

The locked system. Every Hallmark run reads this first and pages share it. Change it on purpose; the file is the rule.

## System
- Genre: modern-minimal
- Shape of the first page: app screen (shell, 13 routes)
- Theme: Console (by request)
- Axes: dark/grotesk-sans/chromatic-amber · posture: restrained

## Tokens
`web/src/tokens.css` is the source of truth. The roles:
```css
:root {
  --color-paper: oklch(17% 0.008 250);  --color-paper-2: oklch(21% 0.009 250);  --color-paper-3: oklch(13.5% 0.007 250);
  --color-ink: oklch(95% 0.005 250);  --color-ink-2: oklch(83% 0.008 250);  --color-muted: oklch(71% 0.01 250);
  --color-rule: oklch(31% 0.01 250);  --color-rule-2: oklch(42% 0.012 250);
  --color-accent: oklch(82% 0.15 80);  --color-accent-ink: oklch(18% 0.04 75);  --color-accent-soft: oklch(29% 0.05 80);  --color-focus: oklch(82% 0.15 80);
  --color-cool: oklch(77% 0.12 245);  --color-cool-soft: oklch(29% 0.05 245);
  --color-ok: oklch(76% 0.15 150);  --color-bad: oklch(70% 0.17 25);
  --font-display: "Host Grotesk", ui-sans-serif, system-ui, sans-serif;  --font-body: var(--font-display);  --font-outlier: "Atkinson Hyperlegible Mono", ui-monospace, monospace;
  --radius-card: 10px;  --radius-pill: 6px;  --rule-hair: 1px;  --shadow-card: none;
}
```
The spacing scale, the type scale, the easings and the durations are the scaffold's and live in `tokens.css`. Faces are self-hosted from `web/src/fonts` (SIL OFL 1.1), inlined by the Bun build.

## Semantics
- Amber is a person or a decision: the current step, a waiting approval, the one primary control.
- Cool is an instrument: measurements, timestamps, hashes, the progress of a run, the selected tab.
- Ok and bad exist for status and diffs only.
- Figures and identifiers use the measured face (`--font-outlier`); labels, heads and controls never do.

## Controls
- Primary: amber fill, `--color-accent-ink` text, 6px radius, 36px tall
- Secondary: `--color-paper-2` fill with a 1px `--color-rule-2` edge, same radius and height
- Small: 32px tall. Inputs: 36px, `--color-paper-3` inside a 1px `--color-muted` edge, focus ring 2px `--color-focus`
- Panels: `--color-paper-2` inside a 1px `--color-rule`, 10px radius, no shadow; adjacent panels share seams

## Motion
- Character: still; values change over `--dur-short` with `--ease-out`, `transform` and `opacity` only, no reveal, no glow. Under reduced motion everything ends at once.

## Workspace composition
- Keep the 13-destination sidebar, using one set of line icons and an amber current selection. On small screens the existing Menu control opens the sidebar.
- Cap the content at `--content-width` (1312px); use `--gutter` (40px desktop, 24px tablet, 16px phone). The desktop sidebar is `--sidebar-width` (224px).
- Overview: a ruled metric strip followed by the audit ledger. Recent audits and live activity share one surface; runtime health, coverage and severity form the companion column. Existing API data supplies every figure.
- Tables use horizontal rules. Tables, logs, empty states and usage figures inside a panel share its surface rather than gaining another card border.
- The Skills catalog has a bounded scrolling list alongside the detail. At 1050px and below the list sits above the detail; the list keeps a bounded height so permissions remain reachable.
- Skill source files use a read-only native text area, preserving keyboard scrolling and text selection without executing file contents.
- Shared loading states show a static skeleton with a live status label. Error messages, retry controls and empty-state actions retain their existing behavior.

## Exports
`web/src/tokens.css` in this project. Tailwind, DTCG or shadcn blocks are added here on request, per `export-formats.md`.
