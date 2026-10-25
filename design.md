# Design: Argus

Shared system for the Argus application screens. The user chose to retain the Argus name, A identity, green accent, and dark foundation.

## System

- Genre: modern-minimal
- Scope: app screens, including sign-in
- Theme: Argus brand
- Axes: dark / sans / green; restrained posture
- Dials: energy 2, rhythm 2, motion 1
- Audience: operators managing source-code security audits
- Signature: audit status, coverage, and evidence shown as a coherent workspace

## Tokens

[web/src/tokens.css](web/src/tokens.css) is the source of truth. Existing role names remain aliases so every route uses the same palette.

- Paper: neutral charcoal with a green tint; sidebar one step darker
- Ink: near-white primary, clear secondary, readable muted text
- Accent: existing Argus green `#54dfc2`, reserved for actions, selections, and live state
- State: labelled warning, error, success, and informational colors
- Fields: a distinct edge at accessible contrast
- Typography: existing Inter/system sans stack; system monospace only for source code, IDs, and measurements
- Scale: fixed 1.2 type ratio, 16px body, 14px labels, 12px metadata
- Spacing: the Hallmark 2/4/8/12/16/24/40/64/96/144px scale
- Radius: 8px regions, 5px controls

## Composition

Keep the existing navigation destinations and component owners. Cap and center the shell at 1504px. Use a quieter 232px sidebar, a compact toolbar, and a consistent content gutter. Audit rows and activity lead the overview; coverage and runtime health support them. Use rules, spacing, and flat surfaces before bordered containers. Tables have horizontal rules, with row identity and actions retained on small screens.

## Controls

- Primary: green fill, paired dark ink, 40px desktop control with 44px hit target
- Secondary: quiet surface or outline; same dimensions
- Mobile: at least 44px controls and 16px field text
- Keyboard: immediate focus outline, modal containment and return focus
- Data states: retain the existing loading, empty, error, and full states

## Motion

State feedback only. No ambient pulse, load reveal, or animated progress width. Reduced motion disables transitions and animations.

## Exports

[web/src/tokens.css](web/src/tokens.css) and [web/src/base.css](web/src/base.css). No external fonts, imagery, or new UI dependencies.
