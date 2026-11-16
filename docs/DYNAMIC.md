# Dynamic and hybrid audits

Argus can send live HTTP requests to an **authorized** target, record what
was tested, and confirm candidates with independent broker replays. Use this
only on systems you are allowed to test.

The default path is an in-process broker. `src/server.ts` does not start a
worker or broker container. Docker images under `deploy/` exist for a
separate container runtime (`src/dynamic/runtime.ts`) and are not selected
by the default process composition.

## Modes

| Mode | Repository | Live target | Phase 1 (map) |
| --- | --- | --- | --- |
| `static` (default) | Required | Not used | Runs |
| `hybrid` | Required | Required | Runs |
| `dynamic` | Optional | Required | Skipped |

Create the audit from **New audit** or `POST /api/audits` with `mode` and,
for `dynamic`/`hybrid`, `target_id`. Starting a non-static audit fails if
the target is missing, disabled, has no active authorization covering now,
or has no active test identity.

## Operator workflow

1. Create a project as usual. Hybrid still needs an imported snapshot;
   dynamic-only may omit a repository.
2. On the project, add a **target**: label, absolute `http`/`https` URL
   (no embedded credentials), environment name, and at least one allowed
   host. Methods default to `GET`, `HEAD`, `OPTIONS`. TLS is required
   unless `tls_required` is explicitly false. Default rate limit is 5 rps.
3. Add an **authorization** with who authorized it, a reference, ISO
   `valid_from` / `valid_until`, and `authorized_actions`. Validity is
   stored as UTC. Start refuses the audit when no row is currently active.
4. Add at least one **test identity** (`auth_kind`: `none`, `header`,
   `cookie`, or `basic`). Authenticated identities need `secret_ref`, which
   must name a credential stored with provider `test-identity`. Secrets are
   injected at the broker and never returned by identity APIs.
5. Start the audit. Argus freezes a scope snapshot
   (`audit_scope_snapshots`). Later edits to the live target tables do not
   rewrite that snapshot. Replay still re-checks that the target and
   authorization are **currently** active, so revocation stops traffic.

Dashboard copy: “Dynamic audits need an active authorization and at least
one test identity.” Requests are described as running through the broker
under the recorded authorization.

## What runs by default

`AuditEngine` uses `createBrokerDynamicExecutor`. For an untested app asset
it proposes one intent: a **GET** of the target path, and only if GET is in
`allowed_methods`. The executor opens a per-audit in-process broker, sends
that request, and records the response. It does not launch Pi or Claude as
a planner or worker.

Exploration state is visible at `GET /api/audits/:id/exploration` (assets,
nodes, edges, anchors, coverage). Coverage and Exploration pages share that
payload.

A later harness-backed planner can replace the executor through
`setDynamicExecutor`. That is an integration surface, not the default.

## Confirmation and evidence

Dynamic candidates are proposed with `POST /api/audits/:id/candidates`
(`audit:propose_candidate`) and confirmed with
`POST /api/candidates/:id/confirm` (`audit:confirm_candidate`). Static
audits reject both.

A proposal must include a PoC **manifest** (language, object owner, three
named checks, environment) and a script string. Each check names an
identity from this audit’s snapshot and a request `{method, path}`. The
positive control must use the object owner; the exploit and negative
control must use a different shared identity. Argus does not accept caller
supply of response bodies.

Confirmation **replays** the three checks through a fresh broker. The live
target and authorization must still be active. Identity secrets are
injected by the broker, redacted from stored exchanges, and refused if they
appear in the manifest. A source quote, if supplied, is checked against
the imported snapshot; a false quote refutes the candidate. Dynamic
confirmation does not require a source quote when none is offered.

Replay constraints match [the security model](SECURITY.md#dynamic-replay-transport):
declared methods only, `/__argus/forward` inside the broker, DNS and
CIDR/private-address checks, 35s client / 30s broker deadlines, 5,000,000
byte response cap.

## Adapter tokens

Workers talk to Argus with `Authorization: Bearer` tokens issued at
`POST /api/tokens` (cookie session required). The raw secret is returned
once. Scopes are exact; `task:create` does not imply
`audit:launch_dynamic`. Creating an `explore` task also requires a running
`dynamic` or `hybrid` audit.

An audit-bound token cannot create another audit. Collection queries
intersect project/audit bindings. Token routes are the allowlist in
`src/api/token-policy.ts`; everything else needs a cookie session.

## Constraints and pitfalls

- **Authorization is not a prompt.** Every request is checked against the
  frozen host, method, CIDR, TLS, and rate policy, then against the live
  authorization on replay.
- **GET-only targets get a GET baseline.** If GET is not allowed, the
  default planner returns no intents.
- **Private addresses fail closed** unless an explicit CIDR allows them.
  Invalid CIDRs grant nothing.
- **Docker Compose** still only runs the Argus app. Building
  `deploy/Dockerfile.broker` / `Dockerfile.worker` does not change the
  default executor.
- **Do not mount identity secrets into agent workspaces.** Store them as
  `test-identity` credentials and let the broker inject them.
- The historical design note `docs/ryugi/specs/2026-10-27-argus-dynamic-layer-design.md`
  describes the intended full loop (container workers, harness planner).
  Treat it as design history; this page is the implemented operator path.

## Related code

| Area | Path |
| --- | --- |
| Target, auth, identity, snapshot | `src/dynamic/targets.ts` |
| Default executor and PoC replay | `src/dynamic/executor.ts` |
| Broker policy and forwarding | `src/dynamic/broker.ts`, `src/dynamic/http.ts`, `src/dynamic/egress.ts` |
| Credential injection | `src/dynamic/credentials.ts` |
| Graphs and coverage | `src/dynamic/graph.ts` |
| Propose/confirm | `src/dynamic/proof.ts`, `src/dynamic/poc.ts` |
| Optional container runtime | `src/dynamic/runtime.ts` |
| HTTP routes | `src/api/api.ts` |
