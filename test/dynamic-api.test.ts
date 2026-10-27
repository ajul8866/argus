import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthService } from "../src/auth.ts";
import { TokenService } from "../src/auth/tokens.ts";
import { createApi } from "../src/api/api.ts";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { GraphStore } from "../src/dynamic/graph.ts";
import { EventLog } from "../src/events.ts";
import { HarnessManager } from "../src/harness/manager.ts";
import { AuditEngine } from "../src/orchestrator/engine.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { ReportService } from "../src/reports/generator.ts";
import { encryptSecret } from "../src/security/credentials.ts";
import { seedDefaults } from "../src/settings.ts";
import { now } from "../src/util.ts";

function config(dataDir: string): Config {
  return {
    port: 0,
    hostname: "127.0.0.1",
    dataDir,
    webDist: join(dataDir, "web"),
    adminEmail: "admin@test.local",
    adminPassword: "test-admin-password",
    sessionTtlMs: 60_000,
    maxConcurrentAgents: 2,
    sandboxMode: "none",
    piBin: "pi",
    claudeBin: "claude",
    allowedRoots: [dataDir],
    masterKey: "dynamic-api-test-key",
    chromeBin: "google-chrome",
    secureCookies: false,
    logLevel: "error",
  };
}

let dir = "";
let store: Store;
let targetServer: Server | null = null;
let engine: AuditEngine | null = null;

afterEach(async () => {
  await engine?.stop();
  engine = null;
  if (targetServer) {
    await new Promise<void>((resolve) => targetServer!.close(() => resolve()));
    targetServer = null;
  }
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("a dynamic audit created through the API explores, reports, and completes", async () => {
  dir = mkdtempSync(join(tmpdir(), "argus-dynamic-api-"));
  const settings = config(dir);
  store = new Store(settings, "test.sqlite");
  seedDefaults(store, settings);
  const auth = new AuthService(settings, store);
  await auth.bootstrap();

  targetServer = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/health") {
      response.writeHead(200, { "content-type": "text/plain" }).end("ok");
      return;
    }
    response.writeHead(404, { "content-type": "application/json" }).end('{"error":"not found"}');
  });
  await new Promise<void>((resolve) => targetServer!.listen(0, "127.0.0.1", resolve));
  const port = (targetServer.address() as { port: number }).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const events = new EventLog(store);
  const manager = new HarnessManager(settings, store);
  const evidence = new EvidenceStore(settings, store);
  const reports = new ReportService(settings, store, evidence, events);
  engine = new AuditEngine(settings, store, manager, evidence, events, reports);
  const api = createApi({ config: settings, store, auth, events, manager, evidence, reports, engine });
  const login = await auth.login(settings.adminEmail, settings.adminPassword!, "local", "test");
  const headers = { cookie: `argus_session=${login.token}`, "x-csrf-token": login.csrf, "content-type": "application/json" };

  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p_api','Invoice portal', ?, '**/*', '', 'Tester', 'AUTH-API', ?, ?)`,
    dir,
    now(),
    now(),
  );

  const call = async (path: string, init: RequestInit = {}) => {
    const response = await api(new Request(`http://localhost${path}`, { ...init, headers: { ...headers, ...(init.headers ?? {}) } }));
    return { status: response.status, body: await response.json().catch(() => null) };
  };

  const target = await call("/api/projects/p_api/targets", {
    method: "POST",
    body: JSON.stringify({
      label: "Invoice portal",
      base_url: baseUrl,
      environment: "test",
      allowed_hosts: ["127.0.0.1"],
      allowed_cidrs: ["127.0.0.1/32"],
      allowed_methods: ["GET"],
      max_rps: 50,
      tls_required: false,
    }),
  });
  expect(target.status).toBe(201);
  const targetId = target.body.target.id;

  const authorization = await call(`/api/targets/${targetId}/authorizations`, {
    method: "POST",
    body: JSON.stringify({
      authorized_by: "Tester",
      authorization_ref: "AUTH-API",
      valid_from: new Date(Date.now() - 60_000).toISOString(),
      valid_until: new Date(Date.now() + 3_600_000).toISOString(),
      authorized_actions: { methods: ["GET"] },
    }),
  });
  expect(authorization.status).toBe(201);

  const identity = await call(`/api/targets/${targetId}/identities`, {
    method: "POST",
    body: JSON.stringify({ label: "anon", role: "user", auth_kind: "none" }),
  });
  expect(identity.status).toBe(201);

  const created = await call("/api/audits", {
    method: "POST",
    body: JSON.stringify({ project_id: "p_api", mode: "dynamic", target_id: targetId }),
  });
  expect(created.status).toBe(201);
  const auditId = created.body.audit.id;

  const listed = await call("/api/audits");
  expect(listed.body.audits.some((audit: { id: string }) => audit.id === auditId)).toBe(true);

  const started = await call(`/api/audits/${auditId}/start`, { method: "POST" });
  expect(started.status).toBe(200);
  expect(started.body.audit.exploration_status).toBe("open");

  // The scheduler is the only driver: nothing below calls the engine directly.
  engine.start();
  const deadline = Date.now() + 25_000;
  let final: { status: string; exploration_status: string | null } | null = null;
  while (Date.now() < deadline) {
    final = store.get<{ status: string; exploration_status: string | null }>(
      "SELECT status, exploration_status FROM audits WHERE id = ?",
      auditId,
    );
    if (final && ["completed", "completed_with_errors", "failed"].includes(final.status)) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  expect(final?.status).toBe("completed");
  expect(final?.exploration_status).toBe("closed");

  const coverage = await call(`/api/audits/${auditId}/exploration`);
  expect(coverage.status).toBe(200);
  expect(coverage.body.assets).toHaveLength(1);
  expect(coverage.body.assets[0]).toMatchObject({ kind: "app", assetKey: baseUrl });
  expect(coverage.body.coverage[0].tested).toBe(true);
  expect(coverage.body.nodes.some((node: { kind: string; status: string }) =>
    node.kind === "fact" && node.status === "completed")).toBe(true);

  await engine.reconcileForTest(auditId);

  const phases = store.all<{ phase: number; status: string }>(
    "SELECT phase, status FROM audit_phases WHERE audit_id = ? ORDER BY phase",
    auditId,
  );
  expect(phases.find((phase) => phase.phase === 1)?.status).toBe("skipped");
  expect(phases.find((phase) => phase.phase === 2)?.status).toBe("completed");
  expect(phases.find((phase) => phase.phase === 6)?.status).toBe("completed");

  const generated = await reports.generate(auditId, ["markdown", "json"], "test");
  expect(generated).toHaveLength(2);
}, 40_000);

test("a worker proposes and an independent run confirms a dynamic candidate", async () => {
  dir = mkdtempSync(join(tmpdir(), "argus-candidate-api-"));
  const settings = config(dir);
  store = new Store(settings, "test.sqlite");
  seedDefaults(store, settings);
  const auth = new AuthService(settings, store);
  await auth.bootstrap();

  targetServer = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const owner = request.headers.authorization === "Bearer token-b" ? "user_b" : "user_a";
    const match = /^\/invoices\/([^/]+)$/.exec(url.pathname);
    if (!match) {
      response.writeHead(404).end("{}");
      return;
    }
    if (match[1] === "inv-1" || (match[1] === "inv-2" && owner === "user_a")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ invoice: { id: match[1], owner_id: match[1] === "inv-1" ? "user_b" : "user_a" } }));
      return;
    }
    response.writeHead(404).end("{}");
  });
  await new Promise<void>((resolve) => targetServer!.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(targetServer.address() as { port: number }).port}`;

  const events = new EventLog(store);
  const manager = new HarnessManager(settings, store);
  const evidence = new EvidenceStore(settings, store);
  const reports = new ReportService(settings, store, evidence, events);
  engine = new AuditEngine(settings, store, manager, evidence, events, reports);
  const api = createApi({ config: settings, store, auth, events, manager, evidence, reports, engine });
  const login = await auth.login(settings.adminEmail, settings.adminPassword!, "local", "test");
  const headers = { cookie: `argus_session=${login.token}`, "x-csrf-token": login.csrf, "content-type": "application/json" };
  const call = async (path: string, init: RequestInit = {}) => {
    const response = await api(new Request(`http://localhost${path}`, { ...init, headers: { ...headers, ...(init.headers ?? {}) } }));
    return { status: response.status, body: await response.json().catch(() => null) };
  };

  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p_c','Candidate', ?, '**/*', '', 'Tester', 'AUTH-C', ?, ?)`,
    join(import.meta.dir, "fixtures", "vulnerable-app"),
    now(),
    now(),
  );
  store.run(
    `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('r_c','p_c',?, 'abc123','main','{}','[]','{}','{}',1,10,?)`,
    join(import.meta.dir, "fixtures", "vulnerable-app"),
    now(),
  );

  const target = await call("/api/projects/p_c/targets", {
    method: "POST",
    body: JSON.stringify({
      label: "Candidate target",
      base_url: baseUrl,
      environment: "test",
      repository_id: "r_c",
      allowed_hosts: ["127.0.0.1"],
      allowed_cidrs: ["127.0.0.1/32"],
      allowed_methods: ["GET"],
      max_rps: 100,
      tls_required: false,
    }),
  });
  expect(target.status).toBe(201);
  const targetId = target.body.target.id;
  await call(`/api/targets/${targetId}/authorizations`, {
    method: "POST",
    body: JSON.stringify({
      authorized_by: "Tester",
      authorization_ref: "AUTH-C",
      valid_from: new Date(Date.now() - 60_000).toISOString(),
      valid_until: new Date(Date.now() + 3_600_000).toISOString(),
      authorized_actions: { methods: ["GET"] },
    }),
  });
  const identityA = await call(`/api/targets/${targetId}/identities`, {
    method: "POST",
    body: JSON.stringify({ label: "user_a", role: "user", auth_kind: "header", secret_ref: "c:user_a" }),
  });
  const identityB = await call(`/api/targets/${targetId}/identities`, {
    method: "POST",
    body: JSON.stringify({ label: "user_b", role: "user", auth_kind: "header", secret_ref: "c:user_b" }),
  });
  for (const [ref, token] of [["c:user_a", "token-a"], ["c:user_b", "token-b"]] as const) {
    const encrypted = encryptSecret(settings, token);
    store.run(
      `INSERT INTO provider_credentials (id, provider, env_var, ciphertext, iv, tag, last4, created_at, updated_at)
       VALUES (?, 'test-identity', ?, ?, ?, ?, ?, ?, ?)`,
      `cred-${ref}`,
      ref,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.tag,
      encrypted.last4,
      now(),
      now(),
    );
  }

  const created = await call("/api/audits", {
    method: "POST",
    body: JSON.stringify({ project_id: "p_c", repository_id: "r_c", mode: "dynamic", target_id: targetId }),
  });
  const auditId = created.body.audit.id;
  await call(`/api/audits/${auditId}/start`, { method: "POST" });
  // Stop the scheduler from racing the explicit proposal in this test.
  await engine.stop();
  engine = null;
  const asset = new GraphStore(store).upsertAsset({ projectId: "p_c", kind: "app", assetKey: baseUrl });

  const manifest = {
    language: "typescript",
    script_evidence_id: "pending",
    object: { asset_id: asset.id, object_id: "inv-1", owner_identity: identityB.body.identity.id },
    checks: {
      positive: {
        identity: identityB.body.identity.id,
        request: { method: "GET", path: "/invoices/inv-1" },
        expect: { status: 200, body_contains: "inv-1" },
      },
      exploit: {
        identity: identityA.body.identity.id,
        request: { method: "GET", path: "/invoices/inv-1" },
        expect: { status: 200, body_contains: "inv-1" },
      },
      negative: {
        identity: identityA.body.identity.id,
        request: { method: "GET", path: "/invoices/missing" },
        expect: { status: 404 },
      },
    },
    environment: { target: baseUrl, commit_sha: "abc123", identities: [identityA.body.identity.id, identityB.body.identity.id] },
  };

  const reader = new TokenService(store).create({
    userId: login.user.id,
    label: "reader",
    scopes: ["finding:read"],
    auditId,
  });
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p_other','Other', ?, '**/*', '', 'Tester', 'AUTH-O', ?, ?)`,
    dir,
    now(),
    now(),
  );
  const crossProject = new TokenService(store).create({
    userId: login.user.id,
    label: "scoped",
    scopes: ["audit:propose_candidate"],
    projectId: "p_other",
  });

  const base = {
    asset_id: asset.id,
    title: "Cross-tenant invoice read",
    category: "idor",
    severity: "high",
    manifest,
    script: "requests.get('/invoices/inv-1')",
    proposed_by: "worker-1",
    source: {
      path: "src/routes/invoices.js",
      start_line: 11,
      end_line: 17,
      quote: "router.get(\"/:id\", (request, response) => {\n  const invoice = findInvoiceById(request.params.id);",
    },
  };

  const wrongScope = await call(`/api/audits/${auditId}/candidates`, {
    method: "POST",
    body: JSON.stringify(base),
    headers: { authorization: `Bearer ${reader.raw}` },
  });
  expect(wrongScope.status).toBe(403);

  const otherProject = await call(`/api/audits/${auditId}/candidates`, {
    method: "POST",
    body: JSON.stringify(base),
    headers: { authorization: `Bearer ${crossProject.raw}` },
  });
  expect(otherProject.status).toBe(403);

  const proposed = await call(`/api/audits/${auditId}/candidates`, { method: "POST", body: JSON.stringify(base) });
  expect(proposed.status).toBe(201);
  expect(proposed.body.sourceVerified).toBe(true);
  const candidateId = proposed.body.candidateId;
  expect(store.get<{ status: string }>("SELECT status FROM candidates WHERE id = ?", candidateId)).toEqual({
    status: "discovered",
  });
  expect(store.get("SELECT id FROM findings WHERE audit_id = ?", auditId)).toBeNull();

  const selfConfirm = await call(`/api/candidates/${candidateId}/confirm`, {
    method: "POST",
    body: JSON.stringify({ confirmed_by: "worker-1" }),
  });
  expect(selfConfirm.status).toBe(409);

  const confirmed = await call(`/api/candidates/${candidateId}/confirm`, {
    method: "POST",
    body: JSON.stringify({ confirmed_by: "validator-1" }),
  });
  expect(confirmed.status).toBe(200);
  expect(confirmed.body.verdict).toBe("CONFIRMED");
  expect(confirmed.body.code).toBe("DYN-001");
  expect(store.get<{ status: string }>("SELECT status FROM candidates WHERE id = ?", candidateId)).toEqual({
    status: "confirmed",
  });
  expect(
    store.get<{ verdict: string }>("SELECT verdict FROM verifications WHERE candidate_id = ? AND kind = 'confirmation'", candidateId),
  ).toEqual({ verdict: "CONFIRMED" });

  const fabricated = await call(`/api/audits/${auditId}/candidates`, {
    method: "POST",
    body: JSON.stringify({
      ...base,
      source: { path: "src/routes/invoices.js", start_line: 1, end_line: 2, quote: "this line does not exist anywhere" },
    }),
  });
  expect(fabricated.status).toBe(400);
  expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM findings WHERE audit_id = ?", auditId)!.count).toBe(1);
}, 40_000);

test("a retest route records a row and the task runs it deterministically", async () => {
  dir = mkdtempSync(join(tmpdir(), "argus-retest-api-"));
  const settings = config(dir);
  store = new Store(settings, "test.sqlite");
  seedDefaults(store, settings);
  const auth = new AuthService(settings, store);
  await auth.bootstrap();

  targetServer = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== "/invoices/inv-1") {
      response.writeHead(404).end("{}");
      return;
    }
    if (request.headers.authorization === "Bearer token-a") {
      response.writeHead(403).end('{"error":"forbidden"}');
      return;
    }
    response.writeHead(200, { "content-type": "application/json" }).end('{"invoice":{"id":"inv-1"}}');
  });
  await new Promise<void>((resolve) => targetServer!.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(targetServer.address() as { port: number }).port}`;

  const events = new EventLog(store);
  const manager = new HarnessManager(settings, store);
  const evidence = new EvidenceStore(settings, store);
  const reports = new ReportService(settings, store, evidence, events);
  engine = new AuditEngine(settings, store, manager, evidence, events, reports);
  const api = createApi({ config: settings, store, auth, events, manager, evidence, reports, engine });
  const login = await auth.login(settings.adminEmail, settings.adminPassword!, "local", "test");
  const headers = { cookie: `argus_session=${login.token}`, "x-csrf-token": login.csrf, "content-type": "application/json" };
  const call = async (path: string, init: RequestInit = {}) => {
    const response = await api(new Request(`http://localhost${path}`, { ...init, headers: { ...headers, ...(init.headers ?? {}) } }));
    return { status: response.status, body: await response.json().catch(() => null) };
  };

  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p_r','Retest', ?, '**/*', '', 'Tester', 'AUTH-R', ?, ?)`,
    join(import.meta.dir, "fixtures", "vulnerable-app"),
    now(),
    now(),
  );
  store.run(
    `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('r_r','p_r',?, 'abc123','main','{}','[]','{}','{}',1,10,?)`,
    join(import.meta.dir, "fixtures", "vulnerable-app"),
    now(),
  );
  const target = await call("/api/projects/p_r/targets", {
    method: "POST",
    body: JSON.stringify({
      label: "Retest target",
      base_url: baseUrl,
      environment: "test",
      repository_id: "r_r",
      allowed_hosts: ["127.0.0.1"],
      allowed_cidrs: ["127.0.0.1/32"],
      allowed_methods: ["GET"],
      max_rps: 100,
      tls_required: false,
    }),
  });
  const targetId = target.body.target.id;
  await call(`/api/targets/${targetId}/authorizations`, {
    method: "POST",
    body: JSON.stringify({
      authorized_by: "Tester",
      authorization_ref: "AUTH-R",
      valid_from: new Date(Date.now() - 60_000).toISOString(),
      valid_until: new Date(Date.now() + 3_600_000).toISOString(),
      authorized_actions: { methods: ["GET"] },
    }),
  });
  const identityA = await call(`/api/targets/${targetId}/identities`, {
    method: "POST",
    body: JSON.stringify({ label: "user_a", role: "user", auth_kind: "header", secret_ref: "r:user_a" }),
  });
  const identityB = await call(`/api/targets/${targetId}/identities`, {
    method: "POST",
    body: JSON.stringify({ label: "user_b", role: "user", auth_kind: "header", secret_ref: "r:user_b" }),
  });
  for (const [ref, token] of [["r:user_a", "token-a"], ["r:user_b", "token-b"]] as const) {
    const encrypted = encryptSecret(settings, token);
    store.run(
      `INSERT INTO provider_credentials (id, provider, env_var, ciphertext, iv, tag, last4, created_at, updated_at)
       VALUES (?, 'test-identity', ?, ?, ?, ?, ?, ?, ?)`,
      `cred-${ref}`,
      ref,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.tag,
      encrypted.last4,
      now(),
      now(),
    );
  }
  const audit = await call("/api/audits", {
    method: "POST",
    body: JSON.stringify({ project_id: "p_r", repository_id: "r_r", mode: "dynamic", target_id: targetId }),
  });
  const auditId = audit.body.audit.id;
  await call(`/api/audits/${auditId}/start`, { method: "POST" });
  await engine.stop();
  engine = null;

  const asset = new GraphStore(store).upsertAsset({ projectId: "p_r", kind: "app", assetKey: baseUrl });
  const aId = identityA.body.identity.id;
  const bId = identityB.body.identity.id;
  const manifest = {
    language: "typescript",
    script_evidence_id: "pending",
    object: { asset_id: asset.id, object_id: "inv-1", owner_identity: bId },
    checks: {
      positive: { identity: bId, request: { method: "GET", path: "/invoices/inv-1" }, expect: { status: 200, body_contains: "inv-1" } },
      exploit: { identity: aId, request: { method: "GET", path: "/invoices/inv-1" }, expect: { status: 403 } },
      negative: { identity: aId, request: { method: "GET", path: "/nope" }, expect: { status: 404 } },
    },
    environment: { target: baseUrl, commit_sha: "abc123", identities: [aId, bId] },
  };
  const proposed = await call(`/api/audits/${auditId}/candidates`, {
    method: "POST",
    body: JSON.stringify({
      asset_id: asset.id,
      title: "Cross-tenant read",
      category: "idor",
      severity: "high",
      manifest,
      script: "requests.get('/invoices/inv-1')",
      proposed_by: "worker-1",
    }),
  });
  expect(proposed.status).toBe(201);
  const confirmed = await call(`/api/candidates/${proposed.body.candidateId}/confirm`, {
    method: "POST",
    body: JSON.stringify({ confirmed_by: "validator-1" }),
  });
  expect(confirmed.body.verdict).toBe("CONFIRMED");
  const findingId = confirmed.body.findingId;

  const retest = await call(`/api/findings/${findingId}/retest`, {
    method: "POST",
    body: JSON.stringify({
      reason: "ownership check added",
      environment_match: true,
      environment_manifest: JSON.stringify({ target: baseUrl, commit_sha: "abc123" }),
      commit_sha: "abc123",
    }),
  });
  expect(retest.status).toBe(201);
  const retestRow = store.get<{ status: string; verdict: string | null; environment_match: number }>(
    "SELECT status, verdict, environment_match FROM retests WHERE finding_id = ?",
    findingId,
  )!;
  expect(retestRow).toMatchObject({ status: "queued", verdict: null, environment_match: 1 });

  const engine2 = new AuditEngine(settings, store, manager, evidence, events, reports);
  engine = engine2;
  engine2.start();
  const deadline = Date.now() + 20_000;
  let verdict: string | null = null;
  while (Date.now() < deadline) {
    verdict = store.get<{ verdict: string | null }>(
      "SELECT verdict FROM retests WHERE finding_id = ?",
      findingId,
    )?.verdict ?? null;
    if (verdict) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  expect(verdict).toBe("still_reproducible");
}, 60_000);
