import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthService } from "../src/auth.ts";
import { createApi } from "../src/api/api.ts";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { EventLog } from "../src/events.ts";
import { HarnessManager } from "../src/harness/manager.ts";
import { AuditEngine } from "../src/orchestrator/engine.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { ReportService } from "../src/reports/generator.ts";
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
