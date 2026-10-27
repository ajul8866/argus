import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApi } from "../src/api/api.ts";
import { AuthService } from "../src/auth.ts";
import { TokenService } from "../src/auth/tokens.ts";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { EventLog } from "../src/events.ts";
import { HarnessManager } from "../src/harness/manager.ts";
import { AuditEngine } from "../src/orchestrator/engine.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { ReportService } from "../src/reports/generator.ts";
import { getSetting, seedDefaults } from "../src/settings.ts";
import { now, sha256 } from "../src/util.ts";

let dir: string;
let store: Store;
let tokens: TokenService;
let api: ReturnType<typeof createApi>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "argus-token-boundaries-"));
  const config: Config = {
    port: 0, hostname: "127.0.0.1", dataDir: dir, webDist: join(dir, "web"),
    adminEmail: "admin@test.local", adminPassword: null, sessionTtlMs: 60_000,
    maxConcurrentAgents: 2, sandboxMode: "none", piBin: "/missing/pi", claudeBin: "/missing/claude",
    allowedRoots: [dir], masterKey: "synthetic-test-key", chromeBin: "/missing/chrome",
    secureCookies: false, logLevel: "error",
  };
  store = new Store(config, "test.sqlite");
  seedDefaults(store, config);
  store.run("INSERT INTO users (id,email,name,password_hash,role,created_at) VALUES ('u1','admin@test.local','Admin','x','admin',?)", now());
  for (const [projectId, auditId] of [["p1", "a1"], ["p2", "a2"], ["p1", "a3"]]) {
    store.run("INSERT OR IGNORE INTO projects (id,name,source_path,scope_include,scope_exclude,authorized_by,authorization_ref,created_at,updated_at) VALUES (?,?,?,'[\"**/*\"]','[]','','',?,?)", projectId, projectId, dir, now(), now());
    store.run("INSERT INTO audits (id,project_id,status,current_phase,config,created_at) VALUES (?,?,'queued',1,'{}',?)", auditId, projectId, now());
    store.run("INSERT INTO findings (id,code,audit_id,project_id,title,category,severity,status,files,root_cause,preconditions,reproduction,expected,observed,impact,remediation,created_at,updated_at) VALUES (?,?,?,?,'Synthetic finding','test','low','unresolved','[]','','[]','[]','','','','',?,?)", `f-${auditId}`, `ARG-${auditId}`, auditId, projectId, now(), now());
    store.run("INSERT INTO tasks (id,audit_id,phase,kind,task_key,title,status,payload,created_at) VALUES (?,?,1,'phase1.map','map','Map','queued','{}',?)", `t-${auditId}`, auditId, now());
  }
  const auth = new AuthService(config, store);
  const events = new EventLog(store);
  const manager = new HarnessManager(config, store);
  const evidence = new EvidenceStore(config, store);
  const reports = new ReportService(config, store, evidence, events);
  const engine = new AuditEngine(config, store, manager, evidence, events, reports);
  api = createApi({ config, store, auth, events, manager, evidence, reports, engine });
  tokens = new TokenService(store);
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function token(scopes = ["audit:read"], binding: { projectId?: string; auditId?: string } = { auditId: "a1" }): string {
  return tokens.create({ userId: "u1", label: "Worker", scopes, ...binding }).raw;
}

function call(raw: string, path: string, method = "GET", body?: unknown, extraHeaders: Record<string, string> = {}) {
  return api(new Request(`http://localhost${path}`, {
    method,
    headers: { authorization: `Bearer ${raw}`, "content-type": "application/json", ...extraHeaders },
    body: body === undefined ? undefined : JSON.stringify(body),
  }));
}

describe("bearer token boundaries", () => {
  test("an audit reader cannot change administrator settings", async () => {
    const before = getSetting(store, "reports.organization", "");
    const response = await call(token(), "/api/settings", "PUT", { settings: { "reports.organization": "Changed by reader" } });
    expect(response.status).toBe(403);
    expect(getSetting(store, "reports.organization", "")).toBe(before);
  });

  test("a limited token cannot mint an unrestricted replacement", async () => {
    const raw = token();
    const before = store.all("SELECT id FROM api_tokens").length;
    const response = await call(raw, "/api/tokens", "POST", { label: "Escalated", scopes: ["target:manage"], project_id: "p2" });
    expect(response.status).toBe(403);
    expect(store.all("SELECT id FROM api_tokens")).toHaveLength(before);
  });

  for (const [method, path] of [
    ["GET", "/api/auth/me"], ["POST", "/api/auth/logout"], ["POST", "/api/auth/password"],
    ["GET", "/api/users"], ["GET", "/api/settings"], ["GET", "/api/credentials"],
    ["GET", "/api/overview"], ["GET", "/api/events/stream"], ["GET", "/api/tokens"],
  ]) {
    test(`a worker token is refused by the cookie-only ${method} ${path} route`, async () => {
      const response = await call(token(), path!, method);
      await response.body?.cancel();
      expect(response.status).toBe(403);
    });
  }

  test("audit and finding lists intersect the token audit binding before returning rows", async () => {
    const raw = token(["audit:read", "finding:read"]);
    const audits = await call(raw, "/api/audits");
    expect(audits.status).toBe(200);
    expect((await audits.json()).audits.map((audit: { id: string }) => audit.id)).toEqual(["a1"]);
    const findings = await call(raw, "/api/findings");
    expect(findings.status).toBe(200);
    expect((await findings.json()).findings.map((finding: { id: string }) => finding.id)).toEqual(["f-a1"]);
    expect((await call(raw, "/api/audits?project_id=p2")).status).toBe(403);
    expect((await call(raw, "/api/findings?audit_id=a3")).status).toBe(403);
  });

  test("a project token cannot access a different project through audit subresources", async () => {
    const raw = token(["audit:read", "finding:read"], { projectId: "p1" });
    for (const suffix of ["tasks", "sessions", "exploration", "events", "stream", "evidence", "reports"]) {
      const response = await call(raw, `/api/audits/a2/${suffix}`);
      await response.body?.cancel();
      expect(response.status).toBe(403);
    }
    expect((await call(raw, "/api/tasks/t-a2")).status).toBe(403);
    expect((await call(raw, "/api/tasks/t-a1")).status).toBe(200);
    const response = await call(raw, "/api/findings");
    expect((await response.json()).findings.map((finding: { audit_id: string }) => finding.audit_id).sort()).toEqual(["a1", "a3"]);
  });

  test("route scopes and both project and audit bindings remain independent requirements", async () => {
    const raw = token(["task:create"]);
    expect((await call(raw, "/api/audits")).status).toBe(403);
    expect((await call(raw, "/api/tasks/t-a1")).status).toBe(403);
    expect((await call(raw, "/api/audits/a1/events")).status).toBe(403);
    const bound = token(["audit:read", "finding:read"]);
    expect((await call(bound, "/api/audits/a3/tasks")).status).toBe(403);
    expect((await call(bound, "/api/findings/f-a3")).status).toBe(403);
    expect(() => token(["audit:read"], { projectId: "p2", auditId: "a1" })).toThrow();
  });

  test("an audit-bound launch token cannot create another audit", async () => {
    const raw = token(["audit:launch_dynamic"]);
    const response = await call(raw, "/api/audits", "POST", { project_id: "p1", mode: "dynamic" });
    expect(response.status).toBe(403);
    expect(store.all("SELECT id FROM audits")).toHaveLength(3);
  });

  test("bound rows are selected before collection limits and owner roles still restrict token grants", async () => {
    store.transaction(() => {
      for (let index = 0; index < 120; index += 1) {
        store.run("INSERT INTO audits (id,project_id,status,current_phase,config,created_at) VALUES (?,'p2','queued',1,'{}','2098-01-01T00:00:00.000Z')", `foreign-${index}`);
      }
      for (let index = 0; index < 501; index += 1) {
        store.run(`INSERT INTO findings (id,code,audit_id,project_id,title,category,severity,status,files,root_cause,preconditions,reproduction,expected,observed,impact,remediation,created_at,updated_at)
          SELECT ?,?,'a2','p2',title,category,severity,status,files,root_cause,preconditions,reproduction,expected,observed,impact,remediation,'2098-01-01T00:00:00.000Z',updated_at FROM findings WHERE id = 'f-a2'`, `foreign-f-${index}`, `FOREIGN-${index}`);
      }
    });
    const raw = token(["audit:read", "finding:read"]);
    expect((await (await call(raw, "/api/audits")).json()).audits.map((row: { id: string }) => row.id)).toEqual(["a1"]);
    expect((await (await call(raw, "/api/findings")).json()).findings.map((row: { id: string }) => row.id)).toEqual(["f-a1"]);
    const manager = token(["target:manage"], { projectId: "p1" });
    store.run("UPDATE users SET role = 'viewer' WHERE id = 'u1'");
    expect((await call(manager, "/api/projects/p1/targets", "POST", {})).status).toBe(403);
  });

  test("cookie sessions retain CSRF checks and a bearer header never falls back to cookie authority", async () => {
    store.run("INSERT INTO auth_sessions (id,user_id,csrf_token,created_at,expires_at) VALUES (?,'u1','synthetic-csrf',?,'2099-01-01T00:00:00.000Z')", sha256("synthetic-session"), now());
    const headers = { cookie: "argus_session=synthetic-session", "content-type": "application/json" };
    const body = JSON.stringify({ settings: { "reports.organization": "Browser update" } });
    expect((await api(new Request("http://localhost/api/settings", { method: "PUT", headers, body }))).status).toBe(403);
    expect((await api(new Request("http://localhost/api/settings", { method: "PUT", headers: { ...headers, "x-csrf-token": "synthetic-csrf" }, body }))).status).toBe(200);
    const limited = await call(token(), "/api/settings", "PUT", { settings: { "reports.organization": "Token update" } }, { ...headers, "x-csrf-token": "synthetic-csrf" });
    expect(limited.status).toBe(403);
    expect((await call("argus_invalid", "/api/audits", "GET", undefined, headers)).status).toBe(401);
  });
});
