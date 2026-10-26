import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthService } from "../src/auth.ts";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { createApi } from "../src/api/api.ts";
import { EventLog } from "../src/events.ts";
import { HarnessManager } from "../src/harness/manager.ts";
import { AuditEngine } from "../src/orchestrator/engine.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { DEFAULT_EXCLUDES } from "../src/repo/inventory.ts";
import { ReportService } from "../src/reports/generator.ts";
import { seedDefaults } from "../src/settings.ts";

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
    masterKey: "auth-test-master-key",
    chromeBin: "google-chrome",
    secureCookies: false,
    logLevel: "error",
  };
}

let dir = "";
let store: Store;
let auth: AuthService;

async function projectClient() {
  const settings = config(dir);
  seedDefaults(store, settings);
  const events = new EventLog(store);
  const manager = new HarnessManager(settings, store);
  const evidence = new EvidenceStore(settings, store);
  const reports = new ReportService(settings, store, evidence, events);
  const engine = new AuditEngine(settings, store, manager, evidence, events, reports);
  const api = createApi({ config: settings, store, auth, events, manager, evidence, reports, engine });
  const login = await auth.login(settings.adminEmail, settings.adminPassword!, "local", "test");
  const headers = { cookie: `argus_session=${login.token}`, "x-csrf-token": login.csrf, "content-type": "application/json" };
  return { api, headers, userId: login.user.id };
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "argus-auth-"));
  store = new Store(config(dir), "test.sqlite");
  auth = new AuthService(config(dir), store);
  await auth.bootstrap();
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("bootstrap admin is stored with an argon2id hash and can sign in", async () => {
  const row = store.get<{ password_hash: string; email: string }>("SELECT * FROM users WHERE email = ?", "admin@test.local");
  expect(row?.password_hash.startsWith("$argon2id$")).toBe(true);
  const result = await auth.login("admin@test.local", "test-admin-password", "127.0.0.1", "test");
  expect(result.user.role).toBe("admin");
  expect(result.user).not.toHaveProperty("password_hash");
  expect(result.csrf.length).toBeGreaterThan(20);
  const request = new Request("http://localhost/api/auth/me", {
    headers: { cookie: `argus_session=${encodeURIComponent(result.token)}` },
  });
  const context = auth.authenticate(request);
  expect(context?.user.email).toBe("admin@test.local");
  expect(context?.user).not.toHaveProperty("password_hash");
  expect(auth.verifyCsrf(context!.session, result.csrf)).toBe(true);
  expect(auth.verifyCsrf(context!.session, "wrong")).toBe(false);
});

test("invalid credentials fail and repeated attempts trigger a temporary lock", async () => {
  let lastError = "";
  for (let attempt = 0; attempt < 7; attempt += 1) {
    try {
      await auth.login("admin@test.local", "wrong-password", "10.0.0.9", "test");
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
  }
  expect(lastError).toContain("Too many failed sign-in attempts");
});

test("session cookie and password rotation revoke other sessions", async () => {
  const first = await auth.login("admin@test.local", "test-admin-password", "127.0.0.1", "test");
  const second = await auth.login("admin@test.local", "test-admin-password", "127.0.0.1", "test");
  await auth.changePassword(first.user, "test-admin-password", "a-new-long-password", first.token.length > 0 ? "" : "");
  const sessions = store.all<{ id: string }>("SELECT id FROM auth_sessions WHERE user_id = ?", first.user.id);
  expect(sessions.length).toBe(0);
  const cookie = auth.sessionCookie(second.token);
  expect(cookie).toContain("HttpOnly");
  expect(cookie).toContain("SameSite=Lax");
  expect(auth.sessionCookie("x")).toContain("argus_session=x");
});

test("role hierarchy and user administration", async () => {
  const auditor = await auth.createUser("auditor@test.local", "Auditor", "auditor-password-1", "auditor");
  expect(auditor.role).toBe("auditor");
  expect(auth.listUsers().length).toBe(2);
  auth.updateUser(auditor.id, { role: "viewer" });
  expect(auth.listUsers().find((user) => user.id === auditor.id)?.role).toBe("viewer");
  auth.updateUser(auditor.id, { disabled: true });
  await expect(auth.login("auditor@test.local", "auditor-password-1", "127.0.0.1", "test")).rejects.toThrow();
  const metadata = auth.listUsers();
  expect(metadata.every((user) => !("password_hash" in user))).toBe(true);
});

test("a project needs only a name and repository path while access controls still apply", async () => {
  const { api, headers, userId } = await projectClient();
  const body = JSON.stringify({ name: "My project", source_path: dir });
  const request = (requestHeaders = headers, requestBody = body) => new Request("http://localhost/api/projects", {
    method: "POST", headers: requestHeaders, body: requestBody,
  });
  expect((await api(request({ ...headers, cookie: "" }))).status).toBe(401);
  expect((await api(request({ ...headers, "x-csrf-token": "invalid" }))).status).toBe(403);
  const outside = await api(request(headers, JSON.stringify({ name: "Outside", source_path: tmpdir() })));
  expect(outside.status).toBe(403);
  expect(await outside.json()).toMatchObject({ error: { code: "repository_not_authorized" } });

  const created = await api(request());
  expect(created.status).toBe(201);
  expect(await created.json()).toMatchObject({ project: {
    name: "My project", source_path: dir, authorized_by: "", authorization_ref: "",
    scope_include: ["**/*"], scope_exclude: DEFAULT_EXCLUDES, created_by: userId,
  } });
  expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM projects")?.count).toBe(1);

  store.run("UPDATE users SET role = 'viewer' WHERE id = ?", userId);
  expect((await api(request())).status).toBe(403);
  expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM projects")?.count).toBe(1);
});

test("optional project authorization metadata remains compatible and validated", async () => {
  const { api, headers } = await projectClient();
  const create = (metadata: Record<string, unknown>) => api(new Request("http://localhost/api/projects", {
    method: "POST", headers,
    body: JSON.stringify({ name: "Existing client", source_path: dir, ...metadata }),
  }));
  const legacy = await create({ authorized_by: "Security owner", authorization_ref: "AUTH-123" });
  expect(legacy.status).toBe(201);
  expect(await legacy.json()).toMatchObject({ project: { authorized_by: "Security owner", authorization_ref: "AUTH-123" } });
  const empty = await create({ authorized_by: "", authorization_ref: "" });
  expect(empty.status).toBe(201);
  expect(await empty.json()).toMatchObject({ project: { authorized_by: "", authorization_ref: "" } });
  expect((await create({ authorized_by: 123 })).status).toBe(400);
  expect((await create({ authorization_ref: "x".repeat(501) })).status).toBe(400);
});
