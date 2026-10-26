import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
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
import { getSetting, harnessConfig, saveHarnessConfig, seedDefaults, setSetting } from "../src/settings.ts";

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

test("folder discovery requires an auditor and only lists folders within configured locations", async () => {
  const { api, headers, userId } = await projectClient();
  mkdirSync(join(dir, "smart-contract", ".git"), { recursive: true });
  const request = (suffix = "", requestHeaders = headers) => new Request(`http://localhost/api/repository-folders${suffix}`, { headers: requestHeaders });
  expect((await api(request("", { ...headers, cookie: "" }))).status).toBe(401);
  const listing = await api(request());
  expect(listing.status).toBe(200);
  const body = await listing.json();
  expect(body.folders).toContainEqual({ name: "smart-contract", path: join(body.path, "smart-contract"), is_repository: true });
  expect((await api(request(`?path=${encodeURIComponent(tmpdir())}`))).status).toBe(403);
  expect((await api(request("?offset=abc"))).status).toBe(400);
  store.run("UPDATE users SET role = 'auditor' WHERE id = ?", userId);
  expect((await api(request())).status).toBe(200);
  store.run("UPDATE users SET role = 'viewer' WHERE id = ?", userId);
  expect((await api(request())).status).toBe(403);
});

test("one explicit runtime assignment configures all audit roles to inherit its tools", async () => {
  const { api, headers } = await projectClient();
  store.run("UPDATE agent_defs SET model = 'old/model', enabled = 0, allow_shell = 1 WHERE role = 'codebase_mapper'");
  const beforeSystemRoles = store.all("SELECT * FROM agent_defs WHERE role IN ('findings_manager','report_writer')");
  const response = await api(new Request("http://localhost/api/harnesses/claude-code/assign", { method: "POST", headers }));
  expect(response.status).toBe(200);
  const roles = store.all<{ harness: string; model: string | null; allowed_tools: string; allow_shell: number; enabled: number }>(
    "SELECT * FROM agent_defs WHERE role IN ('codebase_mapper','security_researcher','independent_validator','retest_auditor')",
  );
  expect(roles).toHaveLength(4);
  for (const role of roles) {
    expect(role).toMatchObject({ harness: "claude-code", model: null, enabled: 1, allow_shell: 0 });
    expect(JSON.parse(role.allowed_tools)).toEqual(["Read", "Grep", "Glob", "LS"]);
  }
  expect(store.all("SELECT * FROM agent_defs WHERE role IN ('findings_manager','report_writer')")).toEqual(beforeSystemRoles);
  expect(getSetting(store, "audit.require_distinct_harness_for_retest", true)).toBe(false);
  expect(store.get("SELECT id FROM audit_log WHERE action = 'harness.assigned'")).toBeDefined();
});

test("runtime assignment keeps every configured tool and rejects unauthorized changes", async () => {
  const { api, headers, userId } = await projectClient();
  const request = (requestHeaders = headers) => new Request("http://localhost/api/harnesses/pi/assign", { method: "POST", headers: requestHeaders });
  expect((await api(request({ ...headers, cookie: "" }))).status).toBe(401);
  expect((await api(request({ ...headers, "x-csrf-token": "invalid" }))).status).toBe(403);
  store.run("UPDATE users SET role = 'auditor' WHERE id = ?", userId);
  expect((await api(request())).status).toBe(403);
  store.run("UPDATE users SET role = 'admin' WHERE id = ?", userId);
  setSetting(store, "security.allow_shell_tools", true, userId);
  saveHarnessConfig(store, "pi", { ...harnessConfig(store, "pi"), allowed_tools: ["read", "bash", "edit", "write"] });
  expect((await api(request())).status).toBe(200);
  const agents = async () => (await (await api(new Request("http://localhost/api/agents", { headers }))).json()).agents as Array<{ role: string; allowed_tools: string[]; inherit_tools: boolean }>;
  expect((await agents()).find((agent) => agent.role === "independent_validator")).toMatchObject({ allowed_tools: ["read", "bash", "edit", "write"], inherit_tools: true });
  const changed = ["read", "grep", "find", "ls", "bash", "edit", "write", "mcp__local__*"];
  expect((await api(new Request("http://localhost/api/harnesses/pi", {
    method: "PUT", headers, body: JSON.stringify({ allowed_tools: changed }),
  }))).status).toBe(200);
  expect((await agents()).find((agent) => agent.role === "independent_validator")?.allowed_tools).toEqual(changed);
  saveHarnessConfig(store, "pi", { ...harnessConfig(store, "pi"), allowed_tools: [] });
  expect((await api(request())).status).toBe(200);
  expect((await agents()).find((agent) => agent.role === "independent_validator")?.allowed_tools).toEqual([]);
});

test("roles inherit all nine runtime tools unless an explicit role restriction is saved", async () => {
  const { api, headers } = await projectClient();
  setSetting(store, "security.allow_shell_tools", true, null);
  const tools = ["Read", "Grep", "Glob", "LS", "Bash", "Edit", "Write", "WebFetch", "WebSearch"];
  saveHarnessConfig(store, "claude-code", { ...harnessConfig(store, "claude-code"), allowed_tools: tools });
  const agents = await (await api(new Request("http://localhost/api/agents", { headers }))).json();
  expect(agents.agents.find((agent: { role: string }) => agent.role === "independent_validator")).toMatchObject({ allowed_tools: tools, inherit_tools: true });
  const update = (body: Record<string, unknown>) => api(new Request("http://localhost/api/agents/independent_validator", {
    method: "PUT", headers, body: JSON.stringify(body),
  }));
  let response = await update({ allowed_tools: ["Read"] });
  expect(response.status).toBe(200);
  expect((await response.json()).agent).toMatchObject({ inherit_tools: false, allowed_tools: ["Read"] });
  response = await update({ model: "test-model" });
  expect((await response.json()).agent).toMatchObject({ inherit_tools: false, allowed_tools: ["Read"] });
  response = await update({ inherit_tools: true });
  expect((await response.json()).agent).toMatchObject({ inherit_tools: true, allowed_tools: tools });
  response = await update({ inherit_tools: false, allowed_tools: [] });
  expect((await response.json()).agent).toMatchObject({ inherit_tools: false, allowed_tools: [] });
  expect((await update({ inherit_tools: "yes" })).status).toBe(400);
});

test("sensitive settings require confirmation only when newly enabled", async () => {
  const { api, headers } = await projectClient();
  const update = (settings: Record<string, unknown>, confirmations = {}) => api(new Request("http://localhost/api/settings", {
    method: "PUT", headers, body: JSON.stringify({ settings, ...confirmations }),
  }));
  const settings = { "security.allow_shell_tools": true, "security.allow_writable_workspace": true };
  expect((await update(settings)).status).toBe(400);
  expect(getSetting(store, "security.allow_shell_tools", false)).toBe(false);
  expect((await update(settings, { confirm_shell: true, confirm_writable_workspace: true })).status).toBe(200);
  expect((await update(settings)).status).toBe(200);
  expect((await update({ "reports.organization": "My team" })).status).toBe(200);
  expect((await update({ "security.allow_shell_tools": false, "security.allow_writable_workspace": false })).status).toBe(200);
  expect((await update(settings)).status).toBe(400);
});
