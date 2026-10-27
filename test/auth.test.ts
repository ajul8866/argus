import { afterEach, beforeEach, expect, test } from "bun:test";
import { constants, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
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
import { TokenService } from "../src/auth/tokens.ts";
import { GraphStore } from "../src/dynamic/graph.ts";
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
  return { api, headers, userId: login.user.id, engine };
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
  expect(auth.authenticate(new Request("http://localhost/api/auth/me", {
    headers: { cookie: "argus_session=%E0%A4%A" },
  }))).toBeNull();
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

test("retry rejects closed audits and only requeues tasks in a running audit", async () => {
  const { api, headers, engine, userId } = await projectClient();
  const timestamp = new Date().toISOString();
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('retry-project', 'Retry', ?, '["**/*"]', '[]', '', '', ?, ?)`, dir, timestamp, timestamp,
  );
  store.run(
    `INSERT INTO repositories (id, project_id, path, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('retry-repo', 'retry-project', ?, '{}', '[]', '{}', '{}', 0, 0, ?)`, dir, timestamp,
  );
  const auditId = engine.createAudit({ projectId: "retry-project", repositoryId: "retry-repo", userId });
  const invalidCursor = await api(new Request(`http://localhost/api/audits/${auditId}/events?after=invalid`, {
    headers,
  }));
  expect(invalidCursor.status).toBe(400);
  const taskId = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "mapper", title: "Mapper", payload: {}, agentRole: "codebase_mapper",
  });
  store.run("UPDATE tasks SET status = 'failed', attempts = 1, error = 'Previous failure' WHERE id = ?", taskId);
  for (const status of ["queued", "failed", "cancelled", "completed_with_errors"]) {
    store.run("UPDATE audits SET status = ? WHERE id = ?", status, auditId);
    const response = await api(new Request(`http://localhost/api/tasks/${taskId}/retry`, { method: "POST", headers }));
    expect(response.status).toBe(409);
    expect(store.get("SELECT status, attempts, error FROM tasks WHERE id = ?", taskId))
      .toMatchObject({ status: "failed", attempts: 1, error: "Previous failure" });
  }
  store.run("UPDATE audits SET status = 'running' WHERE id = ?", auditId);
  const response = await api(new Request(`http://localhost/api/tasks/${taskId}/retry`, { method: "POST", headers }));
  expect(response.status).toBe(200);
  expect(store.get("SELECT status, attempts, error FROM tasks WHERE id = ?", taskId))
    .toMatchObject({ status: "queued", attempts: 1, error: null });
});

test("project concurrency must be a positive integer or null", async () => {
  const { api, headers } = await projectClient();
  for (const maximum of [-1, 0, 1.5, "invalid", {}]) {
    const response = await api(new Request("http://localhost/api/projects", {
      method: "POST", headers,
      body: JSON.stringify({ name: "Invalid limit", source_path: dir, max_concurrent_agents: maximum }),
    }));
    expect(response.status).toBe(400);
  }
  expect(store.all("SELECT id FROM projects")).toHaveLength(0);
  for (const maximum of [null, 1, 16]) {
    const response = await api(new Request("http://localhost/api/projects", {
      method: "POST", headers,
      body: JSON.stringify({ name: "Valid limit", source_path: dir, max_concurrent_agents: maximum }),
    }));
    expect(response.status).toBe(201);
  }
});

test("invalid project scope patterns are rejected without partially updating the project", async () => {
  const { api, headers } = await projectClient();
  const created = await api(new Request("http://localhost/api/projects", {
    method: "POST", headers,
    body: JSON.stringify({ name: "Original", source_path: dir, scope_include: ["**/*"] }),
  }));
  expect(created.status).toBe(201);
  expect((await api(new Request("http://localhost/api/projects", {
    method: "POST", headers,
    body: JSON.stringify({ name: "Invalid", source_path: dir, scope_exclude: ["[z-a]"] }),
  }))).status).toBe(400);
  expect(store.all("SELECT id FROM projects")).toHaveLength(1);

  const project = (await created.json()).project;
  const updated = await api(new Request(`http://localhost/api/projects/${project.id}`, {
    method: "PUT", headers,
    body: JSON.stringify({ name: "Changed", scope_include: ["[z-a]"] }),
  }));
  expect(updated.status).toBe(400);
  expect(store.get("SELECT name, scope_include FROM projects WHERE id = ?", project.id)).toMatchObject({
    name: "Original",
    scope_include: JSON.stringify(["**/*"]),
  });
});

test("forwarded headers cannot change the login throttle bucket for one socket peer", async () => {
  const { api } = await projectClient();
  const login = (password: string, spoofed: string) => api(new Request("http://localhost/api/auth/login", {
    method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": spoofed, "x-real-ip": spoofed },
    body: JSON.stringify({ email: "admin@test.local", password }),
  }), "192.0.2.1");
  for (let attempt = 0; attempt < 6; attempt += 1) {
    expect((await login("wrong-password", `198.51.100.${attempt}`)).status).toBe(401);
  }
  const response = await login("test-admin-password", "203.0.113.99");
  expect(response.status).toBe(401);
  expect((await response.json()).error.message).toContain("Too many failed sign-in attempts");
});

test("login accepts the exact whitespace-bearing password stored by the auth service", async () => {
  const password = "  a-valid-password  ";
  await auth.createUser("spaces@test.local", "Spaces", password, "auditor");
  const { api } = await projectClient();
  const login = (value: string) => api(new Request("http://localhost/api/auth/login", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "spaces@test.local", password: value }),
  }));
  expect((await login(password)).status).toBe(200);
  expect((await login(password.trim())).status).toBe(401);
});

test("user creation and password changes preserve password whitespace", async () => {
  const { api, headers } = await projectClient();
  const password = "  a-valid-password  ";
  const created = await api(new Request("http://localhost/api/users", {
    method: "POST", headers, body: JSON.stringify({ email: "new@test.local", role: "auditor", password }),
  }));
  expect(created.status).toBe(201);
  const row = store.get<{ password_hash: string }>("SELECT password_hash FROM users WHERE email = 'new@test.local'")!;
  expect(await Bun.password.verify(password, row.password_hash)).toBe(true);
  expect(await Bun.password.verify(password.trim(), row.password_hash)).toBe(false);
  const signedIn = await auth.login("new@test.local", password, "local", "test");
  const changedPassword = "  another-password  ";
  const changed = await api(new Request("http://localhost/api/auth/password", {
    method: "POST", headers: { "content-type": "application/json", cookie: `argus_session=${signedIn.token}`, "x-csrf-token": signedIn.csrf },
    body: JSON.stringify({ current_password: password, new_password: changedPassword }),
  }));
  expect(changed.status).toBe(200);
  const updated = store.get<{ password_hash: string }>("SELECT password_hash FROM users WHERE email = 'new@test.local'")!;
  expect(await Bun.password.verify(changedPassword, updated.password_hash)).toBe(true);
  expect(await Bun.password.verify(changedPassword.trim(), updated.password_hash)).toBe(false);
});

test("repository import rejects malformed JSON instead of importing with default options", async () => {
  const { api, headers } = await projectClient();
  const created = await api(new Request("http://localhost/api/projects", {
    method: "POST", headers, body: JSON.stringify({ name: "JSON boundary", source_path: dir, scope_include: ["**/*.ts"] }),
  }));
  const projectId = (await created.json()).project.id;
  const response = await api(new Request(`http://localhost/api/projects/${projectId}/import`, {
    method: "POST", headers, body: '{"ref":',
  }));
  expect(response.status).toBe(400);
  expect((await response.json()).error.code).toBe("invalid_json");
  expect(store.all("SELECT id FROM repositories")).toHaveLength(0);
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

test("invalid user updates are rejected before a partial role or name change", async () => {
  const user = await auth.createUser("unchanged@test.local", "Original", "auditor-password-1", "auditor");
  const { api, headers } = await projectClient();
  for (const body of [
    { role: "owner" },
    { disabled: "true" },
    { name: { value: "Changed" } },
    { role: "viewer", name: { value: "Changed" } },
  ]) {
    const response = await api(new Request(`http://localhost/api/users/${user.id}`, {
      method: "PATCH", headers, body: JSON.stringify(body),
    }));
    expect(response.status).toBe(400);
    expect(auth.listUsers().find((entry) => entry.id === user.id)).toMatchObject({
      role: "auditor",
      name: "Original",
      disabled: 0,
    });
  }
});

test("audit log details redact supplied credentials", async () => {
  const { api, headers } = await projectClient();
  const created = await api(new Request("http://localhost/api/projects", {
    method: "POST", headers,
    body: JSON.stringify({ name: "Audit log", source_path: dir }),
  }));
  const project = (await created.json()).project;
  await api(new Request(`http://localhost/api/projects/${project.id}`, {
    method: "PUT", headers,
    body: JSON.stringify({ name: "Updated", password: "private-password-value" }),
  }));
  const entry = store.get<{ detail: string }>(
    "SELECT detail FROM audit_log WHERE action = 'project.updated' ORDER BY id DESC LIMIT 1",
  )!;
  expect(entry.detail).toContain("[REDACTED]");
  expect(entry.detail).not.toContain("private-password-value");
});

test("report downloads fail closed when the stored bytes no longer match the recorded hash", async () => {
  const { api, headers, engine, userId } = await projectClient();
  const timestamp = new Date().toISOString();
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('report-project', 'Report', ?, '["**/*"]', '[]', '', '', ?, ?)`,
    dir, timestamp, timestamp,
  );
  store.run(
    `INSERT INTO repositories (id, project_id, path, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('report-repo', 'report-project', ?, '{}', '[]', '{}', '{}', 0, 0, ?)`,
    dir, timestamp,
  );
  const auditId = engine.createAudit({ projectId: "report-project", repositoryId: "report-repo", userId });
  const service = new ReportService(config(dir), store, new EvidenceStore(config(dir), store), new EventLog(store));
  const [report] = await service.generate(auditId, ["markdown"], "test");
  const download = () => api(new Request(`http://localhost/api/reports/${report!.id}/download`, { headers }));
  const accepted = await download();
  expect(accepted.status).toBe(200);
  expect(Buffer.from(await accepted.arrayBuffer()).equals(readFileSync(report!.path))).toBe(true);
  const sameSize = Buffer.from(readFileSync(report!.path));
  const first = sameSize[0] ?? 0;
  sameSize[0] = first === 0x41 ? 0x42 : 0x41;
  writeFileSync(report!.path, sameSize);
  const sameLength = await download();
  expect(sameLength.status).toBe(409);
  expect(await sameLength.json()).toMatchObject({ error: { code: "conflict" } });
  writeFileSync(report!.path, "tampered report\n");
  const rejected = await download();
  expect(rejected.status).toBe(409);
  expect(await rejected.json()).toMatchObject({
    error: { code: "conflict", message: "Report integrity check failed; the stored file does not match its recorded size" },
  });
});

test("report downloads reject a pipe or symlink without waiting or following it", async () => {
  const { api, headers, engine, userId } = await projectClient();
  const timestamp = new Date().toISOString();
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('report-pipe-project', 'Report pipe', ?, '["**/*"]', '[]', '', '', ?, ?)`,
    dir, timestamp, timestamp,
  );
  store.run(
    `INSERT INTO repositories (id, project_id, path, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('report-pipe-repo', 'report-pipe-project', ?, '{}', '[]', '{}', '{}', 0, 0, ?)`,
    dir, timestamp,
  );
  const auditId = engine.createAudit({ projectId: "report-pipe-project", repositoryId: "report-pipe-repo", userId });
  const service = new ReportService(config(dir), store, new EvidenceStore(config(dir), store), new EventLog(store));
  const [report] = await service.generate(auditId, ["markdown"], "test");
  const reportPath = report!.path;
  const original = readFileSync(reportPath);
  const download = () => api(new Request(`http://localhost/api/reports/${report!.id}/download`, { headers }));
  const finished = async () => Promise.race([
    download(),
    Bun.sleep(1_000).then(() => {
      throw new Error("report download blocked");
    }),
  ]);

  rmSync(reportPath);
  expect((await finished()).status).toBe(404);

  expect(Bun.spawnSync(["mkfifo", reportPath]).exitCode).toBe(0);
  const unwritable = await finished();
  expect(unwritable.status).toBe(409);
  expect(await unwritable.json()).toMatchObject({
    error: { code: "conflict", message: "Report file is missing or unreadable" },
  });

  const reader = await open(reportPath, constants.O_RDONLY | constants.O_NONBLOCK);
  const writer = await open(reportPath, constants.O_WRONLY);
  await reader.close();
  try {
    const held = await finished();
    expect(held.status).toBe(409);
    expect(await held.json()).toMatchObject({ error: { code: "conflict" } });
  } finally {
    await writer.close();
  }

  rmSync(reportPath);
  const target = join(dir, "report-copy.md");
  writeFileSync(target, original);
  symlinkSync(target, reportPath);
  const linked = await finished();
  expect(linked.status).toBe(409);
  expect(await linked.json()).toMatchObject({
    error: { code: "conflict", message: "Report file is missing or unreadable" },
  });
});

test("report downloads read only the size checked when the file grows", async () => {
  const { api, headers, engine, userId } = await projectClient();
  const timestamp = new Date().toISOString();
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('report-grow-project', 'Report grow', ?, '["**/*"]', '[]', '', '', ?, ?)`,
    dir, timestamp, timestamp,
  );
  store.run(
    `INSERT INTO repositories (id, project_id, path, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('report-grow-repo', 'report-grow-project', ?, '{}', '[]', '{}', '{}', 0, 0, ?)`,
    dir, timestamp,
  );
  const auditId = engine.createAudit({ projectId: "report-grow-project", repositoryId: "report-grow-repo", userId });
  const service = new ReportService(config(dir), store, new EvidenceStore(config(dir), store), new EventLog(store));
  const [report] = await service.generate(auditId, ["markdown"], "test");
  const reportPath = report!.path;
  const original = readFileSync(reportPath);
  const before = original.length;
  const probe = await open(reportPath, "r");
  const proto = Object.getPrototypeOf(probe) as {
    stat: (this: unknown, ...args: unknown[]) => Promise<{ isFile: () => boolean; size: number }>;
    read: (
      this: unknown,
      buffer: Buffer,
      offset?: number,
      length?: number,
      position?: number | null,
    ) => Promise<{ bytesRead: number }>;
    readFile: (this: unknown, ...args: unknown[]) => Promise<unknown>;
  };
  await probe.close();
  const originalStat = proto.stat;
  const originalRead = proto.read;
  const originalReadFile = proto.readFile;
  let readFileCalls = 0;
  let maxRequested = 0;
  proto.stat = async function (this: unknown, ...args: unknown[]) {
    const info = await originalStat.apply(this, args);
    const size = info.size;
    const file = info.isFile();
    if (file && size === before) {
      writeFileSync(reportPath, Buffer.concat([original, Buffer.alloc(1024 * 1024, 0x51)]));
    }
    return { isFile: () => file, size };
  };
  proto.read = async function (
    this: unknown,
    buffer: Buffer,
    offset?: number,
    length?: number,
    position?: number | null,
  ) {
    if (length === undefined || length > before) {
      throw new Error(`unbounded report read of ${String(length)} bytes`);
    }
    maxRequested = Math.max(maxRequested, length);
    return originalRead.call(this, buffer, offset, length, position);
  };
  proto.readFile = async function (this: unknown, ...args: unknown[]) {
    readFileCalls += 1;
    return originalReadFile.apply(this, args);
  };
  try {
    const response = await api(new Request(`http://localhost/api/reports/${report!.id}/download`, { headers }));
    expect(response.status).toBe(200);
    expect(Buffer.from(await response.arrayBuffer()).equals(original)).toBe(true);
    expect(readFileCalls).toBe(0);
    expect(maxRequested).toBeGreaterThan(0);
    expect(maxRequested).toBeLessThanOrEqual(before);
  } finally {
    proto.stat = originalStat;
    proto.read = originalRead;
    proto.readFile = originalReadFile;
  }
});

test("evidence reads fail closed when the stored file no longer matches the database record", async () => {
  const { api, headers, engine, userId } = await projectClient();
  const timestamp = new Date().toISOString();
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('evidence-project', 'Evidence', ?, '["**/*"]', '[]', '', '', ?, ?)`,
    dir, timestamp, timestamp,
  );
  store.run(
    `INSERT INTO repositories (id, project_id, path, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('evidence-repo', 'evidence-project', ?, '{}', '[]', '{}', '{}', 0, 0, ?)`,
    dir, timestamp,
  );
  const auditId = engine.createAudit({ projectId: "evidence-project", repositoryId: "evidence-repo", userId });
  const row = await new EvidenceStore(config(dir), store).append({
    auditId,
    kind: "agent_prompt",
    title: "prompt",
    content: "alpha",
  });
  const read = () => api(new Request(`http://localhost/api/evidence/${row.id}`, { headers }));
  const accepted = await read();
  expect(accepted.status).toBe(200);
  expect(await accepted.json()).toMatchObject({ content: "alpha" });
  const parsed = JSON.parse(readFileSync(row.content_path, "utf8")) as { content?: string };
  parsed.content = "tampered";
  writeFileSync(row.content_path, JSON.stringify(parsed));
  const rejected = await read();
  expect(rejected.status).toBe(409);
  expect(await rejected.json()).toMatchObject({ error: { code: "conflict" } });
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

test("dynamic target, authorization, and identity routes enforce roles and hide secrets", async () => {
  const { api, headers } = await projectClient();
  const projectResponse = await api(new Request("http://localhost/api/projects", {
    method: "POST",
    headers,
    body: JSON.stringify({ name: "Targets", source_path: dir, scope_include: ["**/*"] }),
  }));
  expect(projectResponse.status).toBe(201);
  const projectId = (await projectResponse.json()).project.id;

  const targetResponse = await api(new Request(`http://localhost/api/projects/${projectId}/targets`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      label: "Staging",
      base_url: "https://app.example.test",
      environment: "staging",
      allowed_hosts: ["app.example.test"],
      allowed_methods: ["GET"],
    }),
  }));
  expect(targetResponse.status).toBe(201);
  const target = (await targetResponse.json()).target;
  expect(target.allowedHosts).toEqual(["app.example.test"]);

  const authorizationResponse = await api(new Request(`http://localhost/api/targets/${target.id}/authorizations`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      authorized_by: "Tester",
      authorization_ref: "AUTH-1",
      valid_from: "2020-01-01T00:00:00.000Z",
      valid_until: "2099-01-01T00:00:00.000Z",
      authorized_actions: { methods: ["GET"] },
      restrictions: {},
    }),
  }));
  expect(authorizationResponse.status).toBe(201);

  const identityResponse = await api(new Request(`http://localhost/api/targets/${target.id}/identities`, {
    method: "POST",
    headers,
    body: JSON.stringify({ label: "User A", role: "user_a", auth_kind: "header", secret_ref: "cred_a" }),
  }));
  expect(identityResponse.status).toBe(201);
  const identity = (await identityResponse.json()).identity;
  expect(identity).not.toHaveProperty("secretRef");
  expect(identity).not.toHaveProperty("secret_ref");

  const list = await api(new Request(`http://localhost/api/projects/${projectId}/targets`, { headers }));
  expect(list.status).toBe(200);
  expect((await list.json()).targets).toHaveLength(1);

  await auth.createUser("viewer@test.local", "Viewer", "viewer-password", "viewer");
  const viewerLogin = await auth.login("viewer@test.local", "viewer-password", "local", "test");
  const viewerHeaders = {
    cookie: `argus_session=${viewerLogin.token}`,
    "x-csrf-token": viewerLogin.csrf,
    "content-type": "application/json",
  };
  const forbiddenResponse = await api(new Request(`http://localhost/api/projects/${projectId}/targets`, {
    method: "POST",
    headers: viewerHeaders,
    body: JSON.stringify({
      label: "Nope",
      base_url: "https://nope.example.test",
      environment: "staging",
      allowed_hosts: ["nope.example.test"],
    }),
  }));
  expect(forbiddenResponse.status).toBe(403);
  expect(store.all("SELECT action FROM audit_log WHERE action LIKE 'target.%' ORDER BY id")).toHaveLength(3);
});

test("token scopes gate dynamic launches independently of task:create", async () => {
  const { api, headers, userId } = await projectClient();
  const tokens = new TokenService(store);

  const createProject = async (name: string): Promise<string> => {
    const response = await api(new Request("http://localhost/api/projects", {
      method: "POST",
      headers,
      body: JSON.stringify({ name, source_path: dir, scope_include: ["**/*"] }),
    }));
    expect(response.status).toBe(201);
    return (await response.json()).project.id;
  };

  const projectId = await createProject("Scoped project");
  const otherProjectId = await createProject("Other project");
  store.run(
    `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('repo_scoped', ?, ?, NULL, 'test', '[]', '[]', '[]', '{}', 0, 0, ?)`,
    projectId,
    dir,
    now(),
  );

  const targetResponse = await api(new Request(`http://localhost/api/projects/${projectId}/targets`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      label: "Staging",
      base_url: "https://app.example.test",
      environment: "staging",
      allowed_hosts: ["app.example.test"],
      allowed_methods: ["GET"],
    }),
  }));
  expect(targetResponse.status).toBe(201);
  const targetId = (await targetResponse.json()).target.id;

  const staticToken = tokens.create({
    userId,
    label: "static",
    scopes: ["task:create", "audit:launch_static"],
    projectId,
  });
  const staticHeaders = { authorization: `Bearer ${staticToken.raw}`, "content-type": "application/json" };

  const dynamicWithStaticScope = await api(new Request("http://localhost/api/audits", {
    method: "POST",
    headers: staticHeaders,
    body: JSON.stringify({ project_id: projectId, mode: "dynamic", target_id: targetId }),
  }));
  expect(dynamicWithStaticScope.status).toBe(403);

  const staticAudit = await api(new Request("http://localhost/api/audits", {
    method: "POST",
    headers: staticHeaders,
    body: JSON.stringify({ project_id: projectId, mode: "static" }),
  }));
  expect(staticAudit.status).toBe(201);

  const dynamicToken = tokens.create({
    userId,
    label: "dynamic",
    scopes: ["audit:launch_dynamic"],
    projectId,
  });
  const dynamicHeaders = { authorization: `Bearer ${dynamicToken.raw}`, "content-type": "application/json" };
  const dynamicAudit = await api(new Request("http://localhost/api/audits", {
    method: "POST",
    headers: dynamicHeaders,
    body: JSON.stringify({ project_id: projectId, mode: "dynamic", target_id: targetId }),
  }));
  expect(dynamicAudit.status).toBe(201);

  const otherToken = tokens.create({
    userId,
    label: "other",
    scopes: ["audit:launch_dynamic"],
    projectId: otherProjectId,
  });
  const otherHeaders = { authorization: `Bearer ${otherToken.raw}`, "content-type": "application/json" };
  const crossProject = await api(new Request("http://localhost/api/audits", {
    method: "POST",
    headers: otherHeaders,
    body: JSON.stringify({ project_id: projectId, mode: "dynamic", target_id: targetId }),
  }));
  expect(crossProject.status).toBe(403);

  store.run(
    "INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, mode, created_at) VALUES ('a_task', ?, NULL, 'running', 1, '{}', 'static', ?)",
    projectId,
    now(),
  );
  store.run(
    "INSERT INTO tasks (id, audit_id, phase, kind, task_key, title, status, payload, attempts, max_attempts, created_at) VALUES ('t1','a_task',1,'phase1.map','phase1:map','Map','failed','{}',1,2,?)",
    now(),
  );
  const taskToken = tokens.create({
    userId,
    label: "task only",
    scopes: ["task:create"],
    projectId,
  });
  const taskHeaders = { authorization: `Bearer ${taskToken.raw}`, "content-type": "application/json" };
  const deniedControl = await api(new Request("http://localhost/api/tasks/t1/retry", {
    method: "POST",
    headers: taskHeaders,
    body: "{}",
  }));
  expect(deniedControl.status).toBe(403);
});

test("adapter routes create tasks and read findings under token scopes", async () => {
  const { api, userId } = await projectClient();
  const tokens = new TokenService(store);
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p_adapter','Adapter', ?, '**/*', '', 'Tester', 'AUTH', ?, ?)`,
    dir,
    now(),
    now(),
  );
  store.run(
    "INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, mode, created_at) VALUES ('a_adapter','p_adapter',NULL,'running',1,'{}','dynamic',?)",
    now(),
  );
  store.run(
    `INSERT INTO findings
     (id, code, audit_id, project_id, title, category, cwe, severity, status, repository_commit, files,
      root_cause, preconditions, reproduction, expected, observed, impact, remediation, created_at, updated_at)
     VALUES ('f1','F-1','a_adapter','p_adapter','Test','idor',NULL,'high','confirmed',NULL,'[]',
      'root','none','steps','expected','observed','impact','fix',?,?)`,
    now(),
    now(),
  );

  const headersFor = (raw: string) => ({ authorization: `Bearer ${raw}`, "content-type": "application/json" });
  const onlyCreate = tokens.create({
    userId,
    label: "adapter",
    scopes: ["task:create"],
    projectId: "p_adapter",
  });
  const denied = await api(new Request("http://localhost/api/audits/a_adapter/tasks", {
    method: "POST",
    headers: headersFor(onlyCreate.raw),
    body: JSON.stringify({ kind: "explore", payload: {}, agent_role: "security_researcher" }),
  }));
  expect(denied.status).toBe(403);

  const both = tokens.create({
    userId,
    label: "adapter dynamic",
    scopes: ["task:create", "audit:launch_dynamic"],
    projectId: "p_adapter",
  });
  const created = await api(new Request("http://localhost/api/audits/a_adapter/tasks", {
    method: "POST",
    headers: headersFor(both.raw),
    body: JSON.stringify({ kind: "explore", payload: {}, agent_role: "security_researcher" }),
  }));
  expect(created.status).toBe(201);
  expect((await created.json()).task.audit_id).toBe("a_adapter");

  const reader = tokens.create({
    userId,
    label: "reader",
    scopes: ["finding:read"],
    projectId: "p_adapter",
  });
  const finding = await api(new Request("http://localhost/api/findings/f1", {
    headers: { authorization: `Bearer ${reader.raw}` },
  }));
  expect(finding.status).toBe(200);
  expect((await finding.json()).finding.id).toBe("f1");

  const missing = await api(new Request("http://localhost/api/findings/missing", {
    headers: { authorization: `Bearer ${reader.raw}` },
  }));
  expect(missing.status).toBe(404);
});

test("exploration route returns assets, nodes, edges, anchors, and coverage", async () => {
  const { api, headers } = await projectClient();
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p_graph','Graph', ?, '**/*', '', 'Tester', 'AUTH-GRAPH', ?, ?)`,
    dir,
    now(),
    now(),
  );
  store.run(
    `INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, mode, exploration_status, created_at)
     VALUES ('a_graph','p_graph',NULL,'running',2,'{}','dynamic','open',?)`,
    now(),
  );
  const graph = new GraphStore(store);
  const asset = graph.upsertAsset({ projectId: "p_graph", kind: "app", assetKey: "https://graph.test" });
  const goal = graph.createNode({ auditId: "a_graph", kind: "goal", payload: { text: "Find access issues" } });
  const intent = graph.createNode({
    auditId: "a_graph",
    kind: "intent",
    status: "completed",
    payload: { title: "Read another identity invoice" },
  });
  graph.anchor(goal.id, asset.id);
  graph.anchor(intent.id, asset.id);
  graph.linkNodes(goal.id, intent.id, "spawns");

  const response = await api(new Request("http://localhost/api/audits/a_graph/exploration", { headers }));
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.assets).toHaveLength(1);
  expect(body.assets[0]).toMatchObject({ id: asset.id, assetKey: "https://graph.test" });
  expect(body.nodes).toHaveLength(2);
  expect(body.edges).toEqual([{ fromNodeId: goal.id, toNodeId: intent.id, kind: "spawns" }]);
  expect(body.anchors).toHaveLength(2);
  expect(body.coverage).toEqual([
    expect.objectContaining({ assetId: asset.id, assetKey: "https://graph.test", tested: true }),
  ]);
});
