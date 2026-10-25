import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthService } from "../src/auth.ts";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";

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
