import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { TokenService } from "../src/auth/tokens.ts";

let dir: string;
let store: Store;
let tokens: TokenService;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "argus-tokens-"));
  store = new Store({ dataDir: dir } as Config);
  store.run(
    "INSERT INTO users (id, email, name, password_hash, role, disabled, created_at) VALUES ('u1','user@test.local','User','x','auditor',0,?)",
    "2026-10-27T00:00:00.000Z",
  );
  for (const id of ["p1", "p2"]) {
    store.run(
      `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      id,
      dir,
      "**/*",
      "",
      "Tester",
      "AUTH-TEST",
      "2026-10-27T00:00:00.000Z",
      "2026-10-27T00:00:00.000Z",
    );
  }
  store.run(
    "INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, created_at) VALUES ('a1','p1',NULL,'queued',1,'{}',?)",
    "2026-10-27T00:00:00.000Z",
  );
  tokens = new TokenService(store);
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("TokenService", () => {
  test("a token is shown once, stored hashed, and carries its scopes", () => {
    const created = tokens.create({
      userId: "u1",
      label: "Claude Code",
      scopes: ["audit:read", "task:create"],
      projectId: "p1",
    });

    expect(created.raw.startsWith("argus_")).toBe(true);
    expect(created.token.scopes).toEqual(["audit:read", "task:create"]);
    expect(created.token.projectId).toBe("p1");
    const row = store.get<{ token_hash: string }>("SELECT token_hash FROM api_tokens WHERE id = ?", created.token.id);
    expect(row!.token_hash).not.toBe(created.raw);
    expect(row!.token_hash).toHaveLength(64);

    const verified = tokens.verify(created.raw);
    expect(verified?.user.id).toBe("u1");
    expect(verified?.token.projectId).toBe("p1");
    expect(tokens.hasScope(verified!.token, "task:create")).toBe(true);
    expect(tokens.hasScope(verified!.token, "audit:launch_dynamic")).toBe(false);
    expect(tokens.verify("argus_wrong")).toBeNull();
  });

  test("expired and revoked tokens fail closed", () => {
    const expired = tokens.create({
      userId: "u1",
      label: "Expired",
      scopes: ["audit:read"],
      expiresAt: "2020-01-01T00:00:00.000Z",
    });
    expect(tokens.verify(expired.raw)).toBeNull();

    const revoked = tokens.create({ userId: "u1", label: "Revoked", scopes: ["audit:read"] });
    tokens.revoke(revoked.token.id);
    expect(tokens.verify(revoked.raw)).toBeNull();
    expect(tokens.verify(revoked.raw)).toBeNull();
  });

  test("project and audit scope is explicit", () => {
    const projectToken = tokens.create({ userId: "u1", label: "P1", scopes: ["audit:read"], projectId: "p1" });
    expect(tokens.allowsProject(projectToken.token, "p1")).toBe(true);
    expect(tokens.allowsProject(projectToken.token, "p2")).toBe(false);

    const auditToken = tokens.create({ userId: "u1", label: "A1", scopes: ["audit:read"], auditId: "a1" });
    expect(tokens.allowsAudit(auditToken.token, "a1")).toBe(true);
    expect(tokens.allowsAudit(auditToken.token, "a2")).toBe(false);
  });
});
