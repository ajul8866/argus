import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { TargetService } from "../src/dynamic/targets.ts";
import { sha256 } from "../src/util.ts";

let dir: string;
let store: Store;
let targets: TargetService;
let projectId: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "argus-targets-"));
  store = new Store({ dataDir: dir } as Config);
  projectId = "proj_test";
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    projectId,
    "Demo",
    dir,
    "**/*",
    "",
    "Test operator",
    "AUTH-TEST-1",
    "2026-10-27T00:00:00.000Z",
    "2026-10-27T00:00:00.000Z",
  );
  targets = new TargetService(store);
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("TargetService", () => {
  test("creates and reads a target, authorization, and identity", () => {
    const target = targets.createTarget({
      projectId,
      label: "Staging",
      baseUrl: "https://app.example.test",
      environment: "staging",
      allowedHosts: ["app.example.test"],
      allowedCidrs: ["203.0.113.0/24"],
      allowedMethods: ["GET", "POST"],
      maxRps: 5,
      tlsRequired: true,
    });

    expect(target.projectId).toBe(projectId);
    expect(target.allowedHosts).toEqual(["app.example.test"]);
    expect(target.allowedCidrs).toEqual(["203.0.113.0/24"]);
    expect(target.allowedMethods).toEqual(["GET", "POST"]);
    expect(targets.listTargets(projectId).map((row) => row.id)).toEqual([target.id]);

    const authorization = targets.createAuthorization({
      targetId: target.id,
      authorizedBy: "Test operator",
      reference: "AUTH-TEST-1",
      validFrom: "2026-10-27T00:00:00.000Z",
      validUntil: "2026-11-03T00:00:00.000Z",
      authorizedActions: {
        methods: ["GET", "POST"],
        allow_state_changing: false,
        allow_file_upload: false,
        allow_bruteforce: false,
        require_approval_for: ["POST", "PUT", "PATCH", "DELETE"],
      },
      restrictions: { allowed_paths: [], denied_paths: [], notes: "staging only" },
    });

    expect(authorization.targetId).toBe(target.id);
    expect(authorization.authorizedActions.methods).toEqual(["GET", "POST"]);
    expect(targets.activeAuthorization(target.id, "2026-10-28T00:00:00.000Z")?.id).toBe(authorization.id);
    expect(targets.activeAuthorization(target.id, "2026-12-01T00:00:00.000Z")).toBeNull();

    const identity = targets.createIdentity({
      targetId: target.id,
      label: "User A",
      role: "user_a",
      authKind: "header",
      secretRef: "cred_test_a",
    });

    expect(identity.role).toBe("user_a");
    expect(identity.authKind).toBe("header");
    expect(targets.listIdentities(target.id).map((row) => row.id)).toEqual([identity.id]);
  });

  test("an authorization offset cannot outlive its absolute expiry", () => {
    const target = targets.createTarget({
      projectId,
      label: "Offset target",
      baseUrl: "https://offset.example.test",
      environment: "test",
      allowedHosts: ["offset.example.test"],
    });
    // Absolute time is in the past even though the local wall clock reads 23:00.
    const expired = new Date(Date.now() - 3_600_000);
    const created = targets.createAuthorization({
      targetId: target.id,
      authorizedBy: "Tester",
      reference: "AUTH-OFFSET",
      validFrom: new Date(expired.getTime() - 3_600_000).toISOString(),
      validUntil: expired.toISOString(),
      authorizedActions: { methods: ["GET"] },
    });
    expect(targets.activeAuthorization(target.id)).toBeNull();
    expect(created.validUntil).toBe(expired.toISOString());
  });

  test("rejects an authorization window that ends before it starts", () => {
    const target = targets.createTarget({
      projectId,
      label: "Staging",
      baseUrl: "https://app.example.test",
      environment: "staging",
      allowedHosts: ["app.example.test"],
      allowedCidrs: [],
      allowedMethods: ["GET"],
    });

    expect(() =>
      targets.createAuthorization({
        targetId: target.id,
        authorizedBy: "Test operator",
        reference: "AUTH-TEST-2",
        validFrom: "2026-11-03T00:00:00.000Z",
        validUntil: "2026-10-27T00:00:00.000Z",
        authorizedActions: { methods: ["GET"] },
        restrictions: {},
      }),
    ).toThrow(/valid_until/);
  });

  test("creates an immutable scope snapshot", () => {
    const target = targets.createTarget({
      projectId,
      label: "Staging",
      baseUrl: "https://app.example.test",
      environment: "staging",
      allowedHosts: ["app.example.test"],
      allowedMethods: ["GET"],
    });
    targets.createAuthorization({
      targetId: target.id,
      authorizedBy: "Test operator",
      reference: "AUTH-TEST-3",
      validFrom: "2026-10-27T00:00:00.000Z",
      validUntil: "2026-11-03T00:00:00.000Z",
      authorizedActions: { methods: ["GET"] },
      restrictions: { allowed_paths: ["/api"], denied_paths: [], notes: "local" },
    });
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    store.run(
      "INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, mode, created_at) VALUES ('a1', ?, NULL, 'queued', 1, '{}', 'dynamic', ?)",
      projectId,
      "2026-10-27T00:00:00.000Z",
    );

    const budget = {
      max_usd: 20,
      exploration_cap_usd: 12,
      verification_reserve_usd: 8,
      max_tasks: 200,
      max_requests: 5_000,
      max_runtime_minutes: 240,
    };
    const created = targets.createSnapshot({
      auditId: "a1",
      mode: "dynamic",
      targetId: target.id,
      permissions: ["audit:read", "audit:launch_dynamic"],
      budget,
      repository: null,
      createdBy: null,
    });

    expect(created.sha256).toBe(sha256(JSON.stringify(created.snapshot)));
    expect(targets.getSnapshot("a1")).toEqual(created);
    expect(created.snapshot.target.base_url).toBe("https://app.example.test");
    expect(created.snapshot.identities).toHaveLength(1);
    expect(() => store.run("UPDATE audit_scope_snapshots SET sha256 = 'x' WHERE audit_id = 'a1'")).toThrow(/immutable/);
  });
});
