import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { TargetService } from "../src/dynamic/targets.ts";

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
});
