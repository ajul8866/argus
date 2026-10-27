import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { evaluateRun, validatePoc, type PocManifest } from "../src/dynamic/poc.ts";
import { RetestService, retestVerdict } from "../src/dynamic/retest.ts";

const manifest: PocManifest = {
  language: "python",
  script_evidence_id: "ev_script",
  object: { asset_id: "asset_1", object_id: "invoice_123", owner_identity: "user_b" },
  checks: {
    positive: {
      identity: "user_b",
      request: { method: "GET", path: "/invoices/invoice_123" },
      expect: { status: 200, body_contains: "invoice_123" },
    },
    exploit: {
      identity: "user_a",
      request: { method: "GET", path: "/invoices/invoice_123" },
      expect: { status: 200, body_contains: "invoice_123" },
    },
    negative: {
      identity: "user_a",
      request: { method: "GET", path: "/invoices/invoice_999" },
      expect: { status: [403, 404] },
    },
  },
  environment: { target: "https://app.example.test", commit_sha: "abc", identities: ["user_a", "user_b"] },
};

const exchange = (status: number, body = "") => ({ status, body });

describe("PoC validation", () => {
  test("accepts a structurally sound manifest", () => {
    expect(() => validatePoc(manifest)).not.toThrow();
  });

  test("rejects a positive control that is not the owner", () => {
    const broken = structuredClone(manifest);
    broken.checks.positive.identity = "user_a";
    expect(() => validatePoc(broken)).toThrow(/owner/i);
  });

  test("rejects a negative check that targets the exploited object", () => {
    const broken = structuredClone(manifest);
    broken.checks.negative.request.path = "/invoices/invoice_123";
    expect(() => validatePoc(broken)).toThrow(/negative/i);
  });

  test("rejects a positive and exploit pair that use different objects", () => {
    const broken = structuredClone(manifest);
    broken.checks.exploit.request.path = "/invoices/invoice_456";
    expect(() => validatePoc(broken)).toThrow(/object/i);
  });
});

describe("PoC evaluation", () => {
  test("passes only when all three checks pass", () => {
    expect(
      evaluateRun(manifest, {
        positive: exchange(200, "invoice_123"),
        exploit: exchange(200, "invoice_123"),
        negative: exchange(404),
      }),
    ).toMatchObject({ status: "passed", positive: true, exploit: true, negative: true });
  });

  test("treats a failed positive control as an environment error", () => {
    expect(
      evaluateRun(manifest, {
        positive: exchange(500),
        exploit: exchange(200, "invoice_123"),
        negative: exchange(404),
      }).status,
    ).toBe("error");
  });

  test("fails when the exploit or negative check fails", () => {
    expect(
      evaluateRun(manifest, {
        positive: exchange(200, "invoice_123"),
        exploit: exchange(403),
        negative: exchange(404),
      }).status,
    ).toBe("failed");
    expect(
      evaluateRun(manifest, {
        positive: exchange(200, "invoice_123"),
        exploit: exchange(200, "invoice_123"),
        negative: exchange(200),
      }).status,
    ).toBe("failed");
  });
});

let dir = "";
let store: Store;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "argus-retest-"));
  store = new Store({ dataDir: dir } as Config);
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p1','Demo', ?, '**/*', '', 'Tester', 'AUTH', '2026-10-27T00:00:00.000Z', '2026-10-27T00:00:00.000Z')`,
    dir,
  );
  store.run(
    "INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, mode, created_at) VALUES ('a1','p1',NULL,'completed',1,'{}','dynamic','2026-10-27T00:00:00.000Z')",
  );
  store.run(
    `INSERT INTO findings
     (id, code, audit_id, project_id, title, category, cwe, severity, status, repository_commit, files,
      root_cause, preconditions, reproduction, expected, observed, impact, remediation, created_at, updated_at)
     VALUES ('f1','F-1','a1','p1','Test','idor',NULL,'high','confirmed',NULL,'[]',
      'root','none','steps','expected','observed','impact','fix','2026-10-27T00:00:00.000Z','2026-10-27T00:00:00.000Z')`,
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

const retestInput = {
  findingId: "f1",
  auditId: "a1",
  reason: "fix applied",
  authorizationSnapshot: JSON.stringify({
    id: "auth-1",
    authorized_by: "Tester",
    reference: "AUTH-1",
    valid_from: "2026-01-01T00:00:00.000Z",
    valid_until: "2099-01-01T00:00:00.000Z",
  }),
  environmentManifest: JSON.stringify({ target: "https://app.example.test" }),
  commitSha: "abc",
  buildRef: "build-1",
};

describe("RetestService", () => {
  test("creates a queued retest and records a fixed verdict", async () => {
    const service = new RetestService(store, async () => ({
      positivePassed: true,
      exploitPassed: false,
      evidenceRefs: ["ev1"],
    }));
    const id = service.request({ ...retestInput, environmentMatch: true });
    expect(store.get("SELECT status, verdict FROM retests WHERE id = ?", id)).toEqual({ status: "queued", verdict: null });

    expect(await service.run(id)).toBe("fixed");
    expect(store.get("SELECT status, verdict FROM retests WHERE id = ?", id)).toEqual({
      status: "completed",
      verdict: "fixed",
    });
  });

  test("a failed positive control is cannot_confirm even when the exploit passes", async () => {
    const service = new RetestService(store, async () => ({
      positivePassed: false,
      exploitPassed: true,
      evidenceRefs: [],
    }));
    const id = service.request({ ...retestInput, environmentMatch: true });
    expect(await service.run(id)).toBe("cannot_confirm");
  });

  test("a successful exploit is still_reproducible and an environment mismatch is cannot_confirm", async () => {
    const service = new RetestService(store, async () => ({
      positivePassed: true,
      exploitPassed: true,
      evidenceRefs: [],
    }));
    const reproducible = service.request({ ...retestInput, environmentMatch: true });
    expect(await service.run(reproducible)).toBe("still_reproducible");

    const mismatchService = new RetestService(store, async () => ({
      positivePassed: true,
      exploitPassed: false,
      evidenceRefs: [],
    }));
    const mismatch = mismatchService.request({ ...retestInput, environmentMatch: false });
    expect(await mismatchService.run(mismatch)).toBe("cannot_confirm");
  });

  test("the verdict table is strict", () => {
    expect(retestVerdict(true, true, true)).toBe("still_reproducible");
    expect(retestVerdict(false, false, true)).toBe("cannot_confirm");
    expect(retestVerdict(true, false, true)).toBe("fixed");
    expect(retestVerdict(true, false, false)).toBe("cannot_confirm");
  });
});

describe("RetestService strictness", () => {
  test("an omitted environment_match is rejected instead of assumed", () => {
    const service = new RetestService(store, async () => ({
      positivePassed: true,
      exploitPassed: false,
      evidenceRefs: [],
    }));
    expect(() => service.request({ ...retestInput, environmentMatch: undefined as never })).toThrow(/environment_match/i);
  });

  test("an expired or malformed authorization snapshot is rejected", () => {
    const service = new RetestService(store, async () => ({
      positivePassed: true,
      exploitPassed: false,
      evidenceRefs: [],
    }));
    expect(() =>
      service.request({
        ...retestInput,
        environmentMatch: true,
        authorizationSnapshot: JSON.stringify({
          id: "a",
          authorized_by: "x",
          reference: "r",
          valid_from: "2020-01-01T00:00:00.000Z",
          valid_until: "2020-02-01T00:00:00.000Z",
        }),
      }),
    ).toThrow(/expired/i);
    expect(() =>
      service.request({ ...retestInput, environmentMatch: true, authorizationSnapshot: "{}" }),
    ).toThrow(/authorization_snapshot\./i);
    expect(() =>
      service.request({ ...retestInput, environmentMatch: true, environmentManifest: "[]" }),
    ).toThrow(/environment_manifest/i);
  });

  test("an executor error is cannot_confirm even when the exploit fails", async () => {
    const service = new RetestService(store, async () => ({
      positivePassed: true,
      exploitPassed: false,
      evidenceRefs: [],
      error: "target unreachable",
    }));
    const id = service.request({ ...retestInput, environmentMatch: true });
    expect(await service.run(id)).toBe("cannot_confirm");
    expect(store.get<{ status: string }>("SELECT status FROM retests WHERE id = ?", id)).toEqual({ status: "failed" });
  });
});
