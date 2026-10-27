import { describe, expect, test } from "bun:test";
import { evaluateRun, validatePoc, type PocManifest } from "../src/dynamic/poc.ts";

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
