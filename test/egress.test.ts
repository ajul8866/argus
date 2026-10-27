import { describe, expect, test } from "bun:test";
import { ContainerRuntime } from "../src/dynamic/runtime.ts";
import { checkRedirect, checkRequest, RateLimiter, type EgressPolicy } from "../src/dynamic/egress.ts";

function fakeExecutor(failOn?: (argv: string[]) => boolean) {
  const calls: string[][] = [];
  const executor = async (argv: string[]) => {
    calls.push(argv);
    if (failOn?.(argv)) return { code: 1, stdout: "", stderr: "boom" };
    return { code: 0, stdout: "ok", stderr: "" };
  };
  return { calls, executor };
}

const images = { workerImage: "argus/worker:test", brokerImage: "argus/broker:test" };

describe("ContainerRuntime", () => {
  test("detects docker and creates the internal network and containers", async () => {
    const { calls, executor } = fakeExecutor();
    const runtime = new ContainerRuntime({
      executor,
      which: async (bin) => (bin === "docker" ? "/usr/bin/docker" : null),
      ...images,
    });

    expect(await runtime.detect()).toBe("docker");
    const plan = await runtime.create("a1", { workspacePath: "/tmp/ws" });

    expect(plan.network).toBe("argus-audit-a1");
    expect(calls[0]).toEqual(["docker", "network", "create", "--internal", "argus-audit-a1"]);
    expect(calls[1]).toContain("argus/broker:test");
    expect(calls[1]).toContain("argus-audit-a1");
    expect(calls[2]).toContain("argus/worker:test");
    expect(calls[2]).toContain("argus-audit-a1");
    expect(calls[2]!.join(" ")).toContain("/tmp/ws:/workspace:rw");

    await runtime.destroy("a1");
    expect(calls.at(-1)).toEqual(["docker", "network", "rm", "argus-audit-a1"]);
  });

  test("cleans up when a container fails to start", async () => {
    const { calls, executor } = fakeExecutor((argv) => argv.includes("argus/worker:test"));
    const runtime = new ContainerRuntime({
      executor,
      which: async () => "/usr/bin/docker",
      ...images,
    });

    await expect(runtime.create("a2")).rejects.toThrow(/failed|boom/i);
    expect(calls.some((argv) => argv.includes("rm"))).toBe(true);
    expect(calls.at(-1)).toEqual(["docker", "network", "rm", "argus-audit-a2"]);
  });

  test("refuses to create when no runtime is installed", async () => {
    const runtime = new ContainerRuntime({
      executor: async () => ({ code: 0, stdout: "", stderr: "" }),
      which: async () => null,
    });

    expect(await runtime.detect()).toBeNull();
    await expect(runtime.create("a3")).rejects.toThrow(/docker|podman/i);
  });

  test("exec runs inside the worker container", async () => {
    const { calls, executor } = fakeExecutor();
    const runtime = new ContainerRuntime({
      executor,
      which: async () => "/usr/bin/docker",
      ...images,
    });

    await runtime.create("a4");
    await runtime.exec("a4", ["sh", "-lc", "id"]);
    expect(calls.at(-1)).toEqual(["docker", "exec", "argus-worker-a4", "sh", "-lc", "id"]);
  });
});

const policy: EgressPolicy = {
  baseUrl: "https://app.example.test",
  allowedHosts: ["app.example.test", "*.api.example.test"],
  allowedCidrs: ["203.0.113.0/24"],
  allowedMethods: ["GET", "POST"],
  maxRps: 2,
  tls: true,
  restrictions: { denied_paths: ["/admin"] },
};

describe("egress policy", () => {
  test("allows an in-scope request and blocks the obvious escapes", () => {
    expect(checkRequest(policy, { method: "GET", url: "https://app.example.test/invoices" }, ["203.0.113.10"])).toEqual({
      allowed: true,
    });
    expect(checkRequest(policy, { method: "GET", url: "https://evil.example.test/x" }, ["203.0.113.10"])).toMatchObject({
      allowed: false,
    });
    expect(checkRequest(policy, { method: "DELETE", url: "https://app.example.test/invoices" }, ["203.0.113.10"])).toMatchObject({
      allowed: false,
    });
    expect(checkRequest(policy, { method: "GET", url: "http://app.example.test/invoices" }, ["203.0.113.10"])).toMatchObject({
      allowed: false,
    });
    expect(checkRequest(policy, { method: "GET", url: "https://app.example.test/admin" }, ["203.0.113.10"])).toMatchObject({
      allowed: false,
    });
  });

  test("allows wildcard hosts and rejects private or metadata addresses", () => {
    expect(
      checkRequest(policy, { method: "GET", url: "https://v1.api.example.test/x" }, ["203.0.113.10"]),
    ).toEqual({ allowed: true });
    expect(
      checkRequest(policy, { method: "GET", url: "https://app.example.test/x" }, ["169.254.169.254"]),
    ).toMatchObject({ allowed: false });
    expect(
      checkRequest(policy, { method: "GET", url: "https://app.example.test/x" }, ["10.0.0.5"]),
    ).toMatchObject({ allowed: false });
    expect(
      checkRequest(policy, { method: "GET", url: "https://app.example.test/x" }, ["127.0.0.1"]),
    ).toMatchObject({ allowed: false });
    expect(
      checkRequest(
        { ...policy, allowedCidrs: ["127.0.0.1/32"] },
        { method: "GET", url: "https://app.example.test/x" },
        ["127.0.0.1"],
      ),
    ).toEqual({ allowed: true });
  });

  test("rate limits per key", () => {
    const limiter = new RateLimiter();
    expect(limiter.allow("target:user_a", 2, 0)).toBe(true);
    expect(limiter.allow("target:user_a", 2, 10)).toBe(true);
    expect(limiter.allow("target:user_a", 2, 20)).toBe(false);
    expect(limiter.allow("target:user_a", 2, 1_001)).toBe(true);
  });

  test("checks redirects and the redirect cap", () => {
    expect(
      checkRedirect("https://app.example.test/a", "https://evil.example.test/b", policy, 0),
    ).toMatchObject({ allowed: false });
    expect(
      checkRedirect("https://app.example.test/a", "https://v1.api.example.test/b", policy, 0),
    ).toEqual({ allowed: true });
    expect(
      checkRedirect("https://app.example.test/a", "https://app.example.test/b", policy, 3),
    ).toMatchObject({ allowed: false });
  });
});
