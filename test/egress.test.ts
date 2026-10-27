import { describe, expect, test } from "bun:test";
import { ContainerRuntime } from "../src/dynamic/runtime.ts";

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
