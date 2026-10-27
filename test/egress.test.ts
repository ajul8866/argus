import { describe, expect, test } from "bun:test";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";
import { ContainerRuntime } from "../src/dynamic/runtime.ts";
import { checkRedirect, checkRequest, RateLimiter, type EgressPolicy } from "../src/dynamic/egress.ts";
import { BrokerServer } from "../src/dynamic/broker.ts";

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
    expect(calls[1]).toEqual(["docker", "network", "create", "argus-egress-a1"]);
    expect(calls[2]).toContain("argus/broker:test");
    expect(calls[2]).toContain("argus-audit-a1");
    expect(calls[4]).toContain("argus/worker:test");
    expect(calls[4]).toContain("argus-audit-a1");
    expect(calls[4]!.join(" ")).toContain("/tmp/ws:/workspace:rw");

    // The worker gets no route except the broker, which is its proxy.
    const worker = calls[4]!.join(" ");
    expect(worker).toContain("HTTP_PROXY=http://argus-broker-a1:8080");
    expect(worker).not.toContain("NET_RAW");
    expect(calls.some((argv) => argv.join(" ") === "docker network connect argus-egress-a1 argus-broker-a1")).toBe(true);

    await runtime.destroy("a1");
    const removed = calls.slice(-2).map((argv) => argv.join(" "));
    expect(removed).toEqual([
      "docker network rm argus-audit-a1",
      "docker network rm argus-egress-a1",
    ]);
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
    expect(calls.at(-2)).toEqual(["docker", "network", "rm", "argus-audit-a2"]);
    expect(calls.at(-1)).toEqual(["docker", "network", "rm", "argus-egress-a2"]);
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

describe("BrokerServer", () => {
  test("forwards in-scope HTTP, blocks out-of-scope hosts, and tunnels CONNECT", async () => {
    const target = createHttpServer((req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(`ok ${req.method}`);
    });
    await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", () => resolve()));
    const targetPort = (target.address() as { port: number }).port;
    const exchanges: Array<{ method: string; url: string; status: number; scopeDecision: string }> = [];
    const broker = new BrokerServer({
      policy: {
        baseUrl: "http://127.0.0.1",
        allowedHosts: ["127.0.0.1"],
        allowedCidrs: ["127.0.0.1/32"],
        allowedMethods: ["GET", "POST"],
        allowedPorts: [targetPort],
        maxRps: 100,
        tls: false,
      },
      onExchange: (record) => {
        exchanges.push(record);
      },
    });
    const { port } = await broker.start(0);

    try {
      const forwarded = await new Promise<{ code: number; body: string }>((resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port,
            method: "GET",
            path: `http://127.0.0.1:${targetPort}/ok`,
            headers: { host: `127.0.0.1:${targetPort}` },
          },
          (res) => {
            let body = "";
            res.on("data", (chunk) => (body += chunk));
            res.on("end", () => resolve({ code: res.statusCode ?? 0, body }));
          },
        );
        req.on("error", reject);
        req.end();
      });
      expect(forwarded).toEqual({ code: 200, body: "ok GET" });
      expect(exchanges[0]).toMatchObject({ method: "GET", status: 200, scopeDecision: "allowed" });

      const blocked = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          { host: "127.0.0.1", port, method: "GET", path: "http://evil.example.test/x" },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on("error", reject);
        req.end();
      });
      expect(blocked).toBe(403);

      const tunnel = await new Promise<string>((resolve, reject) => {
        const socket = netConnect(port, "127.0.0.1", () => {
          socket.write(`CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`);
        });
        let data = "";
        let sentGet = false;
        socket.on("data", (chunk) => {
          data += chunk.toString();
          if (!sentGet && data.includes("200 Connection Established")) {
            sentGet = true;
            socket.write("GET /tunnel HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
          }
          if (data.includes("ok GET")) {
            socket.end();
            resolve(data);
          }
        });
        socket.on("error", reject);
        setTimeout(() => {
          socket.destroy();
          resolve(data);
        }, 2_000);
      });
      expect(tunnel).toContain("200 Connection Established");
      expect(tunnel).toContain("ok GET");
    } finally {
      await broker.stop();
      await new Promise<void>((resolve) => target.close(() => resolve()));
    }
  });
});

describe("address pinning", () => {
  test("a request to a host that resolves to loopback is refused without an allowed CIDR", async () => {
    const target = createHttpServer((_request, response) => response.end("ok"));
    await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", resolve));
    const targetPort = (target.address() as { port: number }).port;
    const broker = new BrokerServer({
      policy: { ...policy, baseUrl: `http://localhost:${targetPort}`, allowedHosts: ["localhost"], allowedCidrs: [], tls: false },
    });
    const port = (await broker.start()).port;
    try {
      const status = await new Promise<number>((resolve, reject) => {
        const request = httpRequest(
          { host: "127.0.0.1", port, method: "GET", path: `http://localhost:${targetPort}/x` },
          (response) => {
            response.resume();
            resolve(response.statusCode ?? 0);
          },
        );
        request.on("error", reject);
        request.end();
      });
      expect(status).toBe(403);
    } finally {
      await broker.stop();
      await new Promise<void>((resolve) => target.close(() => resolve()));
    }
  });

  test("the pinned address is used instead of a second resolution", async () => {
    const seen: string[] = [];
    const target = createHttpServer((request, response) => {
      seen.push(String(request.headers.host));
      response.end("ok");
    });
    await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", resolve));
    const targetPort = (target.address() as { port: number }).port;
    const broker = new BrokerServer({
      policy: {
        ...policy,
        baseUrl: `http://127.0.0.1:${targetPort}`,
        allowedHosts: ["127.0.0.1"],
        allowedCidrs: ["127.0.0.1/32"],
        tls: false,
      },
    });
    const port = (await broker.start()).port;
    try {
      const body = await new Promise<string>((resolve, reject) => {
        const request = httpRequest(
          { host: "127.0.0.1", port, method: "GET", path: `http://127.0.0.1:${targetPort}/pinned` },
          (response) => {
            const chunks: Buffer[] = [];
            response.on("data", (chunk: Buffer) => chunks.push(chunk));
            response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
          },
        );
        request.on("error", reject);
        request.end();
      });
      expect(body).toBe("ok");
      expect(seen).toEqual([`127.0.0.1:${targetPort}`]);
    } finally {
      await broker.stop();
      await new Promise<void>((resolve) => target.close(() => resolve()));
    }
  });

  test("a CONNECT tunnel to a host outside the allowed CIDRs is refused", async () => {
    const broker = new BrokerServer({
      policy: { ...policy, baseUrl: "http://127.0.0.1:9", allowedHosts: ["127.0.0.1"], allowedCidrs: [], tls: false },
    });
    const port = (await broker.start()).port;
    try {
      const reply = await new Promise<string>((resolve, reject) => {
        const socket = netConnect(port, "127.0.0.1", () => {
          socket.write("CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n");
        });
        let data = "";
        socket.on("data", (chunk) => {
          data += chunk.toString();
          socket.destroy();
          resolve(data);
        });
        socket.on("error", reject);
        setTimeout(() => {
          socket.destroy();
          resolve(data);
        }, 2_000);
      });
      expect(reply).toContain("403 Forbidden");
    } finally {
      await broker.stop();
    }
  });
});

describe("broker container handshake", () => {
  test("identity tokens arrive once and never through the environment", async () => {
    const { startBrokerProcess } = await import("../src/dynamic/broker-process.ts");
    const process_ = await startBrokerProcess({
      port: 0,
      env: {
        ARGUS_TARGET_BASE_URL: "http://127.0.0.1:9",
        ARGUS_ALLOWED_HOSTS: "127.0.0.1",
        ARGUS_ALLOWED_CIDRS: "127.0.0.1/32",
        ARGUS_ALLOWED_METHODS: "GET",
        ARGUS_TARGET_TLS: "0",
      },
    });
    try {
      expect(process_.ready()).toBe(false);
      process_.handshake({ "id-a": "token-a" });
      expect(process_.ready()).toBe(true);
      expect(() => process_.handshake({ "id-a": "token-b" })).toThrow(/already/i);
    } finally {
      await process_.stop();
    }
  });

  test("the runtime writes the handshake into the broker container", async () => {
    const { calls, executor } = fakeExecutor();
    const runtime = new ContainerRuntime({
      executor,
      which: async () => "/usr/bin/docker",
      ...images,
    });
    await runtime.create("a1");
    await runtime.handshake("a1", { "id-a": "token-a" });
    const call = calls.find((argv) => argv.includes("exec") && argv.join(" ").includes("handshake.json"));
    expect(call).toBeDefined();
    expect(call!.join(" ")).toContain("argus-broker-a1");
    expect(call!.join(" ")).toContain("token-a");
  });
});

describe("worker control plane", () => {
  test("the worker joins an internal control network and learns the Argus API URL", async () => {
    const { calls, executor } = fakeExecutor();
    const runtime = new ContainerRuntime({
      executor,
      which: async () => "/usr/bin/docker",
      ...images,
    });
    const plan = await runtime.create("a3", {
      control: { network: "argus-control", apiUrl: "http://argus:8787" },
    });
    const created = calls.map((argv) => argv.join(" "));
    expect(created).toContain("docker network create --internal argus-control");
    expect(created).toContain("docker network connect argus-control argus-worker-a3");
    const worker = calls.find((argv) => argv.join(" ").includes("argus/worker:test"))!.join(" ");
    expect(worker).toContain("ARGUS_API_BASE_URL=http://argus:8787");
    expect(plan.controlUrl).toBe("http://argus:8787");
  });

  test("a worker without a control plane gets no Argus API URL", async () => {
    const { calls, executor } = fakeExecutor();
    const runtime = new ContainerRuntime({
      executor,
      which: async () => "/usr/bin/docker",
      ...images,
    });
    await runtime.create("a4");
    const worker = calls.find((argv) => argv.join(" ").includes("argus/worker:test"))!.join(" ");
    expect(worker).not.toContain("ARGUS_API_BASE_URL");
  });
});

describe("worker control plane routing", () => {
  test("the worker reaches Argus directly with no proxy while target traffic goes through the broker", async () => {
    const { calls, executor } = fakeExecutor();
    const runtime = new ContainerRuntime({
      executor,
      which: async () => "/usr/bin/docker",
      ...images,
    });
    await runtime.create("a5", {
      control: { network: "argus-control", apiUrl: "http://argus:8787" },
    });
    const worker = calls.find((argv) => argv.join(" ").includes("argus/worker:test"))!.join(" ");
    // NO_PROXY must cover the Argus host, or the API token would be sent to the broker.
    expect(worker).toContain("NO_PROXY=argus");
    expect(worker).toContain("no_proxy=argus");
  });
});
