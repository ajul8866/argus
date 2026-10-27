import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { createBrokerDynamicExecutor, runPocChecks } from "../src/dynamic/executor.ts";
import { resolveAndValidate, type EgressPolicy } from "../src/dynamic/egress.ts";
import { TargetService } from "../src/dynamic/targets.ts";
import { BrokerServer, BROKER_DEADLINE_HEADER, BROKER_FORWARD_PATH, BROKER_TARGET_HEADER } from "../src/dynamic/broker.ts";
import { requestThroughBroker } from "../src/dynamic/http.ts";
import { DynamicProofService } from "../src/dynamic/proof.ts";
import { GraphStore } from "../src/dynamic/graph.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { now } from "../src/util.ts";

let dir: string;
let store: Store;
let server: Server;
let config: Config;
let baseUrl: string;
let seen: Array<{ method: string; path: string }>;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "argus-transport-"));
  config = { dataDir: dir, masterKey: "synthetic-transport-key" } as Config;
  store = new Store(config, "test.sqlite");
  store.run("INSERT INTO projects (id,name,source_path,scope_include,scope_exclude,authorized_by,authorization_ref,created_at,updated_at) VALUES ('p1','Transport',?,'[]','[]','','',?,?)", dir, now(), now());
  store.run("INSERT INTO audits (id,project_id,status,current_phase,config,mode,created_at) VALUES ('a1','p1','running',2,'{}','dynamic',?)", now());
  seen = [];
  server = createServer((request, response) => {
    seen.push({ method: request.method ?? "", path: request.url ?? "" });
    if (request.url?.startsWith("/api/items/missing")) response.statusCode = 404;
    response.end(`${request.method} ${request.url}`);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Target did not bind a port");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function snapshot(methods: string[]) {
  const targets = new TargetService(store);
  const target = targets.createTarget({
    projectId: "p1", label: "Local target", baseUrl, environment: "test",
    allowedHosts: ["127.0.0.1"], allowedCidrs: ["127.0.0.1/32"],
    allowedMethods: methods, tlsRequired: false, maxRps: 100,
  });
  targets.createAuthorization({ targetId: target.id, authorizedBy: "Tester", reference: "LOCAL-ONLY", validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z", authorizedActions: { methods } });
  const identity = targets.createIdentity({ targetId: target.id, label: "Anonymous", role: "test", authKind: "none" });
  targets.createIdentity({ targetId: target.id, label: "Second identity", role: "attacker", authKind: "none" });
  targets.createSnapshot({
    auditId: "a1", mode: "dynamic", targetId: target.id, permissions: ["audit:launch_dynamic"], repository: null,
    budget: { max_usd: 1, exploration_cap_usd: 1, verification_reserve_usd: 0, max_tasks: 10, max_requests: 10, max_runtime_minutes: 1 },
  });
  return identity.id;
}

function checks(identity: string, method: string) {
  return { checks: {
    positive: { identity, request: { method, path: "/api/items/one?control=positive" } },
    exploit: { identity, request: { method, path: "/api/items/one?control=exploit" } },
    negative: { identity, request: { method, path: "/api/items/missing" } },
  } };
}

describe("dynamic request transport", () => {
  test("supported methods arrive unchanged and unsupported tokens never become GET", async () => {
    const methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"];
    const broker = new BrokerServer({ policy: { baseUrl, allowedHosts: ["127.0.0.1"], allowedCidrs: ["127.0.0.1/32"], allowedMethods: methods, maxRps: 100, tls: false } });
    const port = (await broker.start()).port;
    try {
      for (const method of methods) expect((await requestThroughBroker(port, baseUrl, method.toLowerCase(), null)).status).toBe(200);
      expect(seen.map((request) => request.method)).toEqual(methods);
      await expect(requestThroughBroker(port, baseUrl, "CUSTOM", null)).rejects.toThrow("Unsupported broker request method");
      expect(seen).toHaveLength(methods.length);
    } finally {
      await broker.stop();
    }
  });

  test("PoC replay sends each declared method and preserves path and query", async () => {
    const identity = snapshot(["GET", "POST", "OPTIONS"]);
    const manifest = checks(identity, "POST");
    manifest.checks.negative.request.method = "OPTIONS";
    const result = await runPocChecks(config, store, "a1", manifest);
    expect(seen).toEqual([
      { method: "POST", path: "/api/items/one?control=positive" },
      { method: "POST", path: "/api/items/one?control=exploit" },
      { method: "OPTIONS", path: "/api/items/missing" },
    ]);
    expect(result.positive.body).toBe("POST /api/items/one?control=positive");
  });

  test("an unauthorized PoC method is blocked instead of silently replaced with GET", async () => {
    const identity = snapshot(["GET"]);
    const result = await runPocChecks(config, store, "a1", checks(identity, "DELETE"));
    expect([result.positive.status, result.exploit.status, result.negative.status]).toEqual([403, 403, 403]);
    expect(seen).toEqual([]);
  });

  test("an authorized POST-only intent works without requiring GET permission", async () => {
    snapshot(["POST"]);
    const executor = createBrokerDynamicExecutor(config, store);
    const result = await executor.execute("a1", { nodeId: "intent", title: "POST probe", assetIds: ["asset"], method: "POST", path: "/api/probe?test=1" });
    expect(result.facts[0]?.status).toBe(200);
    expect(result.facts[0]?.summary).toBe("POST /api/probe?test=1 → 200");
    expect(seen).toEqual([{ method: "POST", path: "/api/probe?test=1" }]);
  });

  test("address validation does not invent an HTTP GET at the root of a TLS and path-restricted target", async () => {
    const result = await resolveAndValidate({
      baseUrl: "https://localhost/api", allowedHosts: ["localhost"], allowedCidrs: ["127.0.0.1/32"],
      allowedMethods: ["POST"], maxRps: 1, tls: true, restrictions: { allowed_paths: ["/api"] },
    }, "localhost");
    expect(result).toEqual({ allowed: true, addresses: ["127.0.0.1"] });
  });

  test("confirmation persists POST evidence only after replaying the POST checks", async () => {
    const owner = snapshot(["POST"]);
    const attacker = store.get<{ id: string }>("SELECT id FROM test_identities WHERE role = 'attacker'")!.id;
    const asset = new GraphStore(store).upsertAsset({ projectId: "p1", kind: "endpoint", assetKey: "/api/items/one" });
    const evidence = new EvidenceStore(config, store);
    const proof = new DynamicProofService(store, evidence, (auditId, manifest) => runPocChecks(config, store, auditId, manifest));
    const candidate = await proof.propose({
      auditId: "a1", assetId: asset.id, title: "Synthetic method check", category: "idor", severity: "low",
      proposedBy: "discoverer", script: "Synthetic local POST reproduction.",
      manifest: {
        language: "text", script_evidence_id: "pending", object: { asset_id: asset.id, object_id: "one", owner_identity: owner },
        checks: {
          positive: { identity: owner, request: { method: "POST", path: "/api/items/one" }, expect: { status: 200, body_contains: "POST" } },
          exploit: { identity: attacker, request: { method: "POST", path: "/api/items/one" }, expect: { status: 200, body_contains: "POST" } },
          negative: { identity: attacker, request: { method: "POST", path: "/api/items/missing" }, expect: { status: 404 } },
        },
        environment: { target: baseUrl, identities: [owner, attacker] },
      },
    });
    const result = await proof.confirm(candidate.candidateId, "validator");
    expect(result.verdict).toBe("CONFIRMED");
    expect(seen.map((request) => request.method)).toEqual(["POST", "POST", "POST"]);
    const exchange = evidence.listForFinding(result.findingId!).find((row) => row.kind === "http_exchange");
    expect(exchange).toBeDefined();
    expect(JSON.parse((await evidence.content(exchange!.id))!.content)).toMatchObject({ method: "POST", status: 200, body: "POST /api/items/one" });
  });

  test("HTTPS targets use an ordinary broker request rather than an opaque CONNECT", async () => {
    const captured: Array<{ method: string | undefined; path: string | undefined; target: unknown; identity: unknown }> = [];
    const peer = createServer((request, response) => {
      captured.push({ method: request.method, path: request.url, target: request.headers[BROKER_TARGET_HEADER], identity: request.headers["x-argus-identity"] });
      response.end("recorded");
    });
    await new Promise<void>((resolve) => peer.listen(0, "127.0.0.1", resolve));
    try {
      const address = peer.address();
      if (!address || typeof address === "string") throw new Error("Peer did not bind");
      const result = await requestThroughBroker(address.port, "https://target.invalid/api/one?x=1", "POST", "identity", { timeoutMs: 1_000 });
      expect(result).toEqual({ status: 200, body: "recorded" });
      expect(captured).toEqual([{ method: "POST", path: "/__argus/forward", target: "https://target.invalid/api/one?x=1", identity: "identity" }]);
    } finally {
      peer.closeAllConnections();
      await new Promise<void>((resolve) => peer.close(() => resolve()));
    }
  });

  for (const mode of ["timeout", "oversized", "interrupted"] as const) {
    test(`a ${mode} broker response rejects instead of hanging or returning partial evidence`, async () => {
      const peer = createServer((_request, response) => {
        if (mode === "timeout") return;
        if (mode === "oversized") response.end("x".repeat(100));
        else {
          response.writeHead(200, { "content-length": "100" });
          response.write("partial");
          setImmediate(() => response.destroy());
        }
      });
      await new Promise<void>((resolve) => peer.listen(0, "127.0.0.1", resolve));
      try {
        const address = peer.address();
        if (!address || typeof address === "string") throw new Error("Peer did not bind");
        await expect(requestThroughBroker(address.port, baseUrl, "GET", null, { timeoutMs: mode === "timeout" ? 30 : 1_000, maxBytes: 16 })).rejects.toThrow();
      } finally {
        peer.closeAllConnections();
        await new Promise<void>((resolve) => peer.close(() => resolve()));
      }
    });
  }

  test("DNS validation checks every result without inventing a method, scheme, or path", async () => {
    const policy: EgressPolicy = { baseUrl: "https://public.invalid/api", allowedHosts: ["public.invalid"], allowedCidrs: [], allowedMethods: ["POST"], maxRps: 1, tls: true, restrictions: { allowed_paths: ["/api"] } };
    expect(await resolveAndValidate(policy, "public.invalid", async () => ["203.0.113.7"])).toEqual({ allowed: true, addresses: ["203.0.113.7"] });
    for (const addresses of [["203.0.113.7", "127.0.0.1"], ["127.0.0.1", "203.0.113.7"], ["not-an-address"], []]) {
      expect((await resolveAndValidate(policy, "public.invalid", async () => addresses)).allowed).toBe(false);
    }
    expect((await resolveAndValidate(policy, "public.invalid", async () => { throw new Error("DNS failed"); })).allowed).toBe(false);
  });

  test("the forwarding endpoint resolves before address rejection and never leaks transport headers upstream", async () => {
    let resolutions = 0;
    const policy: EgressPolicy = { baseUrl, allowedHosts: ["target.invalid"], allowedCidrs: [], allowedMethods: ["POST"], maxRps: 100, tls: false };
    const broker = new BrokerServer({ policy, lookup: async () => { resolutions += 1; return ["127.0.0.1"]; } });
    const port = (await broker.start()).port;
    try {
      expect((await requestThroughBroker(port, "http://target.invalid/api", "GET", null)).status).toBe(403);
      expect(resolutions).toBe(0);
      expect((await requestThroughBroker(port, "http://target.invalid/api", "POST", null)).status).toBe(403);
      expect(resolutions).toBe(1);
      expect(seen).toEqual([]);
    } finally {
      await broker.stop();
    }
    const accepted = new BrokerServer({ policy: { ...policy, allowedCidrs: ["127.0.0.1/32"] }, lookup: async () => ["127.0.0.1"] });
    const acceptedPort = (await accepted.start()).port;
    let upstreamTarget: unknown;
    let upstreamDeadline: unknown;
    server.on("request", (request) => {
      upstreamTarget = request.headers[BROKER_TARGET_HEADER];
      upstreamDeadline = request.headers[BROKER_DEADLINE_HEADER];
    });
    const targetPort = new URL(baseUrl).port;
    try {
      expect((await requestThroughBroker(acceptedPort, `http://target.invalid:${targetPort}/api`, "POST", null)).status).toBe(200);
      expect(upstreamTarget).toBeUndefined();
      expect(upstreamDeadline).toBeUndefined();
      expect(seen).toEqual([{ method: "POST", path: "/api" }]);
    } finally {
      await accepted.stop();
    }
  });

  for (const restriction of ["tls", "method", "path"] as const) {
    test(`splitting address validation does not enable CONNECT for a ${restriction}-restricted policy`, async () => {
      const broker = new BrokerServer({ policy: {
        baseUrl, allowedHosts: ["127.0.0.1"], allowedCidrs: ["127.0.0.1/32"], allowedMethods: restriction === "method" ? ["POST"] : ["GET"], maxRps: 100,
        tls: restriction === "tls", restrictions: restriction === "path" ? { allowed_paths: ["/api"] } : {},
      } });
      const port = (await broker.start()).port;
      try {
        const status = await new Promise<string>((resolve, reject) => {
          const socket = connect(port, "127.0.0.1", () => socket.write("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
          socket.setTimeout(1_000, () => socket.destroy(new Error("CONNECT did not settle")));
          socket.on("data", (chunk) => { socket.destroy(); resolve(chunk.toString()); });
          socket.on("error", reject);
        });
        expect(status).toContain("403 Forbidden");
        expect(seen).toEqual([]);
      } finally {
        await broker.stop();
      }
    });
  }

  for (const size of [5_000_000, 5_000_001]) {
    test(`the actual broker ${size === 5_000_000 ? "accepts its exact upstream byte limit" : "refuses upstream overflow without a partial 200"}`, async () => {
      server.removeAllListeners("request");
      server.on("request", (_request, response) => response.end("x".repeat(size)));
      const broker = new BrokerServer({ policy: { baseUrl, allowedHosts: ["127.0.0.1"], allowedCidrs: ["127.0.0.1/32"], allowedMethods: ["GET"], maxRps: 100, tls: false } });
      const port = (await broker.start()).port;
      try {
        const result = await requestThroughBroker(port, baseUrl, "GET", null);
        expect(result.status).toBe(size === 5_000_000 ? 200 : 502);
        if (size === 5_000_000) expect(Buffer.byteLength(result.body)).toBe(size);
        else expect(result.body).toContain("response exceeds the broker limit");
      } finally {
        await broker.stop();
      }
    });
  }

  for (const cancel of ["client deadline", "broker stop"] as const) {
    test(`a ${cancel} closes a trickling upstream connection`, async () => {
      let closeUpstream: () => void = () => {};
      const closed = new Promise<void>((resolve) => { closeUpstream = resolve; });
      let started: () => void = () => {};
      const active = new Promise<void>((resolve) => { started = resolve; });
      server.once("connection", (socket) => socket.once("close", closeUpstream));
      server.removeAllListeners("request");
      server.on("request", (_request, response) => {
        response.writeHead(200);
        response.write("prefix");
        const timer = setInterval(() => response.write("x"), 10);
        response.socket?.once("close", () => clearInterval(timer));
        started();
      });
      const broker = new BrokerServer({ policy: { baseUrl, allowedHosts: ["127.0.0.1"], allowedCidrs: ["127.0.0.1/32"], allowedMethods: ["GET"], maxRps: 100, tls: false } });
      const port = (await broker.start()).port;
      try {
        const pending = requestThroughBroker(port, baseUrl, "GET", null, { timeoutMs: cancel === "client deadline" ? 80 : 1_000 });
        const completion = pending.then((result) => {
          expect(result.status).toBe(502);
          expect(result.body).toContain("timed out");
        }, (error) => {
          if (cancel === "client deadline") expect(String(error)).toContain("timed out");
        });
        await active;
        if (cancel === "broker stop") await broker.stop();
        await completion;
        await Promise.race([closed, Bun.sleep(500).then(() => { throw new Error("The upstream kept running after cancellation"); })]);
      } finally {
        await broker.stop();
        server.closeAllConnections();
      }
    });
  }

  test("a request whose deadline expired during resolution never reaches upstream", async () => {
    const broker = new BrokerServer({ policy: { baseUrl, allowedHosts: ["target.invalid"], allowedCidrs: ["127.0.0.1/32"], allowedMethods: ["GET"], maxRps: 100, tls: false }, lookup: async () => { await Bun.sleep(30); return ["127.0.0.1"]; } });
    const port = (await broker.start()).port;
    try {
      const response = await fetch(`http://127.0.0.1:${port}${BROKER_FORWARD_PATH}`, { headers: {
        [BROKER_TARGET_HEADER]: `http://target.invalid:${new URL(baseUrl).port}/`,
        [BROKER_DEADLINE_HEADER]: String(Date.now() + 5),
      } });
      expect(response.status).toBe(502);
      expect(await response.text()).toContain("timed out");
      expect(seen).toEqual([]);
    } finally {
      await broker.stop();
    }
  });

  test("shutdown closes a CONNECT client that is still waiting for DNS", async () => {
    let entered: () => void = () => {};
    const active = new Promise<void>((resolve) => { entered = resolve; });
    let release: () => void = () => {};
    const pendingLookup = new Promise<void>((resolve) => { release = resolve; });
    let upstreamConnections = 0;
    server.on("connection", () => { upstreamConnections += 1; });
    const targetPort = Number(new URL(baseUrl).port);
    const broker = new BrokerServer({ policy: { baseUrl, allowedHosts: ["target.invalid"], allowedCidrs: ["127.0.0.1/32"], allowedMethods: ["GET"], allowedPorts: [targetPort], maxRps: 100, tls: false }, lookup: async () => { entered(); await pendingLookup; return ["127.0.0.1"]; } });
    const port = (await broker.start()).port;
    const client = connect(port, "127.0.0.1", () => client.write(`CONNECT target.invalid:${targetPort} HTTP/1.1\r\nHost: target.invalid\r\n\r\n`));
    client.on("error", () => {});
    const closed = new Promise<void>((resolve) => client.once("close", resolve));
    try {
      await active;
      const stopped = broker.stop();
      await Promise.race([Promise.all([stopped, closed]), Bun.sleep(500).then(() => { throw new Error("CONNECT prevented broker shutdown during DNS"); })]);
      release();
      await Bun.sleep(20);
      expect(upstreamConnections).toBe(0);
    } finally {
      client.destroy();
      release();
      await broker.stop();
    }
  });

  test("private IPv6 addresses are rejected in mapped, expanded, and link-local forms", async () => {
    const policy: EgressPolicy = { baseUrl: "https://target.invalid", allowedHosts: ["target.invalid"], allowedCidrs: [], allowedMethods: ["GET"], maxRps: 1, tls: true };
    for (const address of ["::ffff:7f00:1", "::ffff:ac10:1", "::ffff:a9fe:a9fe", "0:0:0:0:0:0:0:1", "fe90::1", "febf::1", "fd00::1", "ff02::1"]) {
      expect((await resolveAndValidate(policy, "target.invalid", async () => [address])).allowed).toBe(false);
    }
    for (const address of ["2001:4860:4860::8888", "::ffff:808:808", "203.0.113.7"]) {
      expect((await resolveAndValidate(policy, "target.invalid", async () => [address])).allowed).toBe(true);
    }
  });

  test("CIDR checks support IPv6 and mapped IPv4 while rejecting any out-of-scope answer", async () => {
    const policy: EgressPolicy = { baseUrl: "https://target.invalid", allowedHosts: ["target.invalid"], allowedCidrs: ["fd00::/8", "127.0.0.1/32"], allowedMethods: ["GET"], maxRps: 1, tls: true };
    expect((await resolveAndValidate(policy, "target.invalid", async () => ["fd00::1", "::ffff:7f00:1"])).allowed).toBe(true);
    expect((await resolveAndValidate(policy, "target.invalid", async () => ["fd00::1", "fe80::1"])).allowed).toBe(false);
    expect((await resolveAndValidate({ ...policy, allowedCidrs: ["not-a-cidr"] }, "target.invalid", async () => ["127.0.0.1"])).allowed).toBe(false);
  });
});
