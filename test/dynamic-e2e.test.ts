import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createServer, request as httpRequest, type Server } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import { Database } from "bun:sqlite";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { EventLog } from "../src/events.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { AuditEngine, type DynamicExecutor } from "../src/orchestrator/engine.ts";
import { ReportService } from "../src/reports/generator.ts";
import { encryptSecret } from "../src/security/credentials.ts";
import { BrokerServer } from "../src/dynamic/broker.ts";
import { CredentialBroker } from "../src/dynamic/credentials.ts";
import type { EgressPolicy } from "../src/dynamic/egress.ts";
import { GraphStore } from "../src/dynamic/graph.ts";
import type { PocManifest } from "../src/dynamic/poc.ts";
import { DynamicProofService } from "../src/dynamic/proof.ts";
import { RetestService } from "../src/dynamic/retest.ts";
import { TargetService } from "../src/dynamic/targets.ts";
import { now } from "../src/util.ts";

type Exchange = { status: number; body: string };

const FIXTURE_SECRET = "acme-dev-secret-2024";

function jwt(payload: Record<string, unknown>, secret: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${signature}`;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

function proxyRequest(port: number, target: string, identityId: string): Promise<Exchange> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        host: "127.0.0.1",
        port,
        method: "GET",
        path: target,
        headers: { "x-argus-identity": identityId },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    request.on("error", reject);
    request.end();
  });
}

let dir = "";
let store: Store;
let config: Config;
let evidence: EvidenceStore;
let events: EventLog;
let graph: GraphStore;
let targets: TargetService;
let targetServer: Server | null = null;
let fixture: ChildProcess | null = null;
let fixtureDb = "";
let usingFixture = false;
let broker: BrokerServer | null = null;
let baseUrl = "";
let fixed = false;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "argus-dynamic-e2e-"));
  config = { dataDir: dir } as Config;
  store = new Store(config);
  evidence = new EvidenceStore(config, store);
  events = new EventLog(store);
  graph = new GraphStore(store);
  targets = new TargetService(store);
  fixed = false;
});

afterEach(async () => {
  await broker?.stop();
  broker = null;
  if (fixture) {
    const child = fixture;
    fixture = null;
    child.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        resolve();
      }, 2_000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  if (targetServer) {
    await new Promise<void>((resolve) => targetServer!.close(() => resolve()));
    targetServer = null;
  }
  if (fixtureDb) {
    rmSync(fixtureDb, { force: true });
    rmSync(`${fixtureDb}-wal`, { force: true });
    rmSync(`${fixtureDb}-shm`, { force: true });
    fixtureDb = "";
  }
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("dynamic IDOR proof", () => {
  test("finds, proves, retests, and exports a cross-tenant invoice read", async () => {
    const fixtureDir = join(import.meta.dir, "fixtures", "vulnerable-app");
    usingFixture = existsSync(join(fixtureDir, "node_modules", "better-sqlite3"));
    let targetPort = 0;
    if (usingFixture) {
      fixtureDb = join(fixtureDir, "src", "acme.sqlite");
      rmSync(fixtureDb, { force: true });
      const db = new Database(fixtureDb);
      db.run("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL)");
      db.run("CREATE TABLE invoices (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, amount REAL NOT NULL)");
      db.run(
        "INSERT INTO users (id, email, display_name, role) VALUES ('user_a','a@example.test','A','user'), ('user_b','b@example.test','B','user')",
      );
      db.run("INSERT INTO invoices (id, owner_id, amount) VALUES ('inv-1','user_b',42), ('inv-2','user_a',7)");
      db.close();
      targetPort = await freePort();
      fixture = spawn("node", ["src/server.js"], {
        cwd: fixtureDir,
        env: { ...process.env, PORT: String(targetPort) },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let output = "";
      fixture.stdout?.on("data", (chunk) => {
        output += String(chunk);
      });
      fixture.stderr?.on("data", (chunk) => {
        output += String(chunk);
      });
      let ready = false;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        if (fixture.exitCode !== null) break;
        try {
          const response = await fetch(`http://127.0.0.1:${targetPort}/health`);
          if (response.ok) {
            ready = true;
            break;
          }
        } catch {
          // The server is not listening yet.
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      if (!ready) throw new Error(`fixture did not start: ${output}`);
    } else {
      const invoices: Record<string, { owner: string }> = {
        "inv-1": { owner: "user_b" },
        "inv-2": { owner: "user_a" },
      };
      targetServer = createServer((request, response) => {
        const url = new URL(request.url ?? "/", "http://127.0.0.1");
        if (url.pathname === "/health") {
          response.writeHead(200).end("ok");
          return;
        }
        const match = /^\/api\/invoices\/([^/]+)$/.exec(url.pathname);
        if (!match) {
          response.writeHead(404).end("{}");
          return;
        }
        const authorization = request.headers.authorization ?? "";
        const user = authorization === "Bearer token-a" ? "user_a" : authorization === "Bearer token-b" ? "user_b" : null;
        if (!user) {
          response.writeHead(401).end("{}");
          return;
        }
        const invoice = invoices[decodeURIComponent(match[1] ?? "")];
        if (!invoice) {
          response.writeHead(404).end("{}");
          return;
        }
        if (fixed && invoice.owner !== user) {
          response.writeHead(403).end('{"error":"forbidden"}');
          return;
        }
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ invoice: { id: match[1], owner_id: invoice.owner } }));
      });
      await new Promise<void>((resolve) => targetServer!.listen(0, "127.0.0.1", resolve));
      targetPort = (targetServer.address() as { port: number }).port;
    }
    baseUrl = `http://127.0.0.1:${targetPort}`;

    store.run(
      `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES ('p1','Invoice portal', ?, '**/*', '', 'Tester', 'AUTH-1', ?, ?)`,
      dir,
      now(),
      now(),
    );
    store.run(
      `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
       VALUES ('r1','p1',?, 'abc123','main','{}','[]','{}','{}',1,10,?)`,
      join(import.meta.dir, "fixtures", "vulnerable-app"),
      now(),
    );
    store.run(
      `INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, mode, exploration_status, created_at)
       VALUES ('a1','p1','r1','running',2,'{}','dynamic','open',?)`,
      now(),
    );

    const asset = graph.upsertAsset({ projectId: "p1", kind: "app", assetKey: baseUrl });
    const goal = graph.createNode({
      auditId: "a1",
      kind: "goal",
      payload: { text: "Find access control weaknesses in the invoice API" },
    });
    graph.anchor(goal.id, asset.id);

    const target = targets.createTarget({
      projectId: "p1",
      label: "Invoice portal",
      baseUrl,
      environment: "test",
      allowedHosts: ["127.0.0.1"],
      allowedCidrs: ["127.0.0.1/32"],
      allowedMethods: ["GET"],
      maxRps: 100,
      tlsRequired: false,
    });
    targets.createAuthorization({
      targetId: target.id,
      authorizedBy: "Tester",
      reference: "AUTH-1",
      validFrom: new Date(Date.now() - 60_000).toISOString(),
      validUntil: new Date(Date.now() + 3_600_000).toISOString(),
      authorizedActions: { methods: ["GET"] },
    });
    const identityA = targets.createIdentity({
      targetId: target.id,
      label: "user_a",
      role: "user",
      authKind: "header",
      secretRef: "test:user_a",
    });
    const identityB = targets.createIdentity({
      targetId: target.id,
      label: "user_b",
      role: "user",
      authKind: "header",
      secretRef: "test:user_b",
    });
    const tokenA = usingFixture ? jwt({ id: "user_a", role: "user" }, FIXTURE_SECRET) : "token-a";
    const tokenB = usingFixture ? jwt({ id: "user_b", role: "user" }, FIXTURE_SECRET) : "token-b";
    for (const [ref, token] of [
      ["test:user_a", tokenA],
      ["test:user_b", tokenB],
    ] as const) {
      const encrypted = encryptSecret(config, token);
      store.run(
        `INSERT INTO provider_credentials (id, provider, env_var, ciphertext, iv, tag, last4, created_at, updated_at)
         VALUES (?, 'test-identity', ?, ?, ?, ?, ?, ?, ?)`,
        `cred-${ref}`,
        ref,
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.tag,
        encrypted.last4,
        now(),
        now(),
      );
    }

    const snapshot = targets.createSnapshot({
      auditId: "a1",
      mode: "dynamic",
      targetId: target.id,
      permissions: ["audit:launch_dynamic"],
      budget: {
        max_usd: 10,
        exploration_cap_usd: 6,
        verification_reserve_usd: 4,
        max_tasks: 20,
        max_requests: 100,
        max_runtime_minutes: 10,
      },
      repository: { id: "r1", commit_sha: "abc123" },
    }).snapshot;

    const credentials = new CredentialBroker(config, store);
    const policy: EgressPolicy = {
      baseUrl,
      allowedHosts: ["127.0.0.1"],
      allowedCidrs: ["127.0.0.1/32"],
      allowedMethods: ["GET"],
      maxRps: 100,
      tls: false,
      authorizedActions: { methods: ["GET"] },
    };
    const exchanges: Array<{ identityId: string | null; status: number; url: string }> = [];
    broker = new BrokerServer({
      policy,
      credentials,
      onExchange: (record) => {
        exchanges.push({ identityId: record.identityId, status: record.status, url: record.url });
      },
    });
    const brokerPort = (await broker.start()).port;
    const brokerUrl = `http://127.0.0.1:${brokerPort}`;

    const proof = new DynamicProofService(
      store,
      evidence,
      async (_auditId, manifest) => ({
        positive: await proxyRequest(brokerPort, `${baseUrl}${manifest.checks.positive.request.path}`, manifest.checks.positive.identity),
        exploit: await proxyRequest(brokerPort, `${baseUrl}${manifest.checks.exploit.request.path}`, manifest.checks.exploit.identity),
        negative: await proxyRequest(brokerPort, `${baseUrl}${manifest.checks.negative.request.path}`, manifest.checks.negative.identity),
      }),
      graph,
    );
    const manifest: PocManifest = {
      language: "typescript",
      script_evidence_id: "pending",
      object: { asset_id: asset.id, object_id: "inv-1", owner_identity: identityB.id },
      checks: {
        positive: {
          identity: identityB.id,
          request: { method: "GET", path: "/api/invoices/inv-1" },
          expect: { status: 200, body_contains: "inv-1" },
        },
        exploit: {
          identity: identityA.id,
          request: { method: "GET", path: "/api/invoices/inv-1" },
          expect: { status: 200, body_contains: "inv-1" },
        },
        negative: {
          identity: identityA.id,
          request: { method: "GET", path: "/api/invoices/inv-999" },
          expect: { status: 404 },
        },
      },
      environment: { target: baseUrl, commit_sha: "abc123", identities: [identityA.id, identityB.id] },
    };

    const executor: DynamicExecutor = {
      async plan() {
        return [
          {
            title: "Cross-tenant invoice read",
            assetIds: [asset.id],
            method: "GET",
            path: "/api/invoices/inv-1",
            expectedSignal: "The invoice route returns an object owned by another identity.",
            rationale: "The route is authenticated but the handler does not compare the owner.",
            category: "idor",
          },
        ];
      },
      async execute(_auditId, intent) {
        const exploit = await proxyRequest(brokerPort, `${baseUrl}/api/invoices/inv-1`, identityA.id);
        const proposed = await proof.propose({
          auditId: "a1",
          assetId: asset.id,
          title: "Cross-tenant invoice read",
          category: "idor",
          severity: "high",
          manifest,
          script: `# Reproduces the cross-tenant invoice read\nrequests.get("${baseUrl}/api/invoices/inv-1", headers={"authorization": "Bearer <user_a>"})`,
          intentNodeId: intent.nodeId,
          proposedBy: "worker-1",
          source: {
            path: "src/routes/invoices.js",
            start_line: 11,
            end_line: 17,
            quote: "router.get(\"/:id\", (request, response) => {\n  const invoice = findInvoiceById(request.params.id);",
          },
        });
        expect(proposed.sourceVerified).toBe(true);
        const confirmed = await proof.confirm(proposed.candidateId, "validator-1");
        expect(confirmed.verdict).toBe("CONFIRMED");
        expect(confirmed.run.status).toBe("passed");
        return { costUsd: 0.01, facts: [{ status: exploit.status, assetIds: [asset.id], summary: "cross-tenant read" }] };
      },
    };

    const reports = new ReportService(config, store, evidence, events);
    const engine = new AuditEngine(config, store, null as any, evidence, events, reports);
    engine.setDynamicExecutor(executor);

    await engine.runExplorationStep("a1");

    // Dynamic reverification now runs as a claimed phase-5 task so a slow
    // target cannot stall the scheduler tick. Drive the scheduler directly
    // instead of waiting on its 1.5 s clock.
    await engine.runScheduledForTest("a1");

    const candidate = store.get<{ status: string; provenance: string; finding_id: string }>(
      "SELECT status, provenance, finding_id FROM candidates WHERE audit_id = 'a1'",
    )!;
    expect(candidate.status).toBe("confirmed");
    expect(candidate.provenance).toBe("dynamic");
    const finding = store.get<{ id: string; status: string; code: string; files: string }>(
      "SELECT id, status, code, files FROM findings WHERE audit_id = 'a1'",
    )!;
    expect(finding.status).toBe("reverified");
    expect(
      store.get<{ verdict: string }>(
        "SELECT verdict FROM verifications WHERE finding_id = ? AND kind = 'reverification'",
        finding.id,
      ),
    ).toEqual({ verdict: "REVERIFIED" });
    expect(finding.code).toBe("DYN-001");
    expect(JSON.parse(finding.files)).toEqual([{ path: "src/routes/invoices.js", start_line: 12, end_line: 13 }]);
    expect(
      store.get<{ count: number }>("SELECT COUNT(*) AS count FROM evidence WHERE finding_id = ?", finding.id)!.count,
    ).toBe(5);
    expect(exchanges.length).toBe(4);
    expect(graph.coverage("a1").find((entry) => entry.assetId === asset.id)?.tested).toBe(true);

    if (!usingFixture) fixed = true;
    const retests = new RetestService(store, async () => {
      const positive = await proxyRequest(brokerPort, `${baseUrl}/api/invoices/inv-1`, identityB.id);
      const exploit = await proxyRequest(brokerPort, `${baseUrl}/api/invoices/inv-1`, identityA.id);
      return {
        positivePassed: positive.status === 200,
        exploitPassed: exploit.status === 200,
        evidenceRefs: [finding.id],
      };
    });
    const retestId = retests.request({
      findingId: finding.id,
      auditId: "a1",
      reason: "ownership check added",
      authorizationSnapshot: JSON.stringify({
        id: snapshot.authorization.id,
        authorized_by: snapshot.authorization.authorized_by,
        reference: snapshot.authorization.reference,
        valid_from: snapshot.authorization.valid_from,
        valid_until: snapshot.authorization.valid_until,
      }),
      environmentManifest: JSON.stringify({ target: baseUrl, commit_sha: "abc123" }),
      environmentMatch: true,
    });
    const expectedVerdict = usingFixture ? "still_reproducible" : "fixed";
    expect(await retests.run(retestId)).toBe(expectedVerdict);
    expect(store.get<{ verdict: string }>("SELECT verdict FROM retests WHERE id = ?", retestId)).toEqual({
      verdict: expectedVerdict,
    });

    const generated = await reports.generate("a1", ["markdown", "json"], "test");
    const markdown = readFileSync(generated.find((entry) => entry.format === "markdown")!.path, "utf8");
    const json = readFileSync(generated.find((entry) => entry.format === "json")!.path, "utf8");
    expect(markdown).toContain("DYN-001");
    expect(markdown).toContain("Dynamic evidence");
    expect(markdown).toContain("positive check: HTTP 200");
    expect(markdown).toContain("exploit check: HTTP 200");
    expect(markdown).toContain("negative check: HTTP 404");
    expect(json).toContain('"dynamic_evidence"');
    expect(json).toContain('"status": "passed"');
  }, 20_000);
});
