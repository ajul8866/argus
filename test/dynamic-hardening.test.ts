import { afterEach, describe, expect, test } from "bun:test";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { Store } from "../src/db/index.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { EventLog } from "../src/events.ts";
import { ReportService } from "../src/reports/generator.ts";
import { AuditEngine } from "../src/orchestrator/engine.ts";
import { GraphStore } from "../src/dynamic/graph.ts";
import { DynamicProofService } from "../src/dynamic/proof.ts";
import { BrokerServer } from "../src/dynamic/broker.ts";
import { requestThroughBroker } from "../src/dynamic/http.ts";
import { runPocChecks } from "../src/dynamic/executor.ts";
import { CredentialBroker } from "../src/dynamic/credentials.ts";
import { RetestService } from "../src/dynamic/retest.ts";
import { encryptSecret } from "../src/security/credentials.ts";
import { now, sha256 } from "../src/util.ts";
import type { EgressPolicy } from "../src/dynamic/egress.ts";
import type { PocExchange, PocManifest } from "../src/dynamic/poc.ts";

type Runtime = { dir: string; config: any; store: Store; evidence: EvidenceStore; events: EventLog };
const servers: Server[] = [];
const runtimes: Runtime[] = [];

function runtime(): Runtime {
  const dir = mkdtempSync(join(tmpdir(), "argus-hardening-"));
  const config = { dataDir: dir, chromeBin: "/missing/chrome" } as any;
  const store = new Store(config, "test.sqlite");
  const evidence = new EvidenceStore(config, store);
  const events = new EventLog(store);
  const value = { dir, config, store, evidence, events };
  runtimes.push(value);
  return value;
}

function listen(handler: Parameters<typeof createServer>[1]): Promise<{ port: number; server: Server }> {
  const server = createServer(handler);
  servers.push(server);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ port: (server.address() as { port: number }).port, server })));
}

function policy(port: number): EgressPolicy {
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    allowedHosts: ["127.0.0.1"],
    allowedCidrs: ["127.0.0.1/32"],
    allowedMethods: ["GET"],
    maxRps: 100,
    tls: false,
  };
}

function seedScope(rt: Runtime, port: number, identities: string[], authStatus = "active"): { manifest: PocManifest; assetId: string; findingId: string } {
  const { store } = rt;
  store.run("INSERT INTO projects (id,name,source_path,scope_include,scope_exclude,authorized_by,authorization_ref,created_at,updated_at) VALUES ('p','P','/tmp','**/*','','T','A',?,?)", now(), now());
  store.run("INSERT INTO project_targets (id,project_id,label,base_url,environment,repository_id,allowed_hosts,allowed_cidrs,allowed_methods,max_rps,tls_required,status,created_by,created_at,updated_at) VALUES ('t','p','T',?,'test',NULL,'[\"127.0.0.1\"]','[\"127.0.0.1/32\"]','[\"GET\"]',100,0,'active',NULL,?,?)", `http://127.0.0.1:${port}`, now(), now());
  store.run("INSERT INTO target_authorizations (id,target_id,authorized_by,authorization_ref,valid_from,valid_until,authorized_actions,restrictions,status,created_by,created_at) VALUES ('auth','t','T','A',?,?,'{}','{}',?,NULL,?)", new Date(Date.now() - 86_400_000).toISOString(), new Date(Date.now() + 86_400_000).toISOString(), authStatus, now());
  store.run("INSERT INTO audits (id,project_id,repository_id,status,current_phase,config,mode,created_at) VALUES ('a','p',NULL,'running',3,'{}','dynamic',?)", now());
  for (const [id, ref, value] of [["ida", "ALICE", "alice-token"], ["idb", "BOB", "bob-token"]] as const) {
    const enc = encryptSecret(rt.config, value);
    store.run("INSERT INTO provider_credentials (id,provider,env_var,ciphertext,iv,tag,last4,created_at,updated_at) VALUES (?,'test-identity',?,?,?,?,?,?,?)", `c-${id}`, ref, enc.ciphertext, enc.iv, enc.tag, enc.last4, now(), now());
    store.run("INSERT INTO test_identities (id,target_id,label,role,auth_kind,secret_ref,status,created_at,updated_at) VALUES (?,'t',?,'role','header',?,'active',?,?)", id, id, ref, now(), now());
  }
  const snapshot = {
    mode: "dynamic",
    target: { id: "t", base_url: `http://127.0.0.1:${port}`, allowed_hosts: ["127.0.0.1"], allowed_cidrs: ["127.0.0.1/32"], allowed_methods: ["GET"], max_rps: 100, tls: false },
    authorization: { id: "auth", authorized_by: "T", reference: "A", valid_from: new Date(Date.now() - 86_400_000).toISOString(), valid_until: new Date(Date.now() + 86_400_000).toISOString(), authorized_actions: {}, restrictions: {} },
    identities: identities.map((id) => ({ id, role: "role" })),
    permissions: [],
    budget: { max_usd: 1, exploration_cap_usd: 1, verification_reserve_usd: 0, max_tasks: 10, max_requests: 10, max_runtime_minutes: 1 },
    repository: null,
    created_by: null,
    created_at: now(),
  };
  store.run("INSERT INTO audit_scope_snapshots (audit_id,created_at,snapshot,sha256) VALUES ('a',?,?,?)", now(), JSON.stringify(snapshot), sha256(JSON.stringify(snapshot)));
  const assetId = new GraphStore(store).upsertAsset({ projectId: "p", kind: "app", assetKey: `http://127.0.0.1:${port}` }).id;
  const manifest: PocManifest = {
    language: "ts",
    script_evidence_id: "s",
    object: { asset_id: assetId, object_id: "inv-1", owner_identity: "ida" },
    checks: {
      positive: { identity: "ida", request: { method: "GET", path: "/invoices/inv-1" }, expect: { status: 200 } },
      exploit: { identity: "idb", request: { method: "GET", path: "/invoices/inv-1" }, expect: { status: 200 } },
      negative: { identity: "idb", request: { method: "GET", path: "/invoices/inv-2" }, expect: { status: 403 } },
    },
    environment: { target: `http://127.0.0.1:${port}`, identities: ["ida", "idb"] },
  };
  return { manifest, assetId, findingId: "f1" };
}

afterEach(() => {
  for (const server of servers.splice(0)) server.close();
  for (const rt of runtimes.splice(0)) {
    rt.store.close();
    rmSync(rt.dir, { recursive: true, force: true });
  }
});

describe("dynamic transport hardening", () => {
  test("an encoded target response is decoded instead of stored as mojibake", async () => {
    const { port } = await listen((request, response) => {
      const body = JSON.stringify({ marker: "gzip-visible", encoded: String(request.headers["accept-encoding"] ?? "") });
      if (String(request.headers["accept-encoding"] ?? "").includes("gzip")) {
        response.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" }).end(gzipSync(body));
      } else {
        response.writeHead(200, { "content-type": "application/json" }).end(body);
      }
    });
    const broker = new BrokerServer({ policy: policy(port) });
    const brokerPort = (await broker.start()).port;
    try {
      const result = await requestThroughBroker(brokerPort, `http://127.0.0.1:${port}/x`, "GET", null);
      expect(result.status).toBe(200);
      expect(JSON.parse(result.body).marker).toBe("gzip-visible");
      expect(result.brokerError).toBeUndefined();
    } finally {
      await broker.stop();
    }
  });

  test("a broker rejection is distinguishable from a target response", async () => {
    const { port } = await listen((_request, response) => response.writeHead(200).end("target"));
    const broker = new BrokerServer({ policy: { ...policy(port), allowedMethods: ["GET"] } });
    const brokerPort = (await broker.start()).port;
    try {
      const result = await requestThroughBroker(brokerPort, `http://127.0.0.1:${port}/x`, "DELETE", null);
      expect(result.status).toBe(403);
      expect(result.brokerError).toBeTruthy();
    } finally {
      await broker.stop();
    }
  });
});

describe("dynamic authorization and identity binding", () => {
  test("a revoked authorization blocks every replay request", async () => {
    let requests = 0;
    const { port } = await listen((_request, response) => { requests += 1; response.writeHead(200).end("{}"); });
    const rt = runtime();
    const { manifest } = seedScope(rt, port, ["ida", "idb"], "revoked");
    await expect(runPocChecks(rt.config, rt.store, "a", manifest)).rejects.toThrow(/authorization/);
    expect(requests).toBe(0);
  });

  test("a manifest cannot name an identity from another audit scope", async () => {
    const { port } = await listen((_request, response) => response.writeHead(200).end("{}"));
    const rt = runtime();
    const { manifest } = seedScope(rt, port, ["ida"]);
    await expect(runPocChecks(rt.config, rt.store, "a", manifest)).rejects.toThrow(/not part of this audit scope/);
  });

  test("the credential broker refuses an identity owned by another target", () => {
    const rt = runtime();
    rt.store.run("INSERT INTO projects (id,name,source_path,scope_include,scope_exclude,authorized_by,authorization_ref,created_at,updated_at) VALUES ('p2','P2','/tmp','**/*','','T','A',?,?)", now(), now());
    rt.store.run("INSERT INTO project_targets (id,project_id,label,base_url,environment,repository_id,allowed_hosts,allowed_cidrs,allowed_methods,max_rps,tls_required,status,created_by,created_at,updated_at) VALUES ('t2','p2','T2','http://other.test','test',NULL,'[\"other.test\"]','[]','[\"GET\"]',10,1,'active',NULL,?,?)", now(), now());
    rt.store.run("INSERT INTO test_identities (id,target_id,label,role,auth_kind,secret_ref,status,created_at,updated_at) VALUES ('foreign','t2','foreign','role','none',NULL,'active',?,?)", now(), now());
    const broker = new CredentialBroker(rt.config, rt.store);
    expect(() => broker.inject("foreign", "t")).toThrow(/another target/);
  });
});

describe("dynamic evidence and verdict hardening", () => {
  test("confirmation is serialized across service instances", async () => {
    const { port } = await listen((_request, response) => response.writeHead(200).end("{}"));
    const rt = runtime();
    const { manifest, assetId } = seedScope(rt, port, ["ida", "idb"]);
    const pass: Record<"positive" | "exploit" | "negative", PocExchange> = {
      positive: { status: 200, body: "ok" }, exploit: { status: 200, body: "leak" }, negative: { status: 403, body: "no" },
    };
    const make = () => new DynamicProofService(rt.store, rt.evidence, async () => ({ ...pass }));
    const first = make();
    const second = make();
    const proposed = await first.propose({ auditId: "a", assetId, title: "IDOR", category: "idor", severity: "high", manifest, script: "poc", proposedBy: "worker" });
    const results = await Promise.allSettled([
      first.confirm(proposed.candidateId, "validator-1"),
      second.confirm(proposed.candidateId, "validator-2"),
    ]);
    expect(results.filter((entry) => entry.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((entry) => entry.status === "rejected")).toHaveLength(1);
    expect(rt.store.all("SELECT id FROM findings WHERE audit_id = 'a'")).toHaveLength(1);
  });

  test("known credentials are redacted from stored evidence but kept for checks", async () => {
    const { port } = await listen((request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ echoed: String(request.headers.authorization ?? "") }));
    });
    const rt = runtime();
    const { manifest } = seedScope(rt, port, ["ida", "idb"]);
    manifest.checks.positive.expect = { status: 200, body_contains: "echoed" };
    const exchanges = await runPocChecks(rt.config, rt.store, "a", manifest);
    expect(exchanges.positive.body).toContain("alice-token");
    expect(exchanges.positive.evidenceBody).not.toContain("alice-token");
    expect(exchanges.exploit.evidenceBody).not.toContain("bob-token");
  });


  test("a manifest containing a known identity secret is rejected", async () => {
    let requests = 0;
    const { port } = await listen((_request, response) => { requests += 1; response.writeHead(200).end("{}"); });
    const rt = runtime();
    const { manifest } = seedScope(rt, port, ["ida", "idb"]);
    manifest.checks.positive.expect = { status: 200, body_contains: "alice-token" };
    await expect(runPocChecks(rt.config, rt.store, "a", manifest)).rejects.toThrow(/manifest contains an identity secret/);
    expect(requests).toBe(0);
  });

  test("the JSON report omits PoC manifest request text", async () => {
    const { port } = await listen((_request, response) => response.writeHead(200).end("{}"));
    const rt = runtime();
    const { manifest, assetId } = seedScope(rt, port, ["ida", "idb"]);
    rt.store.run(`INSERT INTO findings (id,code,audit_id,project_id,candidate_id,title,category,cwe,severity,status,repository_commit,files,root_cause,preconditions,reproduction,expected,observed,impact,remediation,created_at,updated_at)
      VALUES ('f1','DYN-001','a','p',NULL,'IDOR','idor',NULL,'high','confirmed',NULL,'[]','r','[]','[]','e','o','i','rem',?,?)`, now(), now());
    await rt.evidence.append({
      auditId: "a", findingId: "f1", kind: "dynamic_proof", title: "proof",
      content: {
        manifest: { ...manifest, object: { ...manifest.object, asset_id: assetId } },
        result: { status: "passed", positive: true, exploit: true, negative: true },
        exchanges: { positive: { status: 200 }, exploit: { status: 200 }, negative: { status: 403 } },
      },
    });
    const reports = new ReportService(rt.config, rt.store, rt.evidence, rt.events);
    const generated = await reports.generate("a", ["json"], "test");
    const text = readFileSync(generated[0]!.path, "utf8");
    expect(text).toContain("inv-1");
    expect(text).not.toContain("alice-token");
    expect(text).not.toContain("body_contains");
  });

  test("a broker transport failure during a retest is not reported as fixed", async () => {
    let mode: "destroy" | "deny" = "destroy";
    const { port } = await listen((request, response) => {
      if (String(request.headers.authorization) === "Bearer alice-token") {
        response.writeHead(200, { "content-type": "application/json" }).end('{"id":"inv-1"}');
        return;
      }
      if (mode === "destroy") {
        request.socket.destroy();
        return;
      }
      response.writeHead(403).end("{}");
    });
    const rt = runtime();
    const { manifest } = seedScope(rt, port, ["ida", "idb"]);
    rt.store.run(`INSERT INTO findings (id,code,audit_id,project_id,candidate_id,title,category,cwe,severity,status,repository_commit,files,root_cause,preconditions,reproduction,expected,observed,impact,remediation,created_at,updated_at)
      VALUES ('f1','DYN-001','a','p',NULL,'IDOR','idor',NULL,'high','confirmed',NULL,'[]','r','[]','[]','e','o','i','rem',?,?)`, now(), now());
    await rt.evidence.append({ auditId: "a", findingId: "f1", kind: "dynamic_proof", title: "proof", content: { manifest } });
    const reports = new ReportService(rt.config, rt.store, rt.evidence, rt.events);
    const engine = new AuditEngine(rt.config, rt.store, null as any, rt.evidence, rt.events, reports);
    const executor = (input: { findingId: string; auditId: string }) =>
      (engine as any).replayPocForRetest(input.findingId, input.auditId);
    const service = new RetestService(rt.store, executor);
    const request = () => service.request({
      findingId: "f1",
      auditId: "a",
      reason: "test",
      authorizationSnapshot: JSON.stringify({ id: "auth", authorized_by: "T", reference: "A", valid_from: new Date(Date.now() - 1000).toISOString(), valid_until: new Date(Date.now() + 86_400_000).toISOString() }),
      environmentManifest: JSON.stringify({ target: `http://127.0.0.1:${port}` }),
      environmentMatch: true,
    });
    expect(await service.run(request())).toBe("cannot_confirm");
    mode = "deny";
    expect(await service.run(request())).toBe("fixed");
  });
});
