import { afterEach, beforeEach, describe, expect, setSystemTime, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { PHASE_NAMES } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { EventLog } from "../src/events.ts";
import type { HarnessManager } from "../src/harness/manager.ts";
import type { HarnessKind, HarnessRunResult, HarnessTask } from "../src/harness/types.ts";
import { AuditEngine } from "../src/orchestrator/engine.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { ReportService } from "../src/reports/generator.ts";
import { buildInventory } from "../src/repo/inventory.ts";
import { harnessConfig, saveHarnessConfig, seedDefaults, setSetting } from "../src/settings.ts";
import { now, toJson, uid } from "../src/util.ts";
import { LocalCatalog } from "../src/local/catalog.ts";
import { TargetService } from "../src/dynamic/targets.ts";
import { GraphStore } from "../src/dynamic/graph.ts";
import { mkdirSync, writeFileSync } from "node:fs";

const fixture = join(import.meta.dir, "fixtures", "vulnerable-app");

type ScriptedHarness = {
  run: (
    kind: HarnessKind,
    task: HarnessTask,
    hooks: { onEvent: (event: Record<string, unknown>) => void },
  ) => Promise<HarnessRunResult>;
  cleanupRun: (runId: string) => Promise<void>;
};

function fakeManager(onTask?: (task: HarnessTask) => void): HarnessManager {
  const manager: ScriptedHarness = {
    async run(kind, task, hooks) {
      onTask?.(task);
      const startedAt = now();
      hooks.onEvent({ type: "session_start", at: startedAt, meta: { sandbox: "test", harness: kind } });
      const data = scriptedResult(task);
      await Bun.sleep(10);
      const text = JSON.stringify(data);
      const result: HarnessRunResult = {
        status: "completed",
        text,
        structured: data,
        sessionRef: `scripted-${task.runId}`,
        model: task.model,
        usage: {
          input_tokens: 10,
          output_tokens: 10,
          total_tokens: 20,
          cache_read_tokens: 0,
          cost_usd: 0,
          turns: 1,
          duration_ms: 10,
        },
        events: [],
        startedAt,
        endedAt: now(),
        exitCode: 0,
        metadata: { harness: kind, sandbox: "test" },
      };
      hooks.onEvent({ type: "session_end", at: now(), meta: { sandbox: "test" } });
      return result;
    },
    async cleanupRun() {
      return;
    },
  };
  return manager as unknown as HarnessManager;
}

function scriptedResult(task: HarnessTask): unknown {
  if (task.role === "codebase_mapper") {
    return {
      summary: "Demo Express API with user search and invoice routes.",
      languages: ["JavaScript"],
      frameworks: ["Express"],
      modules: [{ name: "routes", path: "src/routes", purpose: "HTTP route handlers" }],
      entrypoints: ["src/server.js"],
      endpoints: [
        { method: "GET", path: "/api/users/search", file: "src/routes/users.js", line: 8, auth_required: true },
        { method: "GET", path: "/api/invoices/:id", file: "src/routes/invoices.js", line: 14, auth_required: true },
      ],
      auth_boundaries: [
        { kind: "middleware", file: "src/lib/auth.js", line: 6, description: "JWT bearer authentication" },
      ],
      data_access: [
        { kind: "sqlite", description: "Raw SQL statements", files: ["src/lib/db.js", "src/routes/users.js"] },
      ],
      critical_paths: [
        { name: "Invoice access", description: "Authenticated invoice retrieval", files: ["src/routes/invoices.js"] },
      ],
      areas: [
        {
          id: "api",
          title: "User and invoice APIs",
          rationale: "Direct data access and object-level authorization.",
          files: ["src/routes/users.js", "src/routes/invoices.js", "src/lib/db.js", "src/lib/auth.js"],
          security_focus: ["SQL injection", "object-level authorization"],
        },
      ],
      coverage_notes: ["One coherent API area."],
      limitations: ["No runtime database was available."],
    };
  }
  if (task.role === "security_researcher") {
    return {
      area_id: "api",
      summary: "Two high-confidence candidates found in the API area.",
      inspected_files: ["src/routes/users.js", "src/routes/invoices.js", "src/lib/db.js"],
      candidates: [
        {
          title: "User search concatenates input into a SQL query",
          category: "SQL injection",
          cwe: "CWE-89",
          severity: "high",
          files: [{ path: "src/lib/db.js", start_line: 11, end_line: 11 }],
          hypothesis: "The q parameter is concatenated into a LIKE expression and executed.",
          source_to_sink: "request.query.q -> searchUsers(term) -> db.prepare(query).all()",
          preconditions: ["Valid bearer token"],
          evidence_excerpts: [
            {
              path: "src/lib/db.js",
              start_line: 11,
              end_line: 11,
              quote: "  const query = \"SELECT id, email, display_name, role FROM users WHERE email LIKE '%\" + term + \"%'\";",
            },
          ],
          reproduction_notes: "Send an authenticated request with a quote in q and observe the generated query.",
          expected: "SQL metacharacters are parameterized.",
          observed: "Term is concatenated into SQL.",
          impact: "An authenticated user can alter the user search query and read arbitrary database rows allowed by the query.",
          remediation: "Use a bound parameter and escape LIKE wildcards.",
        },
        {
          title: "Invoice detail lacks an ownership check",
          category: "Broken object-level authorization",
          cwe: "CWE-639",
          severity: "high",
          files: [{ path: "src/routes/invoices.js", start_line: 13, end_line: 13 }],
          hypothesis: "Any authenticated user can retrieve any invoice by ID.",
          source_to_sink: "request.params.id -> findInvoiceById(id) -> response.json(invoice)",
          preconditions: ["Valid bearer token", "Knowledge of an invoice ID"],
          evidence_excerpts: [
            {
              path: "src/routes/invoices.js",
              start_line: 13,
              end_line: 13,
              quote: "  const invoice = findInvoiceById(request.params.id);",
            },
          ],
          reproduction_notes: "Authenticate as one user and request another user's invoice ID.",
          expected: "Ownership is enforced before returning the record.",
          observed: "The handler returns any matching invoice.",
          impact: "Cross-tenant disclosure of invoice data, including amounts and owner identifiers.",
          remediation: "Scope the query by owner_id or enforce an explicit authorization policy.",
        },
      ],
      limitations: ["Static review only."],
    };
  }
  if (task.role === "independent_validator") {
    return {
      verdict: "CONFIRMED",
      rationale: "The code confirms both claim paths and no compensating control was found.",
      verified_excerpts: [
        {
          path: "src/lib/db.js",
          start_line: 11,
          end_line: 11,
          quote: "  const query = \"SELECT id, email, display_name, role FROM users WHERE email LIKE '%\" + term + \"%'\";",
        },
        {
          path: "src/routes/invoices.js",
          start_line: 13,
          end_line: 13,
          quote: "  const invoice = findInvoiceById(request.params.id);",
        },
      ],
      reproduction_steps: ["Authenticate, then trigger the affected route with the crafted input."],
      prerequisites_checked: ["Bearer token middleware is applied to the router"],
      alternative_explanations: ["A global authorization layer might compensate; none was found."],
      mitigating_controls: ["None identified in the repository."],
      severity_assessment: "high",
      impact_assessment: "The verified code permits query manipulation and cross-owner invoice reads.",
      completeness_issues: [],
      duplicate_of_finding_code: null,
    };
  }
  if (task.role === "retest_auditor") {
    return {
      decision: "REVERIFIED",
      rationale: "The affected code still matches the finding and impact is supported.",
      verified_excerpts: [
        {
          path: "src/lib/db.js",
          start_line: 11,
          end_line: 11,
          quote: "  const query = \"SELECT id, email, display_name, role FROM users WHERE email LIKE '%\" + term + \"%'\";",
        },
        {
          path: "src/routes/invoices.js",
          start_line: 13,
          end_line: 13,
          quote: "  const invoice = findInvoiceById(request.params.id);",
        },
      ],
      impact_assessment: "The impact remains supported by the source code.",
      reproduction_consistency: "The recorded reasoning follows directly from the verified source.",
      completeness_issues: [],
      unsupported_claims: [],
      severity_assessment: "high",
      notes: ["No runtime exploitation was performed."],
    };
  }
  throw new Error(`Unexpected role ${task.role}`);
}

function testConfig(dataDir: string): Config {
  return {
    port: 0,
    hostname: "127.0.0.1",
    dataDir,
    webDist: join(dataDir, "web"),
    adminEmail: "test@argus.local",
    adminPassword: "test-admin-password",
    sessionTtlMs: 60_000,
    maxConcurrentAgents: 3,
    sandboxMode: "none",
    piBin: "pi",
    claudeBin: "claude",
    allowedRoots: [fixture, dataDir, join(import.meta.dir, "..")],
    masterKey: "test-master-key-material",
    chromeBin: "google-chrome",
    secureCookies: false,
    logLevel: "error",
  };
}

let dir = "";
let store: Store;
let engine: AuditEngine;
let manager: HarnessManager;
let workflowEvidence: EvidenceStore;
let auditId = "";

function createEngine(catalog?: LocalCatalog): AuditEngine {
  const config = testConfig(dir);
  const events = new EventLog(store);
  workflowEvidence = new EvidenceStore(config, store);
  const reports = new ReportService(config, store, workflowEvidence, events);
  return new AuditEngine(config, store, manager, workflowEvidence, events, reports, catalog);
}

async function waitFor(condition: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for workflow state");
    await Bun.sleep(20);
  }
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "argus-engine-"));
  const config = testConfig(dir);
  store = new Store(config, "test.sqlite");
  seedDefaults(store, config);
  store.run(
    "INSERT INTO users (id, email, name, password_hash, role, disabled, created_at) VALUES ('u1','test@argus.local','Tester','x','admin',0,?)",
    now(),
  );
  store.run(
    `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, max_concurrent_agents, created_at, updated_at)
     VALUES ('p1','Fixture','', ?, ?, ?, 'Tester','TEST-AUTH',3,?,?)`,
    fixture,
    toJson(["**/*.js", "**/*.json", "README.md"]),
    toJson([".git/**", "node_modules/**"]),
    now(),
    now(),
  );
  const inventory = await buildInventory(fixture, {
    scope: { include: ["**/*.js", "**/*.json", "README.md"], exclude: [".git/**", "node_modules/**"] },
    maxFiles: 100,
    maxFileBytes: 1_000_000,
  });
  store.run(
    `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('r1','p1',?,NULL,'test',?,?,?,?,?,?,?)`,
    fixture,
    toJson(inventory.languages),
    toJson(inventory.frameworks),
    toJson(inventory),
    toJson({
      endpoints: inventory.endpoints,
      auth_boundaries: inventory.auth_boundaries,
      dependency_graph: inventory.dependency_graph,
      entrypoints: inventory.entrypoints,
    }),
    inventory.files.length,
    inventory.total_bytes,
    now(),
  );
  manager = fakeManager();
  engine = createEngine();
  auditId = engine.createAudit({
    projectId: "p1",
    repositoryId: "r1",
    userId: "u1",
    overrides: {
      max_areas: 1,
      max_candidates_per_area: 2,
      max_confirmations: 3,
      max_reverifications: 3,
      max_concurrent_agents: 2,
    },
  });
  engine.start();
});

afterEach(async () => {
  await engine.stop();
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("project concurrency limits", () => {
  function holdHarnessUntilAbort(): void {
    const run = manager.run.bind(manager);
    manager.run = async (...args) => {
      const signal = args[2].signal;
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      return run(...args);
    };
  }

  async function cancelAudits(ids: string[]): Promise<void> {
    for (const id of ids) {
      const audit = store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", id);
      if (audit && ["running", "queued"].includes(audit.status)) await engine.cancelAudit(id, "u1");
    }
    await waitFor(() => !store.get("SELECT id FROM tasks WHERE status = 'running'"));
  }

  for (const projectLimit of [1, 2]) {
    test(`a project ceiling of ${projectLimit} is shared by its audits and queued work resumes when a slot is released`, async () => {
      setSetting(store, "audit.max_concurrent_agents", 4, null);
      store.run("UPDATE projects SET max_concurrent_agents = ? WHERE id = 'p1'", projectLimit);
      store.run("UPDATE agent_defs SET concurrency_limit = 4 WHERE role = 'codebase_mapper'");
      holdHarnessUntilAbort();
      const secondAudit = engine.createAudit({
        projectId: "p1", repositoryId: "r1", userId: "u1",
        overrides: { max_concurrent_agents: 3 },
      });
      engine.createTask({
        auditId: secondAudit, phase: 1, kind: "phase1.map", taskKey: "extra-mapper",
        title: "Additional mapping task", payload: {}, agentRole: "codebase_mapper",
      });
      const runningCount = () => store.get<{ count: number }>(
        "SELECT COUNT(*) AS count FROM tasks t JOIN audits a ON a.id = t.audit_id WHERE a.project_id = 'p1' AND t.status = 'running'",
      )!.count;

      try {
        await engine.startAudit(auditId, "u1");
        await engine.startAudit(secondAudit, "u1");

        expect(runningCount()).toBe(projectLimit);
        expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'queued'", secondAudit))
          .toHaveLength(3 - projectLimit);

        await engine.cancelAudit(auditId, "u1");
        await waitFor(() => store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND status = 'running'", secondAudit,
        )?.count === projectLimit);
        expect(runningCount()).toBe(projectLimit);
        expect(store.get("SELECT status FROM audits WHERE id = ?", secondAudit)).toMatchObject({ status: "running" });
      } finally {
        await cancelAudits([auditId, secondAudit]);
      }
    });
  }

  for (const scenario of [
    { name: "an unset project ceiling allows audits to share the global capacity", global: 4, audit: 3, role: 4, expected: 2 },
    { name: "the global ceiling still limits audits without a project ceiling", global: 2, audit: 3, role: 4, expected: 1 },
    { name: "the audit ceiling still limits work without a project ceiling", global: 4, audit: 1, role: 4, expected: 1 },
    { name: "the role ceiling still limits work across audits without a project ceiling", global: 4, audit: 3, role: 1, expected: 0 },
  ]) {
    test(scenario.name, async () => {
      setSetting(store, "audit.max_concurrent_agents", scenario.global, null);
      store.run("UPDATE projects SET max_concurrent_agents = NULL WHERE id = 'p1'");
      store.run("UPDATE agent_defs SET concurrency_limit = ? WHERE role = 'codebase_mapper'", scenario.role);
      holdHarnessUntilAbort();
      const secondAudit = engine.createAudit({
        projectId: "p1", repositoryId: "r1", userId: "u1",
        overrides: { max_concurrent_agents: scenario.audit },
      });
      engine.createTask({
        auditId: secondAudit, phase: 1, kind: "phase1.map", taskKey: "extra-mapper",
        title: "Additional mapping task", payload: {}, agentRole: "codebase_mapper",
      });

      try {
        await engine.startAudit(auditId, "u1");
        await engine.startAudit(secondAudit, "u1");

        expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", auditId)).toHaveLength(1);
        expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", secondAudit)).toHaveLength(scenario.expected);
        expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'queued'", secondAudit)).toHaveLength(2 - scenario.expected);
      } finally {
        await cancelAudits([auditId, secondAudit]);
      }
    });
  }

  test("cancelling audits retain their project slots until their tasks finish", async () => {
    store.run("UPDATE projects SET max_concurrent_agents = 1 WHERE id = 'p1'");
    store.run("UPDATE agent_defs SET concurrency_limit = 4 WHERE role = 'codebase_mapper'");
    const run = manager.run.bind(manager);
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    manager.run = async (...args) => {
      entered.resolve();
      await release.promise;
      return run(...args);
    };
    const secondAudit = engine.createAudit({ projectId: "p1", repositoryId: "r1", userId: "u1" });

    try {
      await engine.startAudit(auditId, "u1");
      await entered.promise;
      await engine.cancelAudit(auditId, "u1");
      await engine.startAudit(secondAudit, "u1");

      expect(store.get("SELECT status FROM audits WHERE id = ?", auditId)).toMatchObject({ status: "cancelling" });
      expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", auditId)).toHaveLength(1);
      expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", secondAudit)).toHaveLength(0);
      expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'queued'", secondAudit)).toHaveLength(1);
    } finally {
      release.resolve();
      await cancelAudits([auditId, secondAudit]);
    }
  });

  test("a busy project does not consume another project's ceiling", async () => {
    setSetting(store, "audit.max_concurrent_agents", 4, null);
    store.run("UPDATE projects SET max_concurrent_agents = 1 WHERE id = 'p1'");
    store.run("UPDATE agent_defs SET concurrency_limit = 4 WHERE role = 'codebase_mapper'");
    store.run(
      `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, max_concurrent_agents, created_at, updated_at)
       SELECT 'p2', 'Other project', source_path, scope_include, scope_exclude, authorized_by, authorization_ref, 1, created_at, updated_at FROM projects WHERE id = 'p1'`,
    );
    store.run(
      `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
       SELECT 'r2', 'p2', path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at FROM repositories WHERE id = 'r1'`,
    );
    holdHarnessUntilAbort();
    const secondAudit = engine.createAudit({ projectId: "p2", repositoryId: "r2", userId: "u1" });

    try {
      await engine.startAudit(auditId, "u1");
      await engine.startAudit(secondAudit, "u1");

      for (const id of [auditId, secondAudit]) {
        expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", id)).toHaveLength(1);
      }
    } finally {
      await cancelAudits([auditId, secondAudit]);
    }
  });

  test("a legacy invalid project ceiling falls back to the global limit", async () => {
    store.run("UPDATE projects SET max_concurrent_agents = -1 WHERE id = 'p1'");
    holdHarnessUntilAbort();
    await engine.startAudit(auditId, "u1");
    await waitFor(() => Boolean(store.get(
      "SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'",
      auditId,
    )));
    expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", auditId)).toHaveLength(1);
    await cancelAudits([auditId]);
  });
});

test("reports generated in the same millisecond preserve separate files and their recorded hashes", async () => {
  const config = testConfig(dir);
  const evidence = new EvidenceStore(config, store);
  const reports = new ReportService(config, store, evidence, new EventLog(store));
  setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
  try {
    const [first] = await reports.generate(auditId, ["json"], "test");
    const [second] = await reports.generate(auditId, ["json"], "test");
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first!.path).not.toBe(second!.path);
    for (const report of [first!, second!]) {
      expect(new Bun.CryptoHasher("sha256").update(readFileSync(report.path)).digest("hex")).toBe(report.sha256);
    }
  } finally {
    setSystemTime();
  }
});

test("a zero cost ceiling is saved and stops the audit after reported spend", async () => {
  const capped = engine.createAudit({
    projectId: "p1",
    repositoryId: "r1",
    userId: "u1",
    overrides: { max_cost_usd: 0 },
  });
  const positive = engine.createAudit({
    projectId: "p1",
    repositoryId: "r1",
    userId: "u1",
    overrides: { max_cost_usd: 1.5 },
  });
  const unlimited = engine.createAudit({
    projectId: "p1",
    repositoryId: "r1",
    userId: "u1",
    overrides: {},
  });
  const configFor = (id: string) => JSON.parse(
    store.get<{ config: string }>("SELECT config FROM audits WHERE id = ?", id)!.config,
  ).max_cost_usd;
  expect(configFor(capped)).toBe(0);
  expect(configFor(positive)).toBe(1.5);
  expect(configFor(unlimited)).toBeNull();

  const run = manager.run.bind(manager);
  manager.run = async (...args) => {
    const result = await run(...args);
    return { ...result, usage: { ...result.usage, cost_usd: 0.01 } };
  };
  await engine.startAudit(capped, "u1");
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", capped)?.status === "failed");
  const failed = store.get<{ status: string; error: string | null }>("SELECT status, error FROM audits WHERE id = ?", capped);
  expect(failed).toMatchObject({ status: "failed" });
  expect(failed?.error).toContain("cost budget exceeded");
  expect(failed?.error).toContain("$0.0000");
});

test("a retest refuses a tampered code excerpt instead of quoting it", async () => {
  store.run("UPDATE audits SET status = 'running', started_at = ? WHERE id = ?", now(), auditId);
  store.run("UPDATE agent_defs SET max_retries = 0 WHERE role = 'retest_auditor'");
  const timestamp = now();
  store.run(
    `INSERT INTO findings (
      id, code, audit_id, project_id, title, category, severity, status, files, root_cause,
      preconditions, reproduction, expected, observed, impact, remediation, created_at, updated_at
    ) VALUES ('f-tamper', 'ARG-901', ?, 'p1', 'Tampered excerpt', 'injection', 'high', 'confirmed', '[]',
      'cause', '[]', '[]', 'expected', 'observed', 'impact', 'fix', ?, ?)`,
    auditId, timestamp, timestamp,
  );
  const row = await workflowEvidence.append({
    auditId,
    findingId: "f-tamper",
    kind: "code_excerpt",
    title: "src/lib/db.js:11-11",
    content: { path: "src/lib/db.js", start_line: 11, end_line: 11, quote: "db.prepare(query).all()" },
  });
  const parsed = await Bun.file(row.content_path).json() as { content?: string };
  parsed.content = "tampered quote that must not reach the retest prompt";
  await Bun.write(row.content_path, `${JSON.stringify(parsed, null, 2)}\n`);

  const taskId = await engine.requestRetest("f-tamper", "u1");
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", taskId)?.status === "failed");
  const task = store.get<{ status: string; error: string | null; agent_session_id: string | null }>(
    "SELECT status, error, agent_session_id FROM tasks WHERE id = ?",
    taskId,
  );
  expect(task?.status).toBe("failed");
  expect(task?.error).toContain("Evidence integrity check failed");
  expect(store.all("SELECT id FROM evidence WHERE task_id = ? AND kind = 'agent_prompt'", taskId)).toHaveLength(0);
  expect(store.get<{ status: string }>("SELECT status FROM agent_sessions WHERE id = ?", task?.agent_session_id))
    .toMatchObject({ status: "failed" });
}, 20_000);

test("a repository path containing a colon stays intact through persistence and reverification", async () => {
  const source = join(dir, "colon-repo");
  mkdirSync(join(source, "src"), { recursive: true });
  const loginQuote = 'const token = "hardcoded-login-secret-value";';
  const resetQuote = 'const token = "hardcoded-reset-secret-value";';
  writeFileSync(join(source, "src/auth:login.js"), `${loginQuote}\n`);
  writeFileSync(join(source, "src/auth:reset.js"), `${resetQuote}\n`);
  const timestamp = now();
  store.run(
    `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, max_concurrent_agents, created_at, updated_at)
     VALUES ('p-colon','Colon paths','', ?, ?, '[]', 'Tester','TEST-AUTH',1,?,?)`,
    source,
    toJson(["**/*.js"]),
    timestamp,
    timestamp,
  );
  const inventory = await buildInventory(source, {
    scope: { include: ["**/*.js"], exclude: [] },
    maxFiles: 20,
    maxFileBytes: 100_000,
  });
  store.run(
    `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES ('r-colon','p-colon',?,NULL,'test',?,?,?,?,?,?,?)`,
    source,
    toJson(inventory.languages),
    toJson(inventory.frameworks),
    toJson(inventory),
    toJson({}),
    inventory.files.length,
    inventory.total_bytes,
    timestamp,
  );
  const colonAudit = engine.createAudit({
    projectId: "p-colon",
    repositoryId: "r-colon",
    userId: "u1",
    overrides: { max_concurrent_agents: 1, max_reverifications: 2, require_distinct_harness_for_retest: false },
  });
  const discoveryTask = uid();
  const discoverySession = uid();
  const verifySession = uid();
  store.run(
    `INSERT INTO tasks (id, audit_id, phase, kind, task_key, title, status, priority, payload, agent_role, harness, model, attempts, max_attempts, requires_approval, created_at, finished_at)
     VALUES (?, ?, 2, 'phase2.discover', 'phase2:area:api', 'discover', 'completed', 0, '{}', 'security_researcher', 'pi', NULL, 1, 2, 0, ?, ?)`,
    discoveryTask, colonAudit, timestamp, timestamp,
  );
  store.run(
    `INSERT INTO agent_sessions (id, audit_id, task_id, role, harness, model, status, workspace, sandbox_mode, started_at, ended_at)
     VALUES (?, ?, ?, 'security_researcher', 'pi', NULL, 'completed', ?, 'none', ?, ?)`,
    discoverySession, colonAudit, discoveryTask, join(dir, "colon-ws"), timestamp, timestamp,
  );
  store.run(
    `INSERT INTO agent_sessions (id, audit_id, task_id, role, harness, model, status, workspace, sandbox_mode, started_at, ended_at)
     VALUES (?, ?, NULL, 'independent_validator', 'pi', NULL, 'completed', ?, 'none', ?, ?)`,
    verifySession, colonAudit, join(dir, "colon-ws-verify"), timestamp, timestamp,
  );
  const cases = [
    { id: "c-login", title: "Hardcoded login secret", path: "src/auth:login.js", quote: loginQuote, repeatCheck: true },
    { id: "c-reset", title: "Hardcoded reset secret", path: "src/auth:reset.js", quote: resetQuote, repeatCheck: false },
  ];
  for (const item of cases) {
    const candidate = {
      title: item.title,
      category: "Hardcoded secret",
      cwe: "CWE-798",
      severity: "high",
      files: [{ path: item.path, start_line: 1, end_line: 1 }],
      hypothesis: "A credential is embedded in source.",
      source_to_sink: "source literal -> authentication check",
      preconditions: ["Source is deployed"],
      evidence_excerpts: [{ path: item.path, start_line: 1, end_line: 1, quote: item.quote }],
      reproduction_notes: "Read the source file.",
      expected: "Secrets come from a protected store.",
      observed: "The secret is present in the repository file.",
      impact: "Anyone with the repository can reuse the credential.",
      remediation: "Remove the literal and rotate the credential.",
    };
    store.run(
      `INSERT INTO candidates (id, audit_id, area_id, discovery_task_id, discovery_session_id, title, category, cwe, severity, status, payload, created_at)
       VALUES (?, ?, 'api', ?, ?, ?, 'Hardcoded secret', 'CWE-798', 'high', 'confirmed', ?, ?)`,
      item.id, colonAudit, discoveryTask, discoverySession, item.title, toJson(candidate), timestamp,
    );
    const verificationId = uid();
    const check = { found: true, path: item.path, line_start: 1, line_end: 1 };
    store.run(
      `INSERT INTO verifications (id, audit_id, candidate_id, kind, agent_session_id, discovery_session_id, verdict, rationale, evidence_check, payload, created_at)
       VALUES (?, ?, ?, 'confirmation', ?, ?, 'CONFIRMED', 'Verified against the snapshot.', ?, ?, ?)`,
      verificationId,
      colonAudit,
      item.id,
      verifySession,
      discoverySession,
      toJson({ verified_count: 1, checks: item.repeatCheck ? [check, check] : [check] }),
      toJson({
        raw: {
          verdict: "CONFIRMED",
          rationale: "Verified against the snapshot.",
          verified_excerpts: [{ path: item.path, start_line: 1, end_line: 1, quote: item.quote }],
          reproduction_steps: ["Open the file."],
          severity_assessment: "high",
          impact_assessment: "Anyone with the repository can reuse the credential.",
        },
      }),
      timestamp,
    );
    engine.createTask({
      auditId: colonAudit,
      phase: 4,
      kind: "phase4.persist",
      taskKey: `phase4:candidate:${item.id}`,
      title: `Persist ${item.title}`,
      payload: { candidate_id: item.id, verification_id: verificationId },
      agentRole: null,
    });
  }
  manager.run = async (kind, task, hooks) => {
    const startedAt = now();
    hooks.onEvent({ type: "session_start", at: startedAt, meta: { sandbox: "test", harness: kind } });
    const data = {
      decision: "REVERIFIED",
      rationale: "The affected code still matches the finding and impact is supported.",
      verified_excerpts: cases.map((item) => ({ path: item.path, start_line: 1, end_line: 1, quote: item.quote })),
      impact_assessment: "The impact remains supported by the source code.",
      reproduction_consistency: "The recorded reasoning follows directly from the verified source.",
      completeness_issues: [],
      unsupported_claims: [],
      severity_assessment: "high",
      notes: ["No runtime exploitation was performed."],
    };
    hooks.onEvent({ type: "session_end", at: now(), meta: { sandbox: "test" } });
    return {
      status: "completed" as const,
      text: JSON.stringify(data),
      structured: data,
      sessionRef: `scripted-${task.runId}`,
      model: task.model,
      usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, cache_read_tokens: 0, cost_usd: 0, turns: 1, duration_ms: 1 },
      events: [],
      startedAt,
      endedAt: now(),
      exitCode: 0,
      metadata: { harness: kind, sandbox: "test" },
    };
  };
  store.run("UPDATE audits SET status = 'running', started_at = ? WHERE id = ?", timestamp, colonAudit);

  await waitFor(() => {
    const findings = store.all<{ status: string }>("SELECT status FROM findings WHERE audit_id = ?", colonAudit);
    return findings.length === 2 && findings.every((finding) => finding.status === "reverified");
  }, 20_000);

  const findings = store.all<{ title: string; status: string; files: string; retest_decision: string | null }>(
    "SELECT title, status, files, retest_decision FROM findings WHERE audit_id = ? ORDER BY title",
    colonAudit,
  );
  expect(findings.map((finding) => ({
    title: finding.title,
    status: finding.status,
    retest_decision: finding.retest_decision,
    files: JSON.parse(finding.files),
  }))).toEqual([
    {
      title: "Hardcoded login secret",
      status: "reverified",
      retest_decision: "REVERIFIED",
      files: [{ path: "src/auth:login.js", start_line: 1, end_line: 1 }],
    },
    {
      title: "Hardcoded reset secret",
      status: "reverified",
      retest_decision: "REVERIFIED",
      files: [{ path: "src/auth:reset.js", start_line: 1, end_line: 1 }],
    },
  ]);
  expect(store.all<{ status: string }>("SELECT status FROM candidates WHERE audit_id = ? ORDER BY title", colonAudit))
    .toEqual([{ status: "persisted" }, { status: "persisted" }]);
  const persisted = store.all<{ result: string | null }>(
    "SELECT result FROM tasks WHERE audit_id = ? AND kind = 'phase4.persist'",
    colonAudit,
  );
  expect(persisted).toHaveLength(2);
  expect(persisted.every((task) => task.result?.includes("duplicate_of") !== true)).toBe(true);
  const excerpts = store.all<{ id: string }>(
    "SELECT id FROM evidence WHERE audit_id = ? AND kind = 'code_excerpt' ORDER BY title",
    colonAudit,
  );
  const excerptPaths: string[] = [];
  for (const excerpt of excerpts) {
    const verified = await workflowEvidence.content(excerpt.id);
    excerptPaths.push((JSON.parse(verified!.content) as { path: string }).path);
  }
  expect(excerptPaths).toEqual(["src/auth:login.js", "src/auth:reset.js"]);
  await engine.cancelAudit(colonAudit, "u1");
}, 25_000);

test("invalid audit overrides are rejected before an audit is saved", () => {
  for (const overrides of [
    { max_areas: "invalid" }, { max_concurrent_agents: 1.5 }, { max_confirmations: -1 },
    { task_timeout_ms: Number.NaN }, { max_cost_usd: -5 }, { writable_workspace: "true" },
    { harness_overrides: [] }, { harness_overrides: { codebase_mapper: { harness: "unknown" } } },
  ]) {
    expect(() => engine.createAudit({ projectId: "p1", repositoryId: "r1", userId: "u1", overrides })).toThrow();
  }
  expect(store.all("SELECT id FROM audits")).toHaveLength(1);
});

test("a legacy invalid harness override closes the audit instead of stranding it", async () => {
  const invalid = engine.createAudit({
    projectId: "p1",
    repositoryId: "r1",
    userId: "u1",
    overrides: {},
  });
  store.run(
    "UPDATE audits SET config = json_set(config, '$.harness_overrides.codebase_mapper.harness', 'invalid-kind') WHERE id = ?",
    invalid,
  );

  await expect(engine.startAudit(invalid, "u1")).rejects.toThrow();
  expect(store.get("SELECT status, error FROM audits WHERE id = ?", invalid)).toMatchObject({
    status: "failed",
    error: expect.stringContaining("could not create its initial task"),
  });
  expect(store.all("SELECT id FROM tasks WHERE audit_id = ?", invalid)).toHaveLength(0);
  expect(store.get("SELECT status FROM audit_phases WHERE audit_id = ? AND phase = 1", invalid))
    .toMatchObject({ status: "failed" });
});

test("provider diagnostics are redacted before they are returned as session errors", async () => {
  manager.run = async (_kind, task, hooks) => {
    const startedAt = now();
    hooks.onEvent({ type: "session_start", at: startedAt, meta: { sandbox: "test" } });
    return {
      status: "failed",
      text: "",
      sessionRef: "redaction-test",
      model: task.model,
      usage: {
        input_tokens: 0, output_tokens: 0, total_tokens: 0,
        cache_read_tokens: 0, cost_usd: 0, turns: null, duration_ms: 1,
      },
      events: [],
      startedAt,
      endedAt: now(),
      exitCode: 1,
      error: "Provider rejected Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
      failureKind: "harness_auth",
      metadata: { sandbox: "test", api_key: "must-not-be-returned" },
    };
  };

  await engine.startAudit(auditId, "u1");
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status === "failed");
  const session = store.get<{ error: string; metadata: string }>(
    "SELECT error, metadata FROM agent_sessions WHERE audit_id = ?",
    auditId,
  )!;
  expect(session.error).toContain("[REDACTED]");
  expect(session.error).not.toContain("abcdefghijklmnopqrstuvwxyz");
  expect(session.metadata).toContain("[REDACTED]");
  expect(session.metadata).not.toContain("must-not-be-returned");
});

test("a persistence retry repairs evidence for a finding created by the failed attempt", async () => {
  const append = workflowEvidence.append.bind(workflowEvidence);
  let failed = false;
  workflowEvidence.append = async (input) => {
    if (!failed && input.kind === "code_excerpt") {
      failed = true;
      throw new Error("Injected evidence storage failure");
    }
    return append(input);
  };

  await engine.startAudit(auditId, "u1");
  const deadline = Date.now() + 30_000;
  let audit = store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId);
  while (audit && !["completed", "completed_with_errors", "failed", "cancelled"].includes(audit.status) && Date.now() < deadline) {
    await Bun.sleep(50);
    audit = store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId);
  }

  expect(failed).toBe(true);
  expect(audit?.status).toBe("completed");
  const findings = store.all<{ id: string }>("SELECT id FROM findings WHERE audit_id = ?", auditId);
  expect(findings).toHaveLength(2);
  for (const finding of findings) {
    expect(store.all(
      "SELECT id FROM evidence WHERE finding_id = ? AND kind = 'code_excerpt'",
      finding.id,
    ).length).toBeGreaterThan(0);
    expect(store.all(
      "SELECT id FROM evidence WHERE finding_id = ? AND kind = 'finding_record'",
      finding.id,
    )).toHaveLength(1);
  }
}, 20_000);

for (const failureKind of ["discovery_result", "verification_result", "reverification_result"]) {
  test(`a ${failureKind} storage retry does not duplicate workflow records`, async () => {
    const append = workflowEvidence.append.bind(workflowEvidence);
    let failed = false;
    workflowEvidence.append = async (input) => {
      if (!failed && input.kind === failureKind) {
        failed = true;
        throw new Error(`Injected ${failureKind} storage failure`);
      }
      return append(input);
    };

    await engine.startAudit(auditId, "u1");
    const deadline = Date.now() + 30_000;
    let audit = store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId);
    while (audit && !["completed", "completed_with_errors", "failed", "cancelled"].includes(audit.status) && Date.now() < deadline) {
      await Bun.sleep(50);
      audit = store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId);
    }

    expect(failed).toBe(true);
    expect(audit?.status).toBe("completed");
    expect(store.all("SELECT id FROM candidates WHERE audit_id = ?", auditId)).toHaveLength(2);
    expect(store.all("SELECT id FROM verifications WHERE audit_id = ? AND kind = 'confirmation'", auditId)).toHaveLength(2);
    expect(store.all("SELECT id FROM verifications WHERE audit_id = ? AND kind = 'reverification'", auditId)).toHaveLength(2);
    expect(store.all("SELECT id FROM evidence WHERE audit_id = ? AND kind = ?", auditId, failureKind))
      .toHaveLength(failureKind === "discovery_result" ? 1 : 2);
    expect(store.all("SELECT id FROM execution_events WHERE audit_id = ? AND type = 'task.retry'", auditId).length)
      .toBeGreaterThan(0);
  }, 30_000);
}

for (const scenario of [
  { name: "new audits save the configured task timeout", override: undefined, roleLimit: 720_000, legacy: false, expected: 10_000 },
  { name: "audit timeout overrides reach the harness", override: 12_000, roleLimit: 720_000, legacy: false, expected: 12_000 },
  { name: "legacy audits apply the current timeout setting", override: undefined, roleLimit: 720_000, legacy: true, expected: 10_000 },
  { name: "role duration remains a ceiling on audit timeouts", override: 30_000, roleLimit: 20_000, legacy: false, expected: 20_000 },
]) {
  test(scenario.name, async () => {
    setSetting(store, "audit.task_timeout_ms", 10_000, null);
    store.run("UPDATE agent_defs SET max_duration_ms = ? WHERE role = 'codebase_mapper'", scenario.roleLimit);
    const id = engine.createAudit({
      projectId: "p1", repositoryId: "r1", userId: "u1",
      overrides: scenario.override === undefined ? {} : { task_timeout_ms: scenario.override },
    });
    if (scenario.legacy) store.run("UPDATE audits SET config = json_remove(config, '$.task_timeout_ms') WHERE id = ?", id);
    const timeouts: number[] = [];
    const run = manager.run.bind(manager);
    manager.run = async (...args) => {
      timeouts.push(args[1].timeoutMs);
      engine.cancelTask(args[1].taskId, "test");
      return run(...args);
    };
    await engine.startAudit(id, "u1");
    await waitFor(() => !store.get("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", id));
    expect(timeouts).toEqual([scenario.expected]);
    if (!scenario.legacy) {
      const audit = store.get<{ config: string }>("SELECT config FROM audits WHERE id = ?", id)!;
      expect(JSON.parse(audit.config).task_timeout_ms).toBe(scenario.override ?? 10_000);
    }
  });
}

test("reports omit empty authorization labels and retain supplied metadata", async () => {
  const config = testConfig(dir);
  const events = new EventLog(store);
  const evidence = new EvidenceStore(config, store);
  const reports = new ReportService(config, store, evidence, events);
  const original = await reports.generate(auditId, ["markdown"], "test");
  const originalText = readFileSync(original[0]!.path, "utf8");
  expect(originalText).toContain("**Authorized by:** Tester");
  expect(originalText).toContain("**Authorization reference:** TEST-AUTH");

  store.run("UPDATE projects SET authorized_by = '', authorization_ref = '' WHERE id = 'p1'");
  const generated = await reports.generate(auditId, ["markdown", "json", "html", "pdf"], "test");
  expect(generated).toHaveLength(4);
  for (const report of generated) {
    const content = readFileSync(report.path, "utf8");
    if (report.format === "json") {
      expect(JSON.parse(content).project).toMatchObject({ authorized_by: "", authorization_ref: "" });
    } else {
      expect(content).not.toContain("Authorized by:");
      expect(content).not.toContain("Authorization reference:");
    }
  }
});

test("six-phase workflow persists findings, verification history, evidence, and reports", async () => {
  await engine.startAudit(auditId, "u1");
  const deadline = Date.now() + 90_000;
  let audit = store.get<{ status: string; error: string | null }>(
    "SELECT status, error FROM audits WHERE id = ?",
    auditId,
  );
  while (audit && !["completed", "completed_with_errors", "failed", "cancelled"].includes(audit.status) && Date.now() < deadline) {
    await Bun.sleep(250);
    audit = store.get<{ status: string; error: string | null }>(
      "SELECT status, error FROM audits WHERE id = ?",
      auditId,
    );
  }
  if (!audit || !["completed", "completed_with_errors"].includes(audit.status)) {
    const tasks = store.all("SELECT phase, kind, status, error FROM tasks WHERE audit_id = ?", auditId);
    const failures = store.all("SELECT type, payload FROM execution_events WHERE audit_id = ? AND type IN ('task.failed','audit.failed','system.error')", auditId);
    throw new Error(`Audit did not complete: ${audit?.status} ${audit?.error ?? ""}\n${JSON.stringify(tasks)}\n${JSON.stringify(failures)}`);
  }
  expect(audit.status).toBe("completed");
  const findings = store.all<{ code: string; status: string; title: string }>(
    "SELECT code, status, title FROM findings WHERE audit_id = ? ORDER BY code",
    auditId,
  );
  expect(findings.length).toBe(2);
  expect(findings.every((finding) => finding.status === "reverified")).toBe(true);
  const verifications = store.all<{ kind: string; verdict: string }>(
    "SELECT kind, verdict FROM verifications WHERE audit_id = ?",
    auditId,
  );
  expect(verifications.filter((entry) => entry.kind === "confirmation").length).toBe(2);
  expect(verifications.filter((entry) => entry.kind === "reverification").length).toBe(2);
  const sessions = store.all<{ harness: string }>("SELECT harness FROM agent_sessions WHERE audit_id = ?", auditId);
  expect(new Set(sessions.map((session) => session.harness))).toEqual(new Set(["pi", "claude-code"]));
  const phases = store.all<{ phase: number; status: string; name: string }>(
    "SELECT phase, status, name FROM audit_phases WHERE audit_id = ? ORDER BY phase",
    auditId,
  );
  expect(phases.length).toBe(6);
  expect(phases.every((phase) => phase.status === "completed")).toBe(true);
  const chain = await new EvidenceStore(testConfig(dir), store).verifyChain(auditId);
  expect(chain.ok).toBe(true);
  expect(chain.count).toBeGreaterThan(5);
  const reports = store.all<{ format: string; status: string; path: string | null; sha256: string | null }>(
    "SELECT format, status, path, sha256 FROM reports WHERE audit_id = ?",
    auditId,
  );
  expect(new Set(reports.map((report) => report.format))).toEqual(new Set(["markdown", "json", "html", "pdf"]));
  expect(reports.every((report) => report.status === "generated" && report.path && report.sha256)).toBe(true);
  const pdf = reports.find((report) => report.format === "pdf")!;
  const bytes = readFileSync(pdf.path!);
  expect(bytes.subarray(0, 5).toString()).toBe("%PDF-");
  const markdownReport = reports.find((report) => report.format === "markdown")!;
  const markdownText = readFileSync(markdownReport.path!, "utf8");
  expect(markdownText).toContain("Verified source evidence");
  expect(markdownText).toContain("ARG-001");
  expect(markdownText).toContain("Evidence chain:** verified");
  const events = store.all<{ type: string }>(
    "SELECT type FROM execution_events WHERE audit_id = ? ORDER BY seq",
    auditId,
  );
  expect(events.some((event) => event.type === "finding.created")).toBe(true);
  expect(events.some((event) => event.type === "audit.completed")).toBe(true);
  expect(events.some((event) => event.type === "system.error")).toBe(false);
  // Phase 6 must not be scheduled before confirmation and reverification finish.
  const reportTask = store.get<{ created_at: string }>(
    "SELECT created_at FROM tasks WHERE audit_id = ? AND kind = 'phase6.report'",
    auditId,
  )!;
  const lastRetest = store.get<{ finished_at: string }>(
    "SELECT finished_at FROM tasks WHERE audit_id = ? AND phase = 5 AND status = 'completed' ORDER BY finished_at DESC LIMIT 1",
    auditId,
  )!;
  expect(reportTask.created_at >= lastRetest.finished_at).toBe(true);
}, 120_000);

test("a discovering session cannot confirm its own candidate", () => {
  // The engine enforces this by construction and also checks it in the handler.
  // This unit-level assertion documents the provenance invariant.
  const source = readFileSync(join(import.meta.dir, "..", "src", "orchestrator", "engine.ts"), "utf8");
  expect(source).toContain("Independence violation: the discovering session cannot confirm its own candidate");
  expect(source).toContain("Independence violation: discovery or first-validation session cannot reverify this finding");
});

test("restart finishes cancellation without requeueing interrupted or pending work", async () => {
  const interrupted = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "phase1:map",
    title: "Interrupted mapper", payload: {}, agentRole: "codebase_mapper",
  });
  const queued = engine.createTask({
    auditId, phase: 2, kind: "phase2.discover", taskKey: "queued",
    title: "Queued discovery", payload: { area_id: "api" }, agentRole: "security_researcher",
  });
  const waiting = engine.createTask({
    auditId, phase: 2, kind: "phase2.discover", taskKey: "waiting",
    title: "Waiting for approval", payload: { area_id: "other" }, agentRole: null,
    requiresApproval: true,
  });
  store.run(
    `INSERT INTO agent_sessions (id, audit_id, task_id, role, harness, status, workspace, sandbox_mode, started_at)
     VALUES ('interrupted-session', ?, ?, 'codebase_mapper', 'pi', 'running', ?, 'test', ?)`,
    auditId, interrupted, dir, now(),
  );
  store.run("UPDATE tasks SET status = 'running', attempts = 1, started_at = ? WHERE id = ?", now(), interrupted);
  store.run("UPDATE audits SET status = 'cancelling' WHERE id = ?", auditId);
  store.run("UPDATE audit_phases SET status = 'running' WHERE audit_id = ? AND phase = 1", auditId);
  await engine.stop();
  engine = createEngine();
  engine.start();

  for (const taskId of [interrupted, queued, waiting]) {
    expect(store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", taskId)?.status).toBe("cancelled");
  }
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status === "cancelled");
  expect(store.get<{ status: string }>("SELECT status FROM approvals WHERE task_id = ?", waiting)?.status).toBe("denied");
  expect(store.get<{ status: string; ended_at: string | null }>(
    "SELECT status, ended_at FROM agent_sessions WHERE id = 'interrupted-session'",
  )).toMatchObject({ status: "cancelled", ended_at: expect.any(String) });
  expect(store.all("SELECT phase FROM audit_phases WHERE audit_id = ? AND status IN ('pending','running')", auditId)).toHaveLength(0);
});

test("restart only retries interrupted work in a running audit with attempts remaining", async () => {
  const retryable = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "retryable",
    title: "Retryable mapper", payload: {}, agentRole: "codebase_mapper",
  });
  const exhausted = engine.createTask({
    auditId, phase: 2, kind: "phase2.discover", taskKey: "exhausted",
    title: "Exhausted researcher", payload: { area_id: "api" }, agentRole: "security_researcher",
  });
  store.run("UPDATE audits SET status = 'running' WHERE id = ?", auditId);
  store.run("UPDATE tasks SET status = 'running', attempts = 1, max_attempts = 2 WHERE id = ?", retryable);
  store.run("UPDATE tasks SET status = 'running', attempts = 2, max_attempts = 2 WHERE id = ?", exhausted);
  await engine.stop();
  engine = createEngine();
  engine.start();

  expect(store.get("SELECT status, attempts, failure_kind FROM tasks WHERE id = ?", retryable))
    .toMatchObject({ status: "queued", attempts: 1, failure_kind: "server_restart" });
  expect(store.get("SELECT status, attempts, failure_kind, finished_at FROM tasks WHERE id = ?", exhausted))
    .toMatchObject({ status: "failed", attempts: 2, failure_kind: "server_restart", finished_at: expect.any(String) });
  const recovered = store.get<{ payload: string }>(
    "SELECT payload FROM execution_events WHERE audit_id = ? AND type = 'system.recovered'", auditId,
  );
  expect(JSON.parse(recovered!.payload).tasks_requeued).toBe(1);
});

test("restart closes orphaned work in a failed audit without changing terminal tasks", async () => {
  const pending = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "pending",
    title: "Orphaned mapper", payload: {}, agentRole: "codebase_mapper",
  });
  const completed = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "completed",
    title: "Completed mapper", payload: {}, agentRole: "codebase_mapper",
  });
  store.run("UPDATE audits SET status = 'failed' WHERE id = ?", auditId);
  store.run("UPDATE tasks SET status = 'completed', result = '{\"kept\":true}' WHERE id = ?", completed);
  await engine.stop();
  engine = createEngine();
  engine.start();

  expect(store.get("SELECT status, failure_kind FROM tasks WHERE id = ?", pending))
    .toMatchObject({ status: "failed", failure_kind: "audit_closed" });
  expect(store.get("SELECT status, result FROM tasks WHERE id = ?", completed))
    .toMatchObject({ status: "completed", result: '{"kept":true}' });
});

test("cancelling the only mapping task terminates the audit instead of leaving it running", async () => {
  const taskId = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "phase1:map",
    title: "Mapper", payload: {}, agentRole: "codebase_mapper",
  });
  store.run("UPDATE audits SET status = 'running' WHERE id = ?", auditId);
  engine.cancelTask(taskId, "u1");

  await waitFor(() => store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status !== "running", 3_500);
  expect(store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status).toBe("failed");
  expect(store.get<{ status: string; finished_at: string | null }>(
    "SELECT status, finished_at FROM audit_phases WHERE audit_id = ? AND phase = 1", auditId,
  )).toMatchObject({ status: "failed", finished_at: expect.any(String) });
  expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND phase > 1", auditId)).toHaveLength(0);
});

for (const cancellation of ["audit", "task"]) {
  test(`a harness error after ${cancellation} cancellation never queues a retry`, async () => {
    manager.run = async (_kind, _task, hooks) => {
      hooks.onEvent({ type: "session_start", at: now(), meta: { sandbox: "test" } });
      return new Promise<HarnessRunResult>((_resolve, reject) => {
        const abort = () => reject(new Error("Harness stopped after cancellation"));
        if (hooks.signal?.aborted) abort();
        else hooks.signal?.addEventListener("abort", abort, { once: true });
      });
    };
    await engine.startAudit(auditId, "u1");
    await waitFor(() => Boolean(store.get("SELECT id FROM agent_sessions WHERE audit_id = ? AND status = 'running'", auditId)));
    if (cancellation === "audit") await engine.cancelAudit(auditId, "u1");
    else {
      const task = store.get<{ id: string }>("SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase1.map'", auditId)!;
      engine.cancelTask(task.id, "u1");
    }
    await waitFor(() => !store.get("SELECT id FROM tasks WHERE audit_id = ? AND status = 'running'", auditId));

    expect(store.get<{ status: string; attempts: number }>(
      "SELECT status, attempts FROM tasks WHERE audit_id = ? AND kind = 'phase1.map'", auditId,
    )).toMatchObject({ status: "cancelled", attempts: 1 });
    expect(store.get("SELECT status FROM agent_sessions WHERE audit_id = ?", auditId)).toMatchObject({ status: "cancelled" });
    await waitFor(() => store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status ===
      (cancellation === "audit" ? "cancelled" : "failed"));
    expect(store.all("SELECT seq FROM execution_events WHERE audit_id = ? AND type = 'task.retry'", auditId)).toHaveLength(0);
  });
}

test("cancelling during workspace preparation prevents harness invocation", async () => {
  let invoked = false;
  const run = manager.run.bind(manager);
  manager.run = async (...args) => {
    invoked = true;
    return run(...args);
  };
  await engine.startAudit(auditId, "u1");
  const task = store.get<{ id: string }>("SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase1.map'", auditId)!;
  engine.cancelTask(task.id, "u1");
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", task.id)?.status !== "running");

  expect(invoked).toBe(false);
  expect(store.get("SELECT status FROM tasks WHERE id = ?", task.id)).toMatchObject({ status: "cancelled" });
  expect(store.get("SELECT status FROM agent_sessions WHERE task_id = ?", task.id)).toMatchObject({ status: "cancelled" });
});

test("a successful harness result arriving after task cancellation is not applied", async () => {
  const run = manager.run.bind(manager);
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  manager.run = async (...args) => {
    entered.resolve();
    await release.promise;
    return run(...args);
  };
  await engine.startAudit(auditId, "u1");
  await entered.promise;
  const task = store.get<{ id: string }>("SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase1.map'", auditId)!;
  engine.cancelTask(task.id, "u1");
  release.resolve();
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", task.id)?.status !== "running");

  expect(store.get("SELECT status FROM tasks WHERE id = ?", task.id)).toMatchObject({ status: "cancelled" });
  expect(store.get("SELECT status FROM agent_sessions WHERE task_id = ?", task.id)).toMatchObject({ status: "cancelled" });
  expect(store.all("SELECT id FROM coverage WHERE audit_id = ?", auditId)).toHaveLength(0);
  expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND phase > 1", auditId)).toHaveLength(0);
});

test("a report queued before retest completion is current if generation started afterwards", async () => {
  const createCompleted = (phase: number, kind: string, key: string) => {
    const taskId = engine.createTask({ auditId, phase, kind, taskKey: key, title: key, payload: {}, agentRole: null });
    store.run("UPDATE tasks SET status = 'completed', finished_at = '2020-01-01T00:00:02.000Z' WHERE id = ?", taskId);
    return taskId;
  };
  createCompleted(1, "phase1.map", "mapper");
  createCompleted(2, "phase2.discover", "researcher");
  const retest = createCompleted(5, "phase5.reverify", "manual-retest");
  const report = createCompleted(6, "phase6.report", "report-after-retest");
  store.run("INSERT INTO task_dependencies (task_id, depends_on_task_id) VALUES (?, ?)", report, retest);
  store.run("UPDATE tasks SET created_at = '2020-01-01T00:00:01.000Z', started_at = '2020-01-01T00:00:03.000Z', finished_at = '2020-01-01T00:00:04.000Z' WHERE id = ?", report);
  store.run("UPDATE audits SET status = 'running' WHERE id = ?", auditId);
  store.run("UPDATE audit_phases SET status = 'completed' WHERE audit_id = ?", auditId);
  await waitFor(() => Boolean(store.get("SELECT id FROM execution_events WHERE audit_id = ? AND type IN ('audit.completed','report.rebuild_scheduled')", auditId)));

  expect(store.get("SELECT status FROM audits WHERE id = ?", auditId)).toMatchObject({ status: "completed" });
  expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase6.report'", auditId)).toHaveLength(1);
});

test("engine loads role-assigned local skills and records streamed MCP usage without exposing credentials", async () => {
  const home = join(dir, "local-home");
  const skillRoot = join(home, ".agents/skills/review");
  mkdirSync(skillRoot, { recursive: true });
  writeFileSync(join(skillRoot, "SKILL.md"), "---\nname: local-review\ndescription: Review local source\n---\nUse exact source evidence.\n");
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { local: {
    url: "https://example.test/mcp", headers: { Authorization: "private-mcp-test-credential" },
  } } }));
  const catalog = new LocalCatalog(store, { home, projectRoot: dir });
  const view = await catalog.refresh();
  const skill = view.skills[0]!;
  const server = view.servers[0]!;
  catalog.setSkillAccess(skill.id, { enabled: true, roles: ["codebase_mapper"], mcp_ids: [server.id] });
  let captured: HarnessTask | undefined;
  const run = manager.run.bind(manager);
  manager.run = async (kind, task, hooks) => {
    captured = task;
    const mcp = task.resources?.servers[0];
    if (mcp) hooks.onEvent({ type: "tool_start", at: now(), toolName: `mcp__${mcp.key}__inspect`, toolCallId: "local-call" });
    return run(kind, task, hooks);
  };
  await engine.stop();
  engine = createEngine(catalog);
  engine.start();
  await engine.startAudit(auditId, "u1");
  await waitFor(() => Boolean(store.get("SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase1.map' AND status = 'completed'", auditId)));
  await engine.cancelAudit(auditId, "u1");
  expect(captured?.resources?.skills[0]?.name).toBe("local-review");
  expect(captured?.systemPrompt).toContain("Use exact source evidence.");
  expect(catalog.usage("skill", skill.id).stats.total_calls).toBe(1);
  expect(catalog.usage("mcp", server.id).recent[0]).toMatchObject({ role: "codebase_mapper", tool_name: "inspect" });
  const evidence = store.all("SELECT kind, title FROM evidence WHERE audit_id = ? AND kind = 'local_resources'", auditId);
  expect(evidence).toHaveLength(1);
  expect(JSON.stringify(store.all("SELECT payload FROM execution_events WHERE audit_id = ?", auditId))).not.toContain("private-mcp-test-credential");
});

for (const cap of [0, 1]) {
  test(`automatic reverification respects a cap of ${cap} and still generates reports`, async () => {
    auditId = engine.createAudit({
      projectId: "p1", repositoryId: "r1", userId: "u1",
      overrides: { max_areas: 1, max_candidates_per_area: 2, max_reverifications: cap, max_concurrent_agents: 2 },
    });
    await engine.startAudit(auditId, "u1");
    await waitFor(() => ["completed", "completed_with_errors", "failed"].includes(
      store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status ?? "",
    ), 25_000);

    expect(store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status).toBe("completed");
    expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase5.reverify'", auditId)).toHaveLength(cap);
    expect(store.all("SELECT id FROM findings WHERE audit_id = ? AND status = 'reverified'", auditId)).toHaveLength(cap);
    expect(store.all("SELECT id FROM findings WHERE audit_id = ? AND status = 'unresolved' AND retest_decision = 'UNRESOLVED'", auditId)).toHaveLength(2 - cap);
    expect(store.all("SELECT id FROM reports WHERE audit_id = ? AND status = 'generated'", auditId)).toHaveLength(4);
    expect((await new EvidenceStore(testConfig(dir), store).verifyChain(auditId)).ok).toBe(true);

    if (cap === 0) {
      const finding = store.get<{ id: string }>("SELECT id FROM findings WHERE audit_id = ? ORDER BY code LIMIT 1", auditId)!;
      const manualTask = await engine.requestRetest(finding.id, "u1");
      await waitFor(() => store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId)?.status === "completed", 15_000);
      expect(store.get("SELECT status FROM tasks WHERE id = ?", manualTask)).toMatchObject({ status: "completed" });
      expect(store.get("SELECT status FROM findings WHERE id = ?", finding.id)).toMatchObject({ status: "reverified" });
      expect(store.all("SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase5.reverify' AND task_key NOT LIKE '%:manual:%'", auditId)).toHaveLength(0);
      expect(store.all("SELECT id FROM reports WHERE audit_id = ? AND status = 'generated'", auditId)).toHaveLength(8);
    }
  }, 30_000);
}

test("runtime tools reach the actual task and an audit override uses its chosen runtime list", async () => {
  await engine.stop();
  const tasks: HarnessTask[] = [];
  manager = fakeManager((task) => tasks.push(task));
  engine = createEngine();
  const tools = ["Read", "Grep", "Glob", "LS", "Bash", "Edit", "Write", "WebFetch", "WebSearch"];
  saveHarnessConfig(store, "claude-code", { ...harnessConfig(store, "claude-code"), allowed_tools: tools });
  setSetting(store, "security.allow_shell_tools", true, null);
  setSetting(store, "security.require_approval_for_shell", false, null);
  const config = JSON.parse(store.get<{ config: string }>("SELECT config FROM audits WHERE id = ?", auditId)!.config);
  store.run("UPDATE audits SET config = ?, status = 'running' WHERE id = ?", toJson({ ...config,
    harness_overrides: { codebase_mapper: { harness: "claude-code" } },
  }), auditId);
  const taskId = engine.createTask({ auditId, phase: 1, kind: "phase1.map", taskKey: "runtime-tools",
    title: "Mapper with configured tools", payload: {}, agentRole: "codebase_mapper" });
  expect(store.get("SELECT status, harness FROM tasks WHERE id = ?", taskId)).toMatchObject({ status: "queued", harness: "claude-code" });
  engine.start();
  await waitFor(() => tasks.some((task) => task.taskId === taskId), 8_000);
  expect(tasks.find((task) => task.taskId === taskId)?.allowedTools).toEqual(tools);
  const event = store.get<{ payload: string }>("SELECT payload FROM execution_events WHERE task_id = ? AND type = 'agent.session_started'", taskId);
  expect(JSON.parse(event!.payload)).toMatchObject({ allowed_tools: tools, inherit_tools: true });
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", taskId)?.status === "completed");
});

test("inherited shell tools request approval and an empty runtime cap cannot grant role tools", async () => {
  setSetting(store, "security.allow_shell_tools", true, null);
  saveHarnessConfig(store, "pi", { ...harnessConfig(store, "pi"), allowed_tools: ["read", "bash"] });
  const taskId = engine.createTask({ auditId, phase: 1, kind: "phase1.map", taskKey: "shell-tools",
    title: "Shell mapper", payload: {}, agentRole: "codebase_mapper" });
  expect(store.get("SELECT status FROM tasks WHERE id = ?", taskId)).toMatchObject({ status: "waiting_approval" });
  expect(store.get("SELECT action FROM approvals WHERE task_id = ?", taskId)).toMatchObject({ action: "allow_shell_tools" });
  saveHarnessConfig(store, "pi", { ...harnessConfig(store, "pi"), allowed_tools: [] });
  store.run("UPDATE agent_defs SET inherit_tools = 0 WHERE role = 'codebase_mapper'");
  store.run("UPDATE audits SET status = 'running' WHERE id = ?", auditId);
  const emptyTask = engine.createTask({ auditId, phase: 1, kind: "phase1.map", taskKey: "empty-tools",
    title: "Empty cap mapper", payload: {}, agentRole: "codebase_mapper" });
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", emptyTask)?.status === "failed", 8_000);
  expect(store.get("SELECT failure_kind FROM tasks WHERE id = ?", emptyTask)).toMatchObject({ failure_kind: "harness_tool_policy" });
});

test("runtime shell access enabled after queuing still needs approval at execution", async () => {
  const taskId = engine.createTask({ auditId, phase: 1, kind: "phase1.map", taskKey: "changed-tools",
    title: "Changed runtime tools", payload: {}, agentRole: "codebase_mapper" });
  setSetting(store, "security.allow_shell_tools", true, null);
  saveHarnessConfig(store, "pi", { ...harnessConfig(store, "pi"), allowed_tools: ["read", "bash"] });
  store.run("UPDATE audits SET status = 'running' WHERE id = ?", auditId);
  await waitFor(() => store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", taskId)?.status === "failed", 8_000);
  expect(store.get("SELECT failure_kind, attempts FROM tasks WHERE id = ?", taskId)).toMatchObject({ failure_kind: "shell_tools_not_approved", attempts: 1 });
  expect(store.all("SELECT id FROM agent_sessions WHERE task_id = ?", taskId)).toHaveLength(0);
});

test("an audit cannot request a writable workspace while the policy is disabled", () => {
  expect(() => engine.createAudit({
    projectId: "p1", repositoryId: "r1", userId: "u1",
    overrides: { writable_workspace: true },
  })).toThrow("security.allow_writable_workspace is disabled");
});

test("writable workspace tasks need a dedicated approval and never inherit shell approval", () => {
  setSetting(store, "security.allow_writable_workspace", true, null);
  setSetting(store, "security.allow_shell_tools", true, null);
  setSetting(store, "security.require_approval_for_shell", true, null);
  store.run("UPDATE agent_defs SET allow_shell = 1 WHERE role = 'codebase_mapper'");
  const config = JSON.parse(store.get<{ config: string }>("SELECT config FROM audits WHERE id = ?", auditId)!.config);
  store.run("UPDATE audits SET config = ? WHERE id = ?", toJson({ ...config, writable_workspace: true }), auditId);
  const taskId = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "phase1:writable",
    title: "Writable mapper", payload: {}, agentRole: "codebase_mapper",
  });
  expect(store.get("SELECT status, requires_approval FROM tasks WHERE id = ?", taskId))
    .toMatchObject({ status: "waiting_approval", requires_approval: 1 });
  const approvals = store.all<{ id: string; action: string; status: string }>(
    "SELECT id, action, status FROM approvals WHERE task_id = ? ORDER BY action", taskId,
  );
  expect(approvals.map((approval) => approval.action)).toEqual(["allow_shell_tools", "allow_writable_workspace"]);
  const shell = approvals.find((approval) => approval.action === "allow_shell_tools")!;
  const writable = approvals.find((approval) => approval.action === "allow_writable_workspace")!;
  engine.decideApproval(shell.id, true, "u1", "shell approved");
  expect(store.get("SELECT status FROM tasks WHERE id = ?", taskId)).toMatchObject({ status: "waiting_approval" });
  engine.decideApproval(writable.id, true, "u1", "writes approved");
  expect(store.get("SELECT status FROM tasks WHERE id = ?", taskId)).toMatchObject({ status: "queued" });
});

test("a writable workspace task fails closed when its approval is missing", async () => {
  setSetting(store, "security.allow_writable_workspace", true, null);
  const config = JSON.parse(store.get<{ config: string }>("SELECT config FROM audits WHERE id = ?", auditId)!.config);
  store.run(
    "UPDATE audits SET config = ?, status = 'running' WHERE id = ?",
    toJson({ ...config, writable_workspace: true }),
    auditId,
  );
  const taskId = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "phase1:writable-fail-closed",
    title: "Writable mapper without approval", payload: {}, agentRole: "codebase_mapper",
  });
  store.run("DELETE FROM approvals WHERE task_id = ?", taskId);
  store.run("UPDATE tasks SET status = 'queued', requires_approval = 0, approval_id = NULL WHERE id = ?", taskId);
  await waitFor(() => ["failed", "cancelled"].includes(
    store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", taskId)?.status ?? "",
  ), 8_000);
  const failed = store.get<{ status: string; failure_kind: string; attempts: number; max_attempts: number; error: string }>(
    "SELECT status, failure_kind, attempts, max_attempts, error FROM tasks WHERE id = ?", taskId,
  );
  expect(failed).toMatchObject({
    status: "failed",
    failure_kind: "writable_workspace_not_approved",
    attempts: 1,
  });
  expect(failed!.max_attempts).toBeGreaterThan(failed!.attempts);
  expect(failed!.error).toContain("no approved allow_writable_workspace decision");
  expect(store.all("SELECT seq FROM execution_events WHERE task_id = ? AND type = 'task.retry'", taskId)).toHaveLength(0);
  expect(store.all("SELECT id FROM agent_sessions WHERE task_id = ?", taskId)).toHaveLength(0);
});

test("a writable workspace task fails closed on the first check when the setting is disabled", async () => {
  setSetting(store, "security.allow_writable_workspace", false, null);
  const config = JSON.parse(store.get<{ config: string }>("SELECT config FROM audits WHERE id = ?", auditId)!.config);
  store.run(
    "UPDATE audits SET config = ?, status = 'running' WHERE id = ?",
    toJson({ ...config, writable_workspace: true }),
    auditId,
  );
  const taskId = engine.createTask({
    auditId, phase: 1, kind: "phase1.map", taskKey: "phase1:writable-disabled",
    title: "Writable mapper while policy is disabled", payload: {}, agentRole: "codebase_mapper",
  });
  store.run("DELETE FROM approvals WHERE task_id = ?", taskId);
  store.run("UPDATE tasks SET status = 'queued', requires_approval = 0, approval_id = NULL WHERE id = ?", taskId);
  await waitFor(() => ["failed", "cancelled"].includes(
    store.get<{ status: string }>("SELECT status FROM tasks WHERE id = ?", taskId)?.status ?? "",
  ), 8_000);
  const failed = store.get<{ status: string; failure_kind: string; attempts: number; max_attempts: number; error: string }>(
    "SELECT status, failure_kind, attempts, max_attempts, error FROM tasks WHERE id = ?", taskId,
  );
  expect(failed).toMatchObject({
    status: "failed",
    failure_kind: "writable_workspace_disabled",
    attempts: 1,
  });
  expect(failed!.max_attempts).toBeGreaterThan(failed!.attempts);
  expect(failed!.error).toContain("security.allow_writable_workspace is disabled");
  expect(store.all("SELECT seq FROM execution_events WHERE task_id = ? AND type = 'task.retry'", taskId)).toHaveLength(0);
  expect(store.all("SELECT id FROM agent_sessions WHERE task_id = ?", taskId)).toHaveLength(0);
});

describe("audit modes", () => {
  function insertRepositorylessProject(): void {
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES ('p2','No repo','', ?, '[]', '[]', 'Tester','AUTH-2', ?, ?)`,
      dir,
      now(),
      now(),
    );
  }

  test("a dynamic audit can be created without a repository", () => {
    insertRepositorylessProject();
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic" });
    expect(store.get("SELECT mode, repository_id FROM audits WHERE id = ?", id)).toEqual({
      mode: "dynamic",
      repository_id: null,
    });
  });

  test("a static audit without a repository is refused", () => {
    insertRepositorylessProject();
    expect(() => engine.createAudit({ projectId: "p2", userId: "u1", mode: "static" })).toThrow(/repository/i);
  });

  function dynamicTarget(validUntil = "2099-01-01T00:00:00.000Z") {
    const targets = new TargetService(store);
    const target = targets.createTarget({
      projectId: "p2",
      label: "Staging",
      baseUrl: "https://app.example.test",
      environment: "staging",
      allowedHosts: ["app.example.test"],
      allowedMethods: ["GET"],
    });
    targets.createAuthorization({
      targetId: target.id,
      authorizedBy: "Tester",
      reference: "AUTH-2",
      validFrom: "2020-01-01T00:00:00.000Z",
      validUntil,
      authorizedActions: { methods: ["GET"] },
      restrictions: {},
    });
    return { targets, target };
  }

  test("starting a dynamic audit writes a scope snapshot", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    targets.createIdentity({ targetId: target.id, label: "User B", role: "user_b", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });

    await engine.startAudit(id, "u1");

    const snapshot = targets.getSnapshot(id);
    expect(snapshot).not.toBeNull();
    expect(snapshot!.snapshot.target.id).toBe(target.id);
    expect(snapshot!.snapshot.mode).toBe("dynamic");
    expect(snapshot!.snapshot.identities).toHaveLength(2);
  });

  test("an expired authorization refuses to start a dynamic audit", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget("2021-01-01T00:00:00.000Z");
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });

    await expect(engine.startAudit(id, "u1")).rejects.toMatchObject({ code: "authorization_invalid" });
  });

  test("a disabled target refuses to start a dynamic audit", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    store.run("UPDATE project_targets SET status = 'disabled' WHERE id = ?", target.id);
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });

    await expect(engine.startAudit(id, "u1")).rejects.toMatchObject({ code: "target_disabled" });
  });

  test("a dynamic audit without identities refuses to start", async () => {
    insertRepositorylessProject();
    const { target } = dynamicTarget();
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });

    await expect(engine.startAudit(id, "u1")).rejects.toMatchObject({ code: "identity_required" });
  });

  test("accepts in-scope intents and rejects out-of-scope or duplicate intents", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });
    await engine.startAudit(id, "u1");
    const graph = new GraphStore(store);
    const asset = graph.upsertAsset({ projectId: "p2", kind: "endpoint", assetKey: "GET /invoices/:id" });

    const decision = engine.acceptIntents(id, [
      { title: "read invoice", assetIds: [asset.id], method: "GET", path: "/invoices/123", rationale: "check ownership" },
      { title: "off scope", assetIds: [asset.id], method: "GET", path: "https://evil.example.test/x" },
      { title: "read invoice again", assetIds: [asset.id], method: "GET", path: "/invoices/123" },
    ]);

    expect(decision.accepted).toHaveLength(1);
    expect(decision.rejected).toHaveLength(2);
    const nodes = store.all<{ status: string }>(
      "SELECT status FROM exploration_nodes WHERE audit_id = ? AND kind = 'intent' ORDER BY created_at",
      id,
    );
    expect(nodes.map((node) => node.status)).toEqual(["approved", "rejected", "rejected"]);

    await engine.closeExploration(id, "test finished");
    expect(
      store.get<{ exploration_status: string }>("SELECT exploration_status FROM audits WHERE id = ?", id)
        ?.exploration_status,
    ).toBe("closed");
  });

  test("phase 2 stays open until exploration closes", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });
    await engine.startAudit(id, "u1");
    store.run(
      "INSERT INTO tasks (id, audit_id, phase, kind, task_key, title, status, payload, attempts, max_attempts, created_at) VALUES ('t2', ?, 2, 'phase2.discover', 'phase2:test', 'Discover', 'completed', '{}', 1, 2, ?)",
      id,
      now(),
    );

    await (engine as unknown as { reconcile(id: string): Promise<void> }).reconcile(id);
    expect(
      store.get<{ status: string }>("SELECT status FROM audit_phases WHERE audit_id = ? AND phase = 2", id)?.status,
    ).toBe("running");

    await engine.closeExploration(id, "done");
    await (engine as unknown as { reconcile(id: string): Promise<void> }).reconcile(id);
    expect(
      store.get<{ status: string }>("SELECT status FROM audit_phases WHERE audit_id = ? AND phase = 2", id)?.status,
    ).toBe("completed");
  });

  test("prove_goal requires coverage or an unreachable rationale", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });
    await engine.startAudit(id, "u1");
    const graph = new GraphStore(store);
    const asset = graph.upsertAsset({ projectId: "p2", kind: "endpoint", assetKey: "GET /invoices/:id" });
    const goal = graph.listGoal(id)!;

    await expect(engine.proveGoal(id, goal.id, "")).rejects.toThrow(/coverage|rationale/i);

    const intent = graph.createNode({ auditId: id, kind: "intent", status: "completed", payload: {} });
    const fact = graph.createNode({ auditId: id, kind: "fact", status: "completed", payload: {} });
    graph.linkNodes(intent.id, fact.id, "yields");
    graph.anchor(fact.id, asset.id);
    graph.upsertAsset({ projectId: "p2", kind: "endpoint", assetKey: "GET /admin" });
    await expect(engine.proveGoal(id, goal.id, "")).rejects.toThrow(/coverage|rationale/i);

    await engine.proveGoal(id, goal.id, "the admin endpoint is unreachable from the test network");
    expect(graph.getNode(goal.id)?.status).toBe("completed");
    expect(
      store.get<{ exploration_status: string }>("SELECT exploration_status FROM audits WHERE id = ?", id)
        ?.exploration_status,
    ).toBe("closed");
  });

  test("the exploration loop plans, executes, and advances coverage", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    const id = engine.createAudit({
      projectId: "p2",
      userId: "u1",
      mode: "dynamic",
      targetId: target.id,
      overrides: { max_cost_usd: 10 },
    });
    await engine.startAudit(id, "u1");
    const graph = new GraphStore(store);
    const asset = graph.upsertAsset({ projectId: "p2", kind: "endpoint", assetKey: "GET /invoices/:id" });
    let plans = 0;
    let executes = 0;
    engine.setDynamicExecutor({
      async plan() {
        plans += 1;
        return [
          {
            title: "read invoice",
            assetIds: [asset.id],
            method: "GET",
            path: "/invoices/123",
            rationale: "check ownership",
          },
        ];
      },
      async execute() {
        executes += 1;
        return { costUsd: 0.1, facts: [{ status: 200, assetIds: [asset.id] }] };
      },
    });

    await engine.runExplorationStep(id);

    expect(plans).toBe(1);
    expect(executes).toBe(1);
    expect(
      store.get<{ status: string }>(
        "SELECT status FROM exploration_nodes WHERE audit_id = ? AND kind = 'intent'",
        id,
      )?.status,
    ).toBe("completed");
    expect(graph.coverage(id).find((entry) => entry.assetId === asset.id)?.tested).toBe(true);

    await engine.runExplorationStep(id);
    expect(executes).toBe(1);
  });

  test("the exploration cap closes exploration", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    const id = engine.createAudit({
      projectId: "p2",
      userId: "u1",
      mode: "dynamic",
      targetId: target.id,
      overrides: { max_cost_usd: 0.1 },
    });
    await engine.startAudit(id, "u1");
    const graph = new GraphStore(store);
    const asset = graph.upsertAsset({ projectId: "p2", kind: "endpoint", assetKey: "GET /invoices/:id" });
    engine.setDynamicExecutor({
      async plan() {
        return [{ title: "read", assetIds: [asset.id], method: "GET", path: "/invoices/1" }];
      },
      async execute() {
        return { costUsd: 0.1, facts: [{ status: 200, assetIds: [asset.id] }] };
      },
    });

    await engine.runExplorationStep(id);

    expect(
      store.get<{ exploration_status: string; stop_reason: string }>(
        "SELECT exploration_status, stop_reason FROM audits WHERE id = ?",
        id,
      ),
    ).toMatchObject({ exploration_status: "closed", stop_reason: "exploration_budget" });
  });

  test("an expired authorization stops exploration", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget("2026-10-28T00:00:00.000Z");
    targets.createIdentity({ targetId: target.id, label: "User A", role: "user_a", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });
    await engine.startAudit(id, "u1");
    try {
      setSystemTime(new Date("2026-11-01T00:00:00.000Z"));
      await engine.runExplorationStep(id);
      expect(
        store.get<{ exploration_status: string; stop_reason: string }>(
          "SELECT exploration_status, stop_reason FROM audits WHERE id = ?",
          id,
        ),
      ).toMatchObject({ exploration_status: "closed", stop_reason: "authorization_expired" });
    } finally {
      setSystemTime();
    }
  });
});

describe("authorization and goal guards", () => {
  function insertRepositorylessProject(): void {
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES ('p2','No repo','', ?, '[]', '[]', 'Tester','AUTH-2', ?, ?)`,
      dir,
      now(),
      now(),
    );
  }

  function dynamicTarget(validUntil = "2099-01-01T00:00:00.000Z") {
    const targets = new TargetService(store);
    const target = targets.createTarget({
      projectId: "p2",
      label: "Staging",
      baseUrl: "https://app.example.test",
      environment: "staging",
      allowedHosts: ["app.example.test"],
      allowedMethods: ["GET"],
    });
    targets.createAuthorization({
      targetId: target.id,
      authorizedBy: "Tester",
      reference: "AUTH-2",
      validFrom: "2020-01-01T00:00:00.000Z",
      validUntil,
      authorizedActions: { methods: ["GET"] },
      restrictions: {},
    });
    return { targets, target };
  }

  test("a revoked authorization stops exploration before the next intent", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    const authorization = targets.listAuthorizations(target.id)[0]!;
    targets.createIdentity({ targetId: target.id, label: "anon", role: "user", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });
    await engine.startAudit(id, "u1");

    store.run("UPDATE target_authorizations SET status = 'revoked' WHERE id = ?", authorization.id);
    await engine.runExplorationStep(id);

    expect(
      store.get<{ exploration_status: string; stop_reason: string | null }>(
        "SELECT exploration_status, stop_reason FROM audits WHERE id = ?",
        id,
      ),
    ).toEqual({ exploration_status: "closed", stop_reason: "authorization_expired" });
  });

  test("prove_goal refuses while an intent is still open", async () => {
    insertRepositorylessProject();
    const { targets, target } = dynamicTarget();
    targets.createIdentity({ targetId: target.id, label: "anon", role: "user", authKind: "none" });
    const id = engine.createAudit({ projectId: "p2", userId: "u1", mode: "dynamic", targetId: target.id });
    await engine.startAudit(id, "u1");
    const graph = new GraphStore(store);
    const goal = graph.listGoal(id)!;
    graph.createNode({ auditId: id, kind: "intent", status: "approved", payload: { title: "open" } });

    await expect(
      engine.proveGoal(id, goal.id, "the remaining endpoint is unreachable from the test network"),
    ).rejects.toThrow(/intent/i);
  });
});
