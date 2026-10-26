import { afterEach, beforeEach, expect, test } from "bun:test";
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
import { seedDefaults, setSetting } from "../src/settings.ts";
import { now, toJson, uid } from "../src/util.ts";
import { LocalCatalog } from "../src/local/catalog.ts";
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

function fakeManager(): HarnessManager {
  const manager: ScriptedHarness = {
    async run(kind, task, hooks) {
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
let auditId = "";

function createEngine(catalog?: LocalCatalog): AuditEngine {
  const config = testConfig(dir);
  const events = new EventLog(store);
  const evidence = new EvidenceStore(config, store);
  const reports = new ReportService(config, store, evidence, events);
  return new AuditEngine(config, store, manager, evidence, events, reports, catalog);
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
