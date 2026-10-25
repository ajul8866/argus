import { join } from "node:path";
import type { Config } from "../config.ts";
import { KeyedSerialQueue } from "../concurrency.ts";
import { PHASE_NAMES, WORKSPACE_DIR } from "../config.ts";
import type { Store } from "../db/index.ts";
import { EventLog } from "../events.ts";
import type { HarnessManager } from "../harness/manager.ts";
import type { HarnessKind, HarnessRunResult } from "../harness/types.ts";
import { agentDefinition, getSetting, harnessConfig } from "../settings.ts";
import type { AgentDefinition } from "../settings.ts";
import type { Scope } from "../util.ts";
import {
  AppError,
  clamp,
  extractJson,
  now,
  parseJson,
  sha256,
  toJson,
  truncate,
  uid,
} from "../util.ts";
import { assertAuthorizedRoot, createWorkspace, verifyQuote } from "../repo/workspace.ts";
import { redactSecrets } from "../security/redact.ts";
import { evaluateEvidence } from "./evidence-gate.ts";
import type { Inventory } from "../repo/inventory.ts";
import { inventoryForAgent, inventorySummary } from "../repo/inventory.ts";
import {
  mapperPrompt,
  mapperSystem,
  researcherPrompt,
  researcherSystem,
  retestPrompt,
  retestSystem,
  validatorPrompt,
  validatorSystem,
} from "./prompts.ts";
import type { Candidate, ConfirmationResult, DiscoveryResult, MapResult, RetestResult } from "./schemas.ts";
import type { JsonSchema } from "./schemas.ts";
import {
  CONFIRMATION_SCHEMA,
  DISCOVERY_SCHEMA,
  MAP_SCHEMA,
  RETEST_SCHEMA,
  validateResult,
} from "./schemas.ts";
import type { EvidenceStore } from "./evidence.ts";
import type { ReportService } from "../reports/generator.ts";
import { REPORT_FORMATS } from "../reports/generator.ts";
import type { LocalCatalog } from "../local/catalog.ts";
import type { SessionResources } from "../local/types.ts";
import { localResourcePrompt } from "../harness/resources.ts";

type AuditRow = {
  id: string;
  project_id: string;
  repository_id: string;
  status: string;
  current_phase: number;
  config: string;
  created_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
};

type ProjectRow = {
  id: string;
  name: string;
  source_path: string;
  scope_include: string;
  scope_exclude: string;
  authorization_ref: string;
  authorized_by: string;
  max_concurrent_agents: number | null;
};

type RepositoryRow = {
  id: string;
  project_id: string;
  path: string;
  commit_sha: string | null;
  branch: string | null;
  inventory: string;
  languages: string;
  frameworks: string;
  file_count: number;
};

type TaskRow = {
  id: string;
  audit_id: string;
  phase: number;
  kind: string;
  task_key: string;
  title: string;
  status: string;
  priority: number;
  payload: string;
  result: string | null;
  error: string | null;
  failure_kind: string | null;
  agent_role: string | null;
  harness: HarnessKind | null;
  model: string | null;
  attempts: number;
  max_attempts: number;
  requires_approval: number;
  approval_id: string | null;
  agent_session_id: string | null;
  deadline_at: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

type SessionRow = {
  id: string;
  audit_id: string;
  task_id: string | null;
  role: string;
  harness: string;
  model: string | null;
  status: string;
  workspace: string;
  sandbox_mode: string;
  harness_session_ref: string | null;
  pid: number | null;
  exit_code: number | null;
  usage: string | null;
  metadata: string | null;
  started_at: string;
  ended_at: string | null;
  error: string | null;
};

type CandidateRow = {
  id: string;
  audit_id: string;
  area_id: string;
  discovery_task_id: string;
  discovery_session_id: string;
  title: string;
  category: string;
  cwe: string | null;
  severity: string;
  status: string;
  finding_id: string | null;
  payload: string;
  created_at: string;
};

type VerificationRow = {
  id: string;
  audit_id: string;
  candidate_id: string | null;
  finding_id: string | null;
  kind: string;
  agent_session_id: string;
  discovery_session_id: string;
  verdict: string;
  rationale: string;
  evidence_check: string;
  payload: string;
  created_at: string;
};

type FindingRow = {
  id: string;
  code: string;
  audit_id: string;
  project_id: string;
  candidate_id: string | null;
  title: string;
  category: string;
  cwe: string | null;
  severity: string;
  status: string;
  repository_commit: string | null;
  files: string;
  root_cause: string;
  preconditions: string;
  reproduction: string;
  expected: string;
  observed: string;
  impact: string;
  remediation: string;
  discovery_session_id: string | null;
  verification_session_id: string | null;
  retest_session_id: string | null;
  verification_decision: string | null;
  retest_decision: string | null;
  created_at: string;
  updated_at: string;
};

const TERMINAL_TASK_STATES = new Set(["completed", "failed", "cancelled", "blocked"]);
const DETERMINISTIC_TASK_KINDS: Record<string, true> = { "phase4.persist": true, "phase6.report": true };

const TASK_SCHEMAS: Record<string, JsonSchema> = {
  "phase1.map": MAP_SCHEMA,
  "phase2.discover": DISCOVERY_SCHEMA,
  "phase3.confirm": CONFIRMATION_SCHEMA,
  "phase5.reverify": RETEST_SCHEMA,
};

const RESULT_SESSION_STATUS: Record<string, SessionRow["status"]> = {
  completed: "completed",
  timeout: "timeout",
  cancelled: "cancelled",
  failed: "failed",
};

export class AuditEngine {
  private timer: ReturnType<typeof setInterval> | null = null;
  private ticking = false;
  private readonly running = new Map<string, { auditId: string; controller: AbortController }>();
  private readonly transitions = new KeyedSerialQueue();
  private stopping = false;

  constructor(
    private readonly config: Config,
    private readonly store: Store,
    private readonly manager: HarnessManager,
    private readonly evidence: EvidenceStore,
    private readonly events: EventLog,
    private readonly reports: ReportService,
    private readonly catalog?: LocalCatalog,
  ) {}

  start(): void {
    this.recoverAfterRestart();
    this.timer = setInterval(() => void this.tick(), 1_500);
  }

  async stop(): Promise<void> {
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    for (const entry of this.running.values()) entry.controller.abort();
    await Promise.race([
      Promise.allSettled([...this.running.keys()].map((runId) => this.manager.cleanupRun(runId))),
      new Promise((resolvePromise) => setTimeout(resolvePromise, 3_000)),
    ]);
  }

  private recoverAfterRestart(): void {
    const timestamp = now();
    const sessions = this.store.all<SessionRow & { audit_status: string }>(
      `SELECT s.*, a.status AS audit_status FROM agent_sessions s JOIN audits a ON a.id = s.audit_id
       WHERE s.status IN ('starting','running')`,
    );
    for (const session of sessions) {
      this.store.run(
        "UPDATE agent_sessions SET status = ?, ended_at = ?, error = ? WHERE id = ?",
        ["cancelling", "cancelled"].includes(session.audit_status) ? "cancelled" : "failed",
        timestamp,
        "Interrupted by an Argus server restart",
        session.id,
      );
    }
    const tasks = this.store.all<TaskRow & { audit_status: string }>(
      `SELECT t.*, a.status AS audit_status FROM tasks t JOIN audits a ON a.id = t.audit_id
       WHERE t.status IN ('running','queued','waiting_approval')`,
    );
    for (const task of tasks) {
      if (["cancelling", "cancelled"].includes(task.audit_status)) {
        this.finishTaskFailure(task.id, "cancelled", "Audit cancellation recovered after a server restart");
        continue;
      }
      if (!["running", "queued"].includes(task.audit_status)) {
        this.finishTaskFailure(task.id, "audit_closed", `Audit was ${task.audit_status} when the server restarted`);
        continue;
      }
      if (task.status !== "running") continue;
      this.finishTaskFailure(
        task.id,
        "server_restart",
        task.attempts < task.max_attempts && task.audit_status === "running"
          ? "Interrupted by an Argus server restart; queued for a fresh attempt"
          : "Interrupted by an Argus server restart; no further attempt is available",
      );
    }
    const audits = this.store.all<{ id: string }>(
      "SELECT id FROM audits WHERE status IN ('running','cancelling','queued')",
    );
    for (const audit of audits) {
      const auditRow = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", audit.id);
      if (auditRow?.status === "queued") continue;
      this.events.append({
        auditId: audit.id,
        type: "system.recovered",
        payload: {
          sessions_interrupted: sessions.filter((session) => session.audit_id === audit.id).length,
          tasks_requeued: tasks.filter((task) =>
            task.audit_id === audit.id && task.status === "running" &&
            task.audit_status === "running" && task.attempts < task.max_attempts,
          ).length,
          message: "Server restarted; incomplete work was recovered from durable state.",
        },
      });
    }
  }

  /** Abort every in-flight task belonging to one audit. */
  private abortAuditRuns(auditId: string): void {
    for (const entry of this.running.values()) {
      if (entry.auditId === auditId) entry.controller.abort();
    }
  }

  /** Cancel a deterministic task whose audit closed before it could run. */
  private cancelIfAuditClosed(task: TaskRow, reason: string): boolean {
    const audit = this.store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", task.audit_id);
    if (audit && !["cancelling", "cancelled"].includes(audit.status)) return false;
    this.store.run(
      "UPDATE tasks SET status = 'cancelled', finished_at = ?, error = ? WHERE id = ?",
      now(),
      reason,
      task.id,
    );
    return true;
  }

  private async tick(): Promise<void> {
    if (this.ticking || this.stopping) return;
    this.ticking = true;
    try {
      const audits = this.store.all<{ id: string; status: string }>(
        "SELECT id, status FROM audits WHERE status IN ('running','cancelling') ORDER BY created_at",
      );
      for (const audit of audits) {
        await this.reconcile(audit.id).catch((error) => {
          this.events.append({
            auditId: audit.id,
            type: "system.error",
            payload: { message: `Scheduler reconcile failed: ${String(error)}` },
          });
        });
        if (audit.status === "running") this.schedule(audit.id);
      }
    } finally {
      this.ticking = false;
    }
  }

  private withAuditLock<T>(auditId: string, fn: () => Promise<T> | T): Promise<T> {
    return this.transitions.run(auditId, fn);
  }

  private context(auditId: string): {
    audit: AuditRow;
    project: ProjectRow;
    repository: RepositoryRow;
    auditConfig: Record<string, unknown>;
    inventory: Inventory;
    scope: Scope;
  } {
    const audit = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", auditId);
    if (!audit) throw new AppError(404, "audit_not_found", "Audit not found");
    const project = this.store.get<ProjectRow>("SELECT * FROM projects WHERE id = ?", audit.project_id);
    if (!project) throw new AppError(404, "project_not_found", "Project not found");
    const repository = this.store.get<RepositoryRow>(
      "SELECT * FROM repositories WHERE id = ?",
      audit.repository_id,
    );
    if (!repository) throw new AppError(404, "repository_not_found", "Repository not found");
    const auditConfig = parseJson<Record<string, unknown>>(audit.config, {});
    const configuredScope = auditConfig.scope as { include?: string[]; exclude?: string[] } | undefined;
    const scope = {
      include:
        configuredScope?.include && configuredScope.include.length > 0
          ? configuredScope.include
          : parseJson<string[]>(project.scope_include, ["**/*"]),
      exclude:
        configuredScope?.exclude && configuredScope.exclude.length > 0
          ? configuredScope.exclude
          : parseJson<string[]>(project.scope_exclude, []),
    };
    return {
      audit,
      project,
      repository,
      auditConfig,
      inventory: parseJson<Inventory>(repository.inventory, {
        files: [],
        skipped: [],
        languages: {},
        frameworks: [],
        endpoints: [],
        auth_boundaries: [],
        dependency_graph: [],
        entrypoints: [],
        total_bytes: 0,
        truncated: false,
      }),
      scope,
    };
  }

  createAudit(input: {
    projectId: string;
    repositoryId?: string;
    userId: string | null;
    overrides?: Record<string, unknown>;
  }): string {
    const project = this.store.get<ProjectRow>("SELECT * FROM projects WHERE id = ?", input.projectId);
    if (!project) throw new AppError(404, "project_not_found", "Project not found");
    const repository = input.repositoryId
      ? this.store.get<RepositoryRow>("SELECT * FROM repositories WHERE id = ? AND project_id = ?", input.repositoryId, input.projectId)
      : this.store.get<RepositoryRow>(
          "SELECT * FROM repositories WHERE project_id = ? ORDER BY imported_at DESC LIMIT 1",
          input.projectId,
        );
    if (!repository) {
      throw new AppError(
        400,
        "repository_required",
        "Import an authorized repository for this project before starting an audit",
      );
    }
    const writableWorkspace = input.overrides?.writable_workspace === true;
    if (writableWorkspace && !getSetting(this.store, "security.allow_writable_workspace", false)) {
      throw new AppError(
        409,
        "writable_workspace_disabled",
        "security.allow_writable_workspace is disabled. An administrator must enable it with explicit confirmation before an audit can request a writable workspace.",
      );
    }
    const maxAreas = clamp(
      Number(input.overrides?.max_areas ?? getSetting(this.store, "audit.max_areas", 4)),
      1,
      8,
    );
    const config = {
      max_areas: maxAreas,
      max_candidates_per_area: clamp(
        Number(input.overrides?.max_candidates_per_area ?? getSetting(this.store, "audit.max_candidates_per_area", 4)),
        1,
        8,
      ),
      max_confirmations: clamp(
        Number(input.overrides?.max_confirmations ?? getSetting(this.store, "audit.max_confirmations", 12)),
        0,
        30,
      ),
      max_reverifications: clamp(
        Number(input.overrides?.max_reverifications ?? getSetting(this.store, "audit.max_reverifications", 12)),
        0,
        30,
      ),
      max_concurrent_agents: clamp(
        Number(input.overrides?.max_concurrent_agents ?? getSetting(this.store, "audit.max_concurrent_agents", this.config.maxConcurrentAgents)),
        1,
        12,
      ),
      require_distinct_harness_for_retest: Boolean(
        input.overrides?.require_distinct_harness_for_retest ??
          getSetting(this.store, "audit.require_distinct_harness_for_retest", true),
      ),
      writable_workspace: writableWorkspace,
      max_cost_usd: input.overrides?.max_cost_usd ? Number(input.overrides.max_cost_usd) : null,
      harness_overrides:
        input.overrides?.harness_overrides && typeof input.overrides.harness_overrides === "object"
          ? input.overrides.harness_overrides
          : {},
      scope: {
        include: parseJson<string[]>(project.scope_include, ["**/*"]),
        exclude: parseJson<string[]>(project.scope_exclude, []),
      },
    };
    const id = uid();
    const timestamp = now();
    this.store.transaction(() => {
      this.store.run(
        `INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, created_by, created_at)
         VALUES (?, ?, ?, 'queued', 1, ?, ?, ?)`,
        id,
        input.projectId,
        repository.id,
        toJson(config),
        input.userId,
        timestamp,
      );
      for (let phase = 1; phase <= 6; phase += 1) {
        this.store.run(
          "INSERT INTO audit_phases (audit_id, phase, name, status) VALUES (?, ?, ?, 'pending')",
          id,
          phase,
          PHASE_NAMES[phase - 1]!,
        );
      }
    });
    this.events.append({
      auditId: id,
      type: "audit.created",
      payload: {
        project: project.name,
        repository: repository.id,
        commit: repository.commit_sha,
        config,
      },
    });
    return id;
  }

  async startAudit(auditId: string, userId: string | null): Promise<void> {
    await this.withAuditLock(auditId, async () => {
      const audit = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", auditId);
      if (!audit) throw new AppError(404, "audit_not_found", "Audit not found");
      if (audit.status !== "queued") {
        throw new AppError(409, "audit_not_startable", `Audit is ${audit.status} and cannot be started`);
      }
      this.store.transaction(() => {
        this.store.run(
          "UPDATE audits SET status = 'running', started_at = COALESCE(started_at, ?), finished_at = NULL, error = NULL, current_phase = 1 WHERE id = ?",
          now(),
          auditId,
        );
        this.store.run(
          "UPDATE audit_phases SET status = 'pending', started_at = NULL, finished_at = NULL, summary = NULL WHERE audit_id = ?",
          auditId,
        );
      });
      this.events.append({ auditId, type: "audit.started", payload: { by: userId } });
      this.createTask({
        auditId,
        phase: 1,
        kind: "phase1.map",
        taskKey: "phase1:map",
        title: "Phase 1 — Map codebase and define assessment areas",
        payload: {},
        agentRole: "codebase_mapper",
        priority: 100,
      });
    });
    await this.reconcile(auditId);
    this.schedule(auditId);
  }

  async cancelAudit(auditId: string, userId: string | null): Promise<void> {
    const audit = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", auditId);
    if (!audit) throw new AppError(404, "audit_not_found", "Audit not found");
    if (["completed", "completed_with_errors", "failed", "cancelled"].includes(audit.status)) {
      throw new AppError(409, "audit_not_running", `Audit is already ${audit.status}`);
    }
    this.store.run("UPDATE audits SET status = 'cancelling', error = ? WHERE id = ?", "Cancellation requested", auditId);
    const pending = this.store.all<TaskRow>(
      "SELECT * FROM tasks WHERE audit_id = ? AND status IN ('queued','waiting_approval')",
      auditId,
    );
    for (const task of pending) this.finishTaskFailure(task.id, "cancelled", "Audit cancelled by operator");
    this.abortAuditRuns(auditId);
    this.events.append({ auditId, type: "audit.cancelling", payload: { by: userId } });
    await this.reconcile(auditId);
  }

  cancelTask(taskId: string, actor: string | null): void {
    const task = this.store.get<TaskRow>("SELECT * FROM tasks WHERE id = ?", taskId);
    if (!task) throw new AppError(404, "task_not_found", "Task not found");
    if (TERMINAL_TASK_STATES.has(task.status)) {
      throw new AppError(409, "task_terminal", `Task is already ${task.status}`);
    }
    if (task.status === "running") {
      this.running.get(task.id)?.controller.abort();
    } else {
      this.finishTaskFailure(task.id, "cancelled", `Cancelled by ${actor ?? "operator"}`);
    }
    this.events.append({
      auditId: task.audit_id,
      taskId: task.id,
      type: "task.cancel_requested",
      payload: { by: actor },
    });
  }

  async requestRetest(findingId: string, userId: string | null): Promise<string> {
    const finding = this.store.get<FindingRow>("SELECT * FROM findings WHERE id = ?", findingId);
    if (!finding) throw new AppError(404, "finding_not_found", "Finding not found");
    const audit = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", finding.audit_id);
    if (!audit) throw new AppError(404, "audit_not_found", "Audit not found");
    if (!["running", "completed", "completed_with_errors", "cancelled", "failed"].includes(audit.status)) {
      throw new AppError(409, "audit_not_retestable", `Audit is ${audit.status}`);
    }
    const suffix = this.store.all<{ id: string }>(
      "SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase5.reverify' AND task_key LIKE ?",
      finding.audit_id,
      `phase5:finding:${finding.id}%`,
    ).length;
    const task = this.createTask({
      auditId: finding.audit_id,
      phase: 5,
      kind: "phase5.reverify",
      taskKey: `phase5:finding:${finding.id}:manual:${suffix + 1}`,
      title: `Phase 5 — Manual retest ${finding.code}`,
      payload: { finding_id: finding.id },
      agentRole: "retest_auditor",
      priority: 50,
    });
    this.store.transaction(() => {
      this.store.run(
        "UPDATE findings SET status = 'confirmed', retest_decision = NULL, updated_at = ? WHERE id = ?",
        now(),
        findingId,
      );
      if (audit.status !== "running") {
        this.store.run(
          "UPDATE audits SET status = 'running', finished_at = NULL, current_phase = 5, error = NULL WHERE id = ?",
          finding.audit_id,
        );
        this.store.run(
          "UPDATE audit_phases SET status = 'running', finished_at = NULL WHERE audit_id = ? AND phase = 5",
          finding.audit_id,
        );
      }
    });
    this.events.append({
      auditId: finding.audit_id,
      type: "finding.retest_requested",
      payload: { finding_id: finding.id, code: finding.code, task_id: task, by: userId },
      taskId: task,
    });
    await this.reconcile(finding.audit_id);
    this.schedule(finding.audit_id);
    return task;
  }

  decideApproval(approvalId: string, approved: boolean, userId: string | null, reason: string): void {
    const approval = this.store.get<{
      id: string;
      audit_id: string | null;
      task_id: string | null;
      status: string;
      action: string;
    }>("SELECT * FROM approvals WHERE id = ?", approvalId);
    if (!approval) throw new AppError(404, "approval_not_found", "Approval not found");
    if (approval.status !== "pending") throw new AppError(409, "approval_decided", "Approval already decided");
    this.store.transaction(() => {
      this.store.run(
        "UPDATE approvals SET status = ?, decided_by = ?, reason = ?, decided_at = ? WHERE id = ?",
        approved ? "approved" : "denied",
        userId,
        reason,
        now(),
        approvalId,
      );
      if (approval.task_id && approved) {
        const pending = this.store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM approvals WHERE task_id = ? AND status = 'pending'",
          approval.task_id,
        )?.count ?? 0;
        if (pending === 0) {
          this.store.run(
            "UPDATE tasks SET status = 'queued' WHERE id = ? AND status = 'waiting_approval'",
            approval.task_id,
          );
        }
      }
    });
    if (approval.task_id && !approved) {
      this.store.run(
        "UPDATE approvals SET status = 'denied', reason = COALESCE(reason, ?), decided_at = COALESCE(decided_at, ?) WHERE task_id = ? AND status = 'pending'",
        `Approval denied by ${userId ?? "administrator"}`,
        now(),
        approval.task_id,
      );
      this.finishTaskFailure(approval.task_id, "cancelled", `Approval denied by ${userId ?? "administrator"}`);
    }
    if (approval.audit_id) {
      this.events.append({
        auditId: approval.audit_id,
        taskId: approval.task_id,
        type: approved ? "approval.approved" : "approval.denied",
        payload: { approval_id: approvalId, action: approval.action, reason, by: userId },
      });
      this.schedule(approval.audit_id);
      void this.reconcile(approval.audit_id);
    }
  }

  createTask(options: {
    auditId: string;
    phase: number;
    kind: string;
    taskKey: string;
    title: string;
    payload: Record<string, unknown>;
    agentRole: string | null;
    priority?: number;
    dependsOn?: string[];
    maxAttempts?: number;
    harness?: HarnessKind | null;
    model?: string | null;
    requiresApproval?: boolean;
  }): string {
    const existing = this.store.get<{ id: string }>(
      "SELECT id FROM tasks WHERE audit_id = ? AND task_key = ?",
      options.auditId,
      options.taskKey,
    );
    if (existing) return existing.id;
    const timestamp = now();
    const id = uid();
    let harness: HarnessKind | null = options.harness ?? null;
    let model: string | null = options.model ?? null;
    let maxAttempts = options.maxAttempts ?? 2;
    let requiresApproval = options.requiresApproval ?? false;
    const approvalRequests: Array<{ action: string; scope: string }> = [];
    if (options.agentRole) {
      const definition = agentDefinition(this.store, options.agentRole);
      const audit = this.store.get<{ config: string }>("SELECT config FROM audits WHERE id = ?", options.auditId);
      const auditConfig = parseJson<Record<string, unknown>>(audit?.config ?? "{}", {});
      const overrides = (auditConfig.harness_overrides ?? {}) as Record<
        string,
        { harness?: HarnessKind; model?: string | null }
      >;
      const override = overrides[options.agentRole] ?? {};
      harness = override.harness ?? definition.harness;
      model = override.model !== undefined ? override.model : definition.model;
      maxAttempts = definition.max_retries + 1;
      if (
        definition.role === "retest_auditor" &&
        auditConfig.require_distinct_harness_for_retest === true &&
        typeof options.payload.finding_id === "string"
      ) {
        const finding = this.store.get<{
          discovery_session_id: string | null;
          verification_session_id: string | null;
        }>("SELECT discovery_session_id, verification_session_id FROM findings WHERE id = ?", options.payload.finding_id);
        if (finding?.discovery_session_id && finding.verification_session_id) {
          const harnesses = this.store.all<{ harness: string }>(
            "SELECT harness FROM agent_sessions WHERE id IN (?, ?)",
            finding.discovery_session_id,
            finding.verification_session_id,
          );
          const prior = new Set(harnesses.map((row) => row.harness));
          if (prior.size === 1 && prior.has(harness)) {
            const alternative: HarnessKind = harness === "pi" ? "claude-code" : "pi";
            const alternateHarness = this.store.get<{ status: string }>(
              "SELECT status FROM harnesses WHERE kind = ?",
              alternative,
            );
            if (alternateHarness?.status === "ready") {
              harness = alternative;
              model = harnessConfig(this.store, alternative).model;
              this.events.append({
                auditId: options.auditId,
                type: "harness.separation_applied",
                payload: {
                  role: definition.role,
                  finding_id: options.payload.finding_id,
                  from: definition.harness,
                  to: alternative,
                  reason: "require_distinct_harness_for_retest",
                },
              });
            } else {
              this.events.append({
                auditId: options.auditId,
                type: "harness.separation_unavailable",
                payload: {
                  role: definition.role,
                  finding_id: options.payload.finding_id,
                  configured: harness,
                  unavailable_alternative: alternative,
                  message: "The configured retest harness was kept; fresh-session independence is still enforced.",
                },
              });
            }
          }
        }
      }
      const shellTools = definition.allow_shell || definition.allowed_tools.some((tool) => /^(bash|Bash)$/.test(tool));
      if (shellTools) {
        const allowShell = Boolean(getSetting(this.store, "security.allow_shell_tools", false));
        if (!allowShell) {
          throw new AppError(
            409,
            "shell_tools_disabled",
            `Agent ${definition.role} requests shell tools, but security.allow_shell_tools is disabled. Enable it explicitly and approve the task.`,
          );
        }
        if (Boolean(getSetting(this.store, "security.require_approval_for_shell", true))) {
          requiresApproval = true;
          approvalRequests.push({
            action: "allow_shell_tools",
            scope: `Task ${id} (${options.kind}) requests shell tool execution`,
          });
        }
      }
      if (DETERMINISTIC_TASK_KINDS[options.kind] !== true && auditConfig.writable_workspace === true) {
        approvalRequests.push({
          action: "allow_writable_workspace",
          scope: `Task ${id} (${options.kind}) requests a writable audit workspace`,
        });
      }
    }
    if (requiresApproval && approvalRequests.length === 0) {
      approvalRequests.push({
        action: "allow_shell_tools",
        scope: `Task ${id} (${options.kind}) requests task-level approval`,
      });
    }
    requiresApproval = requiresApproval || approvalRequests.length > 0;
    this.store.transaction(() => {
      this.store.run(
        `INSERT INTO tasks (id, audit_id, phase, kind, task_key, title, status, priority, payload, agent_role, harness, model, attempts, max_attempts, requires_approval, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
        id,
        options.auditId,
        options.phase,
        options.kind,
        options.taskKey,
        options.title,
        requiresApproval ? "waiting_approval" : "queued",
        options.priority ?? 0,
        toJson(options.payload),
        options.agentRole,
        harness,
        model,
        maxAttempts,
        requiresApproval ? 1 : 0,
        timestamp,
      );
      for (const dependency of options.dependsOn ?? []) {
        this.store.run(
          "INSERT OR IGNORE INTO task_dependencies (task_id, depends_on_task_id) VALUES (?, ?)",
          id,
          dependency,
        );
      }
      if (requiresApproval) {
        let primaryApprovalId: string | null = null;
        for (const request of approvalRequests) {
          const approvalId = uid();
          this.store.run(
            `INSERT INTO approvals (id, audit_id, task_id, action, scope, status, requested_by, created_at)
             VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?)`,
            approvalId,
            options.auditId,
            id,
            request.action,
            request.scope,
            timestamp,
          );
          primaryApprovalId = primaryApprovalId ?? approvalId;
        }
        this.store.run("UPDATE tasks SET approval_id = ? WHERE id = ?", primaryApprovalId, id);
      }
    });
    this.events.append({
      auditId: options.auditId,
      taskId: id,
      type: requiresApproval ? "approval.requested" : "task.queued",
      payload: {
        kind: options.kind,
        title: options.title,
        phase: options.phase,
        harness,
        model,
        agent_role: options.agentRole,
      },
    });
    return id;
  }

  private schedule(auditId: string): void {
    if (this.stopping) return;
    const audit = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", auditId);
    if (!audit || audit.status !== "running") return;
    const auditConfig = parseJson<Record<string, unknown>>(audit.config, {});
    const globalLimit = clamp(
      Number(getSetting(this.store, "audit.max_concurrent_agents", this.config.maxConcurrentAgents)),
      1,
      16,
    );
    const project = this.store.get<ProjectRow>("SELECT * FROM projects WHERE id = ?", audit.project_id);
    const auditLimit = clamp(
      Number(auditConfig.max_concurrent_agents ?? globalLimit),
      1,
      12,
    );
    const projectLimit = project?.max_concurrent_agents ?? auditLimit;
    const limit = Math.min(globalLimit, auditLimit, projectLimit, 16);
    if (this.running.size >= globalLimit) return;
    const runningForAudit = this.store.get<{ count: number }>(
      "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND status = 'running'",
      auditId,
    )?.count ?? 0;
    let slots = Math.min(limit - runningForAudit, globalLimit - this.running.size);
    if (slots <= 0) return;
    const candidates = this.store.all<TaskRow>(
      `SELECT t.* FROM tasks t
       WHERE t.audit_id = ? AND t.status = 'queued'
         AND NOT EXISTS (
           SELECT 1 FROM task_dependencies d
           JOIN tasks dep ON dep.id = d.depends_on_task_id
           WHERE d.task_id = t.id AND dep.status != 'completed'
         )
       ORDER BY t.phase ASC, t.priority DESC, t.created_at ASC
       LIMIT 50`,
      auditId,
    );
    const roleLimits = new Map<string, number>(
      this.store
        .all<{ role: string; concurrency_limit: number }>("SELECT role, concurrency_limit FROM agent_defs")
        .map((row) => [row.role, row.concurrency_limit]),
    );
    const runningByRole = new Map<string, number>(
      this.store
        .all<{ agent_role: string; count: number }>(
          "SELECT agent_role, COUNT(*) AS count FROM tasks WHERE status = 'running' AND agent_role IS NOT NULL GROUP BY agent_role",
        )
        .map((row) => [row.agent_role, row.count]),
    );
    for (const task of candidates) {
      if (slots <= 0) break;
      const role = task.agent_role;
      if (role) {
        const roleLimit = roleLimits.get(role);
        if (roleLimit !== undefined && (runningByRole.get(role) ?? 0) >= roleLimit) continue;
      }
      const claimed = this.store.changes(
        `UPDATE tasks SET status = 'running', started_at = ?, attempts = attempts + 1 WHERE id = ? AND status = 'queued'`,
        now(),
        task.id,
      );
      if (claimed === 0) continue;
      if (role) runningByRole.set(role, (runningByRole.get(role) ?? 0) + 1);
      const controller = new AbortController();
      this.running.set(task.id, { auditId, controller });
      slots -= 1;
      this.events.append({
        auditId,
        taskId: task.id,
        type: "task.started",
        payload: {
          kind: task.kind,
          title: task.title,
          attempt: task.attempts + 1,
          max_attempts: task.max_attempts,
          harness: task.harness,
          model: task.model,
          agent_role: task.agent_role,
        },
      });
      void this.executeTask(task.id, controller.signal)
        .catch((error) => {
          this.events.append({
            auditId,
            taskId: task.id,
            type: "system.error",
            payload: { message: `Task execution crashed: ${String(error)}` },
          });
          this.finishTaskFailure(task.id, "internal", String(error));
        })
        .finally(() => {
          this.running.delete(task.id);
          void this.reconcile(auditId);
        });
    }
  }

  private async executeTask(taskId: string, signal: AbortSignal): Promise<void> {
    const task = this.store.get<TaskRow>("SELECT * FROM tasks WHERE id = ?", taskId);
    if (!task) return;
    const audit = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", task.audit_id);
    if (!audit) return;
    if (audit.status === "cancelling" || audit.status === "cancelled") {
      this.store.run(
        "UPDATE tasks SET status = 'cancelled', finished_at = ?, error = ? WHERE id = ?",
        now(),
        "Audit was cancelled before the task started",
        task.id,
      );
      return;
    }
    if (task.kind === "phase4.persist") {
      await this.runDeterministicTask(task);
      return;
    }
    if (task.kind === "phase6.report") {
      await this.runReportTask(task);
      return;
    }
    await this.runAgentTask(task, audit, signal);
  }

  private async runDeterministicTask(task: TaskRow): Promise<void> {
    try {
      if (this.cancelIfAuditClosed(task, "Audit was cancelled before deterministic persistence ran")) return;
      const payload = parseJson<Record<string, unknown>>(task.payload, {});
      const result = await this.persistFinding(task, payload);
      this.completeTask(task.id, result);
    } catch (error) {
      this.finishTaskFailure(task.id, "internal", error instanceof Error ? error.message : String(error));
    }
  }

  private async runReportTask(task: TaskRow): Promise<void> {
    try {
      if (this.cancelIfAuditClosed(task, "Audit was cancelled before report generation")) return;
      const generated = await this.reports.generate(task.audit_id, REPORT_FORMATS, "phase6");
      if (generated.length !== REPORT_FORMATS.length) {
        throw new Error(`Only ${generated.length}/${REPORT_FORMATS.length} report formats were generated`);
      }
      this.completeTask(task.id, {
        reports: generated.map((entry) => ({ id: entry.id, format: entry.format, sha256: entry.sha256, size: entry.size })),
      });
    } catch (error) {
      this.finishTaskFailure(task.id, "internal", error instanceof Error ? error.message : String(error));
    }
  }

  private toolsForHarness(tools: string[], harness: HarnessKind): string[] {
    const toClaude: Record<string, string> = {
      read: "Read",
      grep: "Grep",
      find: "Glob",
      ls: "LS",
      bash: "Bash",
    };
    const toPi: Record<string, string> = {
      Read: "read",
      Grep: "grep",
      Glob: "find",
      LS: "ls",
      Bash: "bash",
    };
    return tools.map((tool) => (harness === "claude-code" ? toClaude[tool] ?? tool : toPi[tool] ?? tool));
  }

  private async runAgentTask(task: TaskRow, audit: AuditRow, signal: AbortSignal): Promise<void> {
    const ctx = this.context(task.audit_id);
    const definition = agentDefinition(this.store, task.agent_role!);
    const harness = task.harness ?? definition.harness;
    const supportsRole = definition.enabled;
    if (!supportsRole) {
      this.finishTaskFailure(task.id, "internal", `Agent role ${definition.role} is disabled`);
      return;
    }
    let writableWorkspace: boolean;
    try {
      writableWorkspace = this.resolveWritableWorkspace(task, ctx.auditConfig);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.finishTaskFailure(task.id, "writable_workspace_denied", message);
      return;
    }
    const sessionId = uid();
    const timestamp = now();
    const workspace = join(WORKSPACE_DIR(this.config), task.audit_id, sessionId);
    this.store.run(
      `INSERT INTO agent_sessions (id, audit_id, task_id, role, harness, model, status, workspace, sandbox_mode, started_at)
       VALUES (?, ?, ?, ?, ?, ?, 'starting', ?, 'pending', ?)`,
      sessionId,
      task.audit_id,
      task.id,
      definition.role,
      harness,
      task.model,
      workspace,
      timestamp,
    );
    this.store.run("UPDATE tasks SET agent_session_id = ? WHERE id = ?", sessionId, task.id);
    this.events.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      type: "agent.session_created",
      payload: { role: definition.role, harness, model: task.model, workspace },
    });

    let sessionFinalized = false;
    const finalizeSession = (
      status: SessionRow["status"],
      result: HarnessRunResult | null,
      error: string | null,
    ) => {
      if (sessionFinalized) return;
      sessionFinalized = true;
      this.store.run(
        `UPDATE agent_sessions SET status = ?, ended_at = ?, exit_code = ?, usage = ?, error = ?, harness_session_ref = COALESCE(?, harness_session_ref), metadata = ? WHERE id = ?`,
        status,
        now(),
        result?.exitCode ?? null,
        result ? toJson(result.usage) : null,
        error,
        result?.sessionRef ?? null,
        result ? toJson(result.metadata) : null,
        sessionId,
      );
      this.events.append({
        auditId: task.audit_id,
        taskId: task.id,
        sessionId,
        type: "agent.session_ended",
        payload: {
          status,
          usage: result?.usage ?? null,
          error,
          harness_session_ref: result?.sessionRef ?? null,
        },
      });
    };
    const cancelBeforeRun = (): boolean => {
      if (!signal.aborted) return false;
      const reason = "Task cancelled before harness execution";
      finalizeSession("cancelled", null, reason);
      this.finishTaskFailure(task.id, "cancelled", reason);
      return true;
    };

    try {
      const workspaceRoot = await assertAuthorizedRoot(ctx.repository.path, this.config.allowedRoots);
      await createWorkspace(
        workspaceRoot,
        ctx.inventory,
        ctx.scope,
        workspace,
        {
          audit_id: task.audit_id,
          task_id: task.id,
          session_id: sessionId,
          commit: ctx.repository.commit_sha,
          scope: ctx.scope,
        },
        writableWorkspace,
      );
      this.events.append({
        auditId: task.audit_id,
        taskId: task.id,
        sessionId,
        type: "agent.workspace_ready",
        payload: {
          workspace,
          writable: writableWorkspace,
          file_count: ctx.inventory.files.length,
          summary: inventorySummary(ctx.inventory),
        },
      });
    } catch (error) {
      finalizeSession(signal.aborted ? "cancelled" : "failed", null, `Workspace creation failed: ${String(error)}`);
      this.finishTaskFailure(task.id, "internal", `Workspace creation failed: ${String(error)}`);
      return;
    }

    if (cancelBeforeRun()) return;
    let resources: SessionResources = { skills: [], servers: [] };
    try {
      if (this.catalog) resources = await this.catalog.resourcesForRole(definition.role);
    } catch (error) {
      const reason = `Local Skills/MCP configuration failed: ${error instanceof Error ? error.message : String(error)}`;
      finalizeSession("failed", null, reason);
      this.finishTaskFailure(task.id, "local_resources", reason);
      return;
    }
    const resourceContext = { auditId: task.audit_id, taskId: task.id, sessionId, role: definition.role, harness };
    const prompt = await this.buildPrompt(task, ctx);
    if (!prompt) {
      finalizeSession("failed", null, "No prompt builder for task kind");
      this.finishTaskFailure(task.id, "internal", `No prompt builder for task kind ${task.kind}`);
      return;
    }
    const agentPromptEvidence = await this.evidence.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      kind: "agent_prompt",
      title: `${definition.role} prompt — attempt ${task.attempts}`,
      content: prompt,
    });
    if (resources.skills.length > 0) {
      await this.evidence.append({
        auditId: task.audit_id, taskId: task.id, sessionId, kind: "local_resources",
        title: `${definition.role} local skills and linked MCP`,
        content: {
          skills: resources.skills.map((skill) => ({ id: skill.id, name: skill.name, sha256: sha256(skill.content),
            files: skill.files.map((file) => ({ path: file.path, sha256: sha256(file.content) })) })),
          mcp_servers: resources.servers.map((server) => ({ id: server.id, name: server.name, key: server.key })),
        },
      });
    }

    const schema = TASK_SCHEMAS[task.kind] ?? null;
    const shellApproval = this.store.get<{ status: string }>(
      "SELECT status FROM approvals WHERE task_id = ? AND action = 'allow_shell_tools' ORDER BY created_at DESC LIMIT 1",
      task.id,
    );
    const tools = this.toolsForHarness(
      shellApproval?.status === "approved"
        ? [...definition.allowed_tools, harness === "pi" ? "bash" : "Bash"]
        : definition.allowed_tools,
      harness,
    );
    const harnessPolicy = harnessConfig(this.store, harness).allowed_tools;
    const policyViolations =
      harnessPolicy.length > 0 ? tools.filter((tool) => !harnessPolicy.includes(tool)) : [];
    if (policyViolations.length > 0) {
      finalizeSession(
        "failed",
        null,
        `Harness policy does not allow tool(s): ${policyViolations.join(", ")}. Update Harness settings or the role tool list.`,
      );
      this.finishTaskFailure(
        task.id,
        "harness_tool_policy",
        `Harness policy does not allow tool(s): ${policyViolations.join(", ")}. The task failed closed; no tool was silently removed.`,
      );
      return;
    }
    let bufferedText = "";
    let lastFlush = Date.now();
    const flush = () => {
      if (!bufferedText) return;
      this.events.append({
        auditId: task.audit_id,
        taskId: task.id,
        sessionId,
        type: "agent.text",
        payload: { text: truncate(bufferedText, 2_000) },
      });
      bufferedText = "";
      lastFlush = Date.now();
    };
    const onEvent = (event: import("../harness/types.ts").HarnessEvent) => {
      if (event.type === "session_start") {
        this.catalog?.recordLoads(resources, resourceContext);
        this.store.run(
          "UPDATE agent_sessions SET status = 'running', sandbox_mode = ?, pid = ?, harness_session_ref = COALESCE(?, harness_session_ref) WHERE id = ?",
          String((event.meta?.sandbox as string) ?? "unknown"),
          Number(event.meta?.pid ?? 0) || null,
          (event.meta?.session_id as string) ?? null,
          sessionId,
        );
        this.events.append({
          auditId: task.audit_id,
          taskId: task.id,
          sessionId,
          type: "agent.session_started",
          payload: {
            harness,
            model: task.model,
            sandbox: event.meta?.sandbox,
            warnings: event.meta?.warnings ?? [],
            pid: event.meta?.pid,
            local_skills: resources.skills.map((skill) => ({ id: skill.id, name: skill.name })),
            mcp_servers: resources.servers.map((server) => ({ id: server.id, name: server.name })),
          },
        });
        return;
      }
      if (event.type === "text_delta") {
        bufferedText += event.text ?? "";
        if (bufferedText.length > 1_500 || Date.now() - lastFlush > 750) flush();
        return;
      }
      if (event.type === "thinking_delta") {
        if ((event.text?.length ?? 0) > 40) {
          this.events.append({
            auditId: task.audit_id,
            taskId: task.id,
            sessionId,
            type: "agent.thinking",
            payload: { text: truncate(event.text ?? "", 500) },
          });
        }
        return;
      }
      if (event.type === "tool_start") {
        this.catalog?.recordTool(resources, resourceContext, event.toolName ?? "", event.toolCallId ?? "");
        flush();
        this.events.append({
          auditId: task.audit_id,
          taskId: task.id,
          sessionId,
          type: "agent.tool_start",
          payload: {
            tool: event.toolName,
            tool_call_id: event.toolCallId,
            input: event.input,
          },
        });
        return;
      }
      if (event.type === "tool_end") {
        this.events.append({
          auditId: task.audit_id,
          taskId: task.id,
          sessionId,
          type: "agent.tool_end",
          payload: {
            tool: event.toolName,
            tool_call_id: event.toolCallId,
            output: event.output,
            is_error: event.isError ?? false,
          },
        });
        return;
      }
      if (event.type === "usage") {
        this.store.run(
          "UPDATE agent_sessions SET usage = ? WHERE id = ?",
          toJson(event.usage ?? {}),
          sessionId,
        );
        return;
      }
      if (event.type === "error") {
        this.events.append({
          auditId: task.audit_id,
          taskId: task.id,
          sessionId,
          type: "agent.error",
          payload: { message: event.text ?? "Agent reported an error" },
        });
        return;
      }
      if (event.type === "log") {
        this.events.append({
          auditId: task.audit_id,
          taskId: task.id,
          sessionId,
          type: "agent.log",
          payload: { message: event.text, meta: event.meta },
        });
      }
    };

    if (cancelBeforeRun()) return;
    let result: HarnessRunResult;
    try {
      result = await this.manager.run(
        harness,
        {
          runId: sessionId,
          auditId: task.audit_id,
          taskId: task.id,
          role: definition.role,
          prompt,
          systemPrompt: this.systemPrompt(task, definition, ctx.scope, ctx.repository.commit_sha, workspace, writableWorkspace) + localResourcePrompt(this.config, sessionId, resources),
          workspace,
          model: task.model,
          provider: harnessConfig(this.store, harness).provider,
          allowedTools: tools,
          timeoutMs: Math.min(definition.max_duration_ms, Number(ctx.auditConfig.task_timeout_ms ?? definition.max_duration_ms)),
          schema: schema ?? undefined,
          maxBudgetUsd: definition.budget_usd,
          metadata: { attempt: task.attempts },
          resources,
          workspaceWritable: writableWorkspace,
        },
        { onEvent, signal },
      );
    } catch (error) {
      flush();
      finalizeSession(signal.aborted ? "cancelled" : "failed", null, String(error));
      this.finishTaskFailure(task.id, "harness_error", `Harness invocation failed: ${String(error)}`);
      return;
    }
    flush();

    const sessionStatus = signal.aborted ? "cancelled" : RESULT_SESSION_STATUS[result.status] ?? "failed";
    finalizeSession(sessionStatus, result, signal.aborted ? "Task cancelled by operator" : result.error ?? null);

    const liveAudit = this.store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", task.audit_id);
    if (liveAudit && liveAudit.status !== "running") {
      await this.evidence.append({
        auditId: task.audit_id,
        taskId: task.id,
        sessionId,
        kind: "agent_transcript",
        title: `${definition.role} transcript — audit closed during execution`,
        content: {
          status: result.status,
          error: result.error ?? null,
          text: result.text,
          structured: result.structured ?? null,
          usage: result.usage,
          closed_audit_status: liveAudit.status,
        },
      });
      this.finishTaskFailure(
        task.id,
        "audit_closed",
        `Audit was ${liveAudit.status} while the harness session was executing; result was not persisted.`,
      );
      return;
    }

    await this.evidence.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      kind: "agent_transcript",
      title: `${definition.role} transcript — ${result.status}`,
      content: {
        status: result.status,
        error: result.error ?? null,
        text: result.text,
        structured: result.structured ?? null,
        usage: result.usage,
        events: result.events.map((event) => ({
          type: event.type,
          at: event.at,
          text: event.text,
          toolName: event.toolName,
          toolCallId: event.toolCallId,
          input: event.input,
          output: event.output,
          isError: event.isError,
        })),
        prompt_evidence_id: agentPromptEvidence.id,
        harness,
        model: result.model,
        session_ref: result.sessionRef,
        sandbox: result.metadata.sandbox,
      },
    });

    if (signal.aborted) {
      this.finishTaskFailure(task.id, "cancelled", "Task cancelled by operator; harness result was not applied");
      return;
    }
    if (result.status !== "completed") {
      const kind =
        result.status === "timeout"
          ? "timeout"
          : result.status === "cancelled"
            ? "cancelled"
            : result.failureKind ?? "agent_error";
      this.finishTaskFailure(task.id, kind, result.error ?? `Agent finished with status ${result.status}`);
      return;
    }

    const structured = result.structured ?? extractJson(result.text);
    if (!structured) {
      this.finishTaskFailure(task.id, "invalid_output", "Agent response did not contain a parseable JSON result");
      return;
    }
    if (schema) {
      const validated = validateResult<MapResult | DiscoveryResult | ConfirmationResult | RetestResult>(structured, schema);
      if (!validated.ok) {
        this.finishTaskFailure(
          task.id,
          "invalid_output",
          `Agent response failed schema validation: ${validated.errors.slice(0, 12).join("; ")}`,
        );
        return;
      }
    }
    if (definition.budget_usd !== null && result.usage.cost_usd > definition.budget_usd) {
      this.finishTaskFailure(
        task.id,
        "budget_exceeded",
        `Reported cost $${result.usage.cost_usd.toFixed(4)} exceeded the ${definition.role} budget of $${definition.budget_usd.toFixed(4)}`,
      );
      return;
    }

    try {
      const data = await this.handleAgentResult(task, ctx, structured, result, sessionId);
      this.completeTask(task.id, { data, meta: this.runMeta(result, sessionId, harness) });
    } catch (error) {
      this.finishTaskFailure(task.id, "invalid_output", error instanceof Error ? error.message : String(error));
    }
  }

  private runMeta(result: HarnessRunResult, sessionId: string, harness: HarnessKind) {
    return {
      session_id: sessionId,
      harness,
      model: result.model,
      session_ref: result.sessionRef,
      usage: result.usage,
      sandbox: result.metadata.sandbox,
      started_at: result.startedAt,
      ended_at: result.endedAt,
    };
  }

  /** Fail closed unless the audit requested writes and an administrator approved this task. */
  private resolveWritableWorkspace(task: TaskRow, auditConfig: Record<string, unknown>): boolean {
    if (auditConfig.writable_workspace !== true) return false;
    if (!getSetting(this.store, "security.allow_writable_workspace", false)) {
      throw new AppError(
        409,
        "writable_workspace_disabled",
        "security.allow_writable_workspace is disabled; refusing to run this task with write access.",
      );
    }
    const approval = this.store.get<{ status: string }>(
      "SELECT status FROM approvals WHERE task_id = ? AND action = 'allow_writable_workspace' ORDER BY created_at DESC LIMIT 1",
      task.id,
    );
    if (approval?.status !== "approved") {
      throw new AppError(
        409,
        "writable_workspace_not_approved",
        "This audit requests a writable workspace, but this task has no approved allow_writable_workspace decision.",
      );
    }
    return true;
  }

  private systemPrompt(
    task: TaskRow,
    definition: AgentDefinition,
    scope: Scope,
    commit: string | null,
    workspace: string,
    writable: boolean,
  ): string {
    if (task.kind === "phase1.map") return mapperSystem(definition.system_instructions, workspace, commit, writable);
    if (task.kind === "phase2.discover") return researcherSystem(definition.system_instructions, workspace, commit, writable);
    if (task.kind === "phase3.confirm") return validatorSystem(definition.system_instructions, workspace, commit, writable);
    if (task.kind === "phase5.reverify") return retestSystem(definition.system_instructions, workspace, commit, writable);
    return `${definition.system_instructions}\nWorkspace (${writable ? "writable copy, administrator-approved for this task" : "read-only copy"}): ${workspace}\nScope: ${scope.include.join(", ")}`;
  }

  private async buildPrompt(task: TaskRow, ctx: ReturnType<AuditEngine["context"]>): Promise<string | null> {
    const payload = parseJson<Record<string, unknown>>(task.payload, {});
    if (task.kind === "phase1.map") {
      return mapperPrompt({
        projectName: ctx.project.name,
        repositoryPath: ctx.repository.path,
        commit: ctx.repository.commit_sha,
        scope: ctx.scope,
        inventory: ctx.inventory,
        inventoryJson: inventoryForAgent(ctx.inventory),
        maxAreas: Number(ctx.auditConfig.max_areas ?? 4),
      });
    }
    if (task.kind === "phase2.discover") {
      const map = parseJson<{ data?: MapResult }>(payload.map_result as string, {});
      const area = map.data?.areas.find((entry) => entry.id === payload.area_id);
      if (!area) return null;
      return researcherPrompt({
        area,
        inventory: ctx.inventory,
        maxCandidates: Number(ctx.auditConfig.max_candidates_per_area ?? 4),
      });
    }
    if (task.kind === "phase3.confirm") {
      const candidateRow = this.store.get<CandidateRow>("SELECT * FROM candidates WHERE id = ?", String(payload.candidate_id));
      if (!candidateRow) return null;
      const candidate = parseJson<Candidate>(candidateRow.payload, {} as Candidate);
      const findingCodes = this.store
        .all<{ code: string }>("SELECT code FROM findings WHERE audit_id = ? ORDER BY code", task.audit_id)
        .map((row) => row.code);
      return validatorPrompt({
        candidate,
        areaTitle: String(payload.area_title ?? candidateRow.area_id),
        commit: ctx.repository.commit_sha,
        findingCodes,
      });
    }
    if (task.kind === "phase5.reverify") {
      const finding = this.store.get<FindingRow>("SELECT * FROM findings WHERE id = ?", String(payload.finding_id));
      if (!finding) return null;
      const evidence = this.store.all<{ kind: string; title: string; content_path: string }>(
        "SELECT kind, title, content_path FROM evidence WHERE finding_id = ? AND kind = 'code_excerpt' ORDER BY rowid",
        finding.id,
      );
      const excerpts: Array<{ path: string; start_line: number; end_line: number; quote: string }> = [];
      for (const item of evidence) {
        try {
          const raw = await Bun.file(item.content_path).json() as {
            content?: string | { path: string; start_line: number; end_line: number; quote: string };
          };
          let content = raw.content;
          if (typeof content === "string") {
            try {
              content = JSON.parse(content) as { path: string; start_line: number; end_line: number; quote: string };
            } catch {
              continue;
            }
          }
          if (content && typeof content === "object" && "quote" in content) {
            excerpts.push(content);
          }
        } catch {
          // skip unreadable evidence; the platform evidence chain check reports it separately
        }
      }
      return retestPrompt({
        finding: {
          code: finding.code,
          title: finding.title,
          category: finding.category,
          cwe: finding.cwe,
          severity: finding.severity,
          root_cause: finding.root_cause,
          preconditions: parseJson<string[]>(finding.preconditions, []),
          reproduction: parseJson<string[]>(finding.reproduction, []),
          expected: finding.expected,
          observed: finding.observed,
          impact: finding.impact,
          remediation: finding.remediation,
          files: parseJson<Array<{ path: string; start_line: number; end_line: number }>>(finding.files, []),
        },
        excerpts,
      });
    }
    return null;
  }

  private async handleAgentResult(
    task: TaskRow,
    ctx: ReturnType<AuditEngine["context"]>,
    structured: unknown,
    result: HarnessRunResult,
    sessionId: string,
  ): Promise<unknown> {
    if (task.kind === "phase1.map") {
      return this.handleMap(task, ctx, structured as MapResult, result, sessionId);
    }
    if (task.kind === "phase2.discover") {
      return this.handleDiscovery(task, ctx, structured as DiscoveryResult, result, sessionId);
    }
    if (task.kind === "phase3.confirm") {
      return this.handleConfirmation(task, ctx, structured as ConfirmationResult, result, sessionId);
    }
    if (task.kind === "phase5.reverify") {
      return this.handleRetest(task, ctx, structured as RetestResult, result, sessionId);
    }
    throw new Error(`Unsupported agent task kind: ${task.kind}`);
  }

  private async handleMap(
    task: TaskRow,
    ctx: ReturnType<AuditEngine["context"]>,
    raw: MapResult,
    result: HarnessRunResult,
    sessionId: string,
  ): Promise<MapResult> {
    const validPaths = new Set(ctx.inventory.files.map((file) => file.path));
    const maxAreas = Number(ctx.auditConfig.max_areas ?? 4);
    const seenAreaIds = new Set<string>();
    const normalized: MapResult = {
      ...raw,
      endpoints: raw.endpoints.filter((entry) => validPaths.has(entry.file)),
      modules: raw.modules.filter((entry) => validPaths.has(entry.path)),
      entrypoints: raw.entrypoints.filter((entry) => validPaths.has(entry)),
      auth_boundaries: raw.auth_boundaries.filter((entry) => validPaths.has(entry.file)),
      data_access: raw.data_access.filter((entry) => entry.files.some((file) => validPaths.has(file))),
      critical_paths: raw.critical_paths.filter((entry) => entry.files.some((file) => validPaths.has(file))),
      areas: [],
    };
    for (const area of raw.areas) {
      const id = area.id.replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 48) || `area-${normalized.areas.length + 1}`;
      if (seenAreaIds.has(id)) continue;
      const files = [...new Set(area.files.filter((file) => validPaths.has(file)))];
      if (files.length === 0) continue;
      seenAreaIds.add(id);
      normalized.areas.push({ ...area, id, files: files.slice(0, 120) });
      if (normalized.areas.length >= maxAreas) break;
    }
    let fallback = false;
    if (normalized.areas.length === 0) {
      fallback = true;
      const groups = new Map<string, string[]>();
      for (const file of ctx.inventory.files) {
        const top = file.path.includes("/") ? file.path.split("/").slice(0, 2).join("/") : "(root)";
        const bucket = groups.get(top) ?? [];
        bucket.push(file.path);
        groups.set(top, bucket);
      }
      const entries = [...groups.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, maxAreas);
      for (const [index, [top, files]] of entries.entries()) {
        normalized.areas.push({
          id: `platform-area-${index + 1}`,
          title: `Module ${top}`,
          rationale: "Platform-generated fallback area: the mapper response did not contain valid areas.",
          files: files.slice(0, 120),
          security_focus: ["authentication", "authorization", "injection", "data access", "file handling"],
        });
      }
      normalized.coverage_notes.push(
        "Agent mapping did not yield valid areas; the platform created directory-based fallback areas.",
      );
    }
    if (normalized.areas.length === 0) throw new Error("Repository has no in-scope files to audit");
    const assigned = new Set(normalized.areas.flatMap((area) => area.files));
    const unmapped = ctx.inventory.files.map((file) => file.path).filter((path) => !assigned.has(path));
    this.store.transaction(() => {
      for (const area of normalized.areas) {
        this.store.run(
          `INSERT INTO coverage (id, audit_id, area_id, title, status, files, notes, updated_at)
           VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?)
           ON CONFLICT(audit_id, area_id) DO UPDATE SET title = excluded.title, files = excluded.files, notes = excluded.notes, updated_at = excluded.updated_at`,
          uid(),
          task.audit_id,
          area.id,
          area.title,
          toJson(area.files),
          area.security_focus.join(", "),
          now(),
        );
      }
      this.store.run(
        `INSERT INTO coverage (id, audit_id, area_id, title, status, files, notes, updated_at)
         VALUES (?, ?, 'unmapped', 'Files outside mapped areas', 'NOT_APPLICABLE', ?, ?, ?)
         ON CONFLICT(audit_id, area_id) DO UPDATE SET files = excluded.files, notes = excluded.notes, updated_at = excluded.updated_at`,
        uid(),
        task.audit_id,
        toJson(unmapped),
        `${unmapped.length} file(s) were not assigned to an assessment area. They are a known coverage limitation.`,
        now(),
      );
      this.store.run(
        "UPDATE audit_phases SET status = 'completed', finished_at = ?, summary = ? WHERE audit_id = ? AND phase = 1",
        now(),
        `Mapped ${ctx.inventory.files.length} files into ${normalized.areas.length} areas${fallback ? " (platform fallback)" : ""}. ${unmapped.length} files unmapped.`,
        task.audit_id,
      );
      this.store.run(
        "UPDATE audit_phases SET status = 'running', started_at = COALESCE(started_at, ?) WHERE audit_id = ? AND phase = 2",
        now(),
        task.audit_id,
      );
      this.store.run("UPDATE audits SET current_phase = MAX(current_phase, 2) WHERE id = ?", task.audit_id);
    });
    for (const area of normalized.areas) {
      this.createTask({
        auditId: task.audit_id,
        phase: 2,
        kind: "phase2.discover",
        taskKey: `phase2:area:${area.id}`,
        title: `Phase 2 — Discover vulnerabilities in ${area.title}`,
        payload: { area_id: area.id, area_title: area.title, map_result: toJson({ data: normalized }) },
        agentRole: "security_researcher",
        priority: 50,
        dependsOn: [task.id],
      });
      this.events.append({
        auditId: task.audit_id,
        taskId: task.id,
        sessionId,
        type: "coverage.area_created",
        payload: { area_id: area.id, title: area.title, files: area.files.length },
      });
    }
    this.events.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      type: "phase.completed",
      payload: { phase: 1, areas: normalized.areas.length, unmapped_files: unmapped.length, fallback },
    });
    return normalized;
  }

  private async handleDiscovery(
    task: TaskRow,
    ctx: ReturnType<AuditEngine["context"]>,
    raw: DiscoveryResult,
    result: HarnessRunResult,
    sessionId: string,
  ): Promise<DiscoveryResult> {
    const payload = parseJson<Record<string, unknown>>(task.payload, {});
    const areaId = String(payload.area_id);
    const validPaths = new Set(ctx.inventory.files.map((file) => file.path));
    const maxCandidates = Number(ctx.auditConfig.max_candidates_per_area ?? 4);
    const candidates = raw.candidates.slice(0, maxCandidates).map((candidate) => ({
      ...candidate,
      files: candidate.files.filter((file) => validPaths.has(file.path)),
      evidence_excerpts: candidate.evidence_excerpts.filter((excerpt) => validPaths.has(excerpt.path)),
    }));
    const checks: Array<Record<string, unknown>> = [];
    for (const candidate of candidates) {
      for (const excerpt of candidate.evidence_excerpts) {
        checks.push({
          candidate: candidate.title,
          ...(await verifyQuote(await assertAuthorizedRoot(ctx.repository.path, this.config.allowedRoots), ctx.scope, excerpt)),
        });
      }
    }
    const createdAt = now();
    const candidateRows: CandidateRow[] = [];
    this.store.transaction(() => {
      for (const candidate of candidates) {
        const id = uid();
        const payloadWithChecks = {
          ...candidate,
          discovery_evidence_check: checks.filter((check) => check.candidate === candidate.title),
          area_id: areaId,
        };
        this.store.run(
          `INSERT INTO candidates (id, audit_id, area_id, discovery_task_id, discovery_session_id, title, category, cwe, severity, status, payload, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'discovered', ?, ?)`,
          id,
          task.audit_id,
          areaId,
          task.id,
          sessionId,
          candidate.title,
          candidate.category,
          candidate.cwe,
          candidate.severity,
          toJson(payloadWithChecks),
          createdAt,
        );
        candidateRows.push({
          id,
          audit_id: task.audit_id,
          area_id: areaId,
          discovery_task_id: task.id,
          discovery_session_id: sessionId,
          title: candidate.title,
          category: candidate.category,
          cwe: candidate.cwe,
          severity: candidate.severity,
          status: "discovered",
          finding_id: null,
          payload: toJson(payloadWithChecks),
          created_at: createdAt,
        });
        this.events.append({
          auditId: task.audit_id,
          taskId: task.id,
          sessionId,
          type: "candidate.discovered",
          payload: {
            candidate_id: id,
            title: candidate.title,
            category: candidate.category,
            cwe: candidate.cwe,
            severity: candidate.severity,
            area_id: areaId,
            evidence_checks: checks.filter((check) => check.candidate === candidate.title),
          },
        });
      }
      this.store.run(
        "UPDATE coverage SET status = 'COMPLETED', task_id = ?, notes = ?, updated_at = ? WHERE audit_id = ? AND area_id = ?",
        task.id,
        truncate(`${raw.summary}${raw.limitations.length ? ` | limitations: ${raw.limitations.join("; ")}` : ""}`, 2_000),
        now(),
        task.audit_id,
        areaId,
      );
      this.store.run(
        "UPDATE audit_phases SET status = 'running', started_at = COALESCE(started_at, ?) WHERE audit_id = ? AND phase = 2",
        now(),
        task.audit_id,
      );
    });
    await this.evidence.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      kind: "discovery_result",
      title: `Discovery result — ${areaId}`,
      content: { area_id: areaId, summary: raw.summary, limitations: raw.limitations, candidates, checks },
    });
    return {
      ...raw,
      area_id: areaId,
      inspected_files: raw.inspected_files.filter((path) => validPaths.has(path)),
      candidates,
    };
  }

  private async handleConfirmation(
    task: TaskRow,
    ctx: ReturnType<AuditEngine["context"]>,
    raw: ConfirmationResult,
    result: HarnessRunResult,
    sessionId: string,
  ): Promise<ConfirmationResult & { effective_verdict: string; evidence_checks: unknown[] }> {
    const payload = parseJson<Record<string, unknown>>(task.payload, {});
    const candidateRow = this.store.get<CandidateRow>("SELECT * FROM candidates WHERE id = ?", String(payload.candidate_id));
    if (!candidateRow) throw new Error("Candidate not found for confirmation task");
    if (candidateRow.discovery_session_id === sessionId) {
      throw new Error("Independence violation: the discovering session cannot confirm its own candidate");
    }
    const repoRoot = await assertAuthorizedRoot(ctx.repository.path, this.config.allowedRoots);
    const candidateData = parseJson<Candidate>(candidateRow.payload, {} as Candidate);
    const candidatePaths = new Set(candidateData.files.map((file) => file.path));
    const evaluation = await evaluateEvidence(repoRoot, ctx.scope, raw.verified_excerpts, candidatePaths);
    const evidenceChecks = evaluation.checks;
    const verifiedCount = evaluation.verifiedCount;
    const relevantCount = evaluation.relevantCount;
    let effectiveVerdict = raw.verdict;
    let rationale = raw.rationale;
    if ((raw.verdict === "CONFIRMED" || raw.verdict === "DUPLICATE") && relevantCount === 0) {
      effectiveVerdict = "INCONCLUSIVE";
      rationale = `${rationale}\n\nPlatform evidence gate: the validation response contained no verified code excerpt on an affected candidate file. The claim is therefore not confirmed.`;
    }
    if (raw.verdict === "DUPLICATE") {
      const duplicateCode = raw.duplicate_of_finding_code?.trim();
      const duplicate = duplicateCode
        ? this.store.get<{ id: string }>(
            "SELECT id FROM findings WHERE audit_id = ? AND code = ?",
            task.audit_id,
            duplicateCode,
          )
        : null;
      if (!duplicate) {
        effectiveVerdict = "INCONCLUSIVE";
        rationale = `${rationale}\n\nPlatform note: DUPLICATE was claimed without a valid existing finding code in this audit.`;
      }
    }
    const verificationId = uid();
    const createdAt = now();
    const checkJson = {
      verified_count: verifiedCount,
      relevant_count: relevantCount,
      checks: evidenceChecks,
      original_verdict: raw.verdict,
      effective_verdict: effectiveVerdict,
    };
    this.store.transaction(() => {
      this.store.run(
        `INSERT INTO verifications (id, audit_id, candidate_id, kind, agent_session_id, discovery_session_id, verdict, rationale, evidence_check, payload, created_at)
         VALUES (?, ?, ?, 'confirmation', ?, ?, ?, ?, ?, ?, ?)`,
        verificationId,
        task.audit_id,
        candidateRow.id,
        sessionId,
        candidateRow.discovery_session_id,
        effectiveVerdict,
        rationale,
        toJson(checkJson),
        toJson({ raw, evidence_checks: evidenceChecks }),
        createdAt,
      );
      this.store.run(
        "UPDATE candidates SET status = ? WHERE id = ?",
        effectiveVerdict === "CONFIRMED"
          ? "confirmed"
          : effectiveVerdict === "REFUTED"
            ? "refuted"
            : effectiveVerdict === "DUPLICATE"
              ? "duplicate"
              : "inconclusive",
        candidateRow.id,
      );
    });
    await this.evidence.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      kind: "verification_result",
      title: `Independent confirmation — ${candidateRow.title}`,
      content: { verification_id: verificationId, candidate_id: candidateRow.id, raw, effective_verdict: effectiveVerdict, evidence_checks: evidenceChecks },
    });
    if (verifiedCount > 0) {
      await this.evidence.append({
        auditId: task.audit_id,
        taskId: task.id,
        sessionId,
        kind: "verified_code_excerpts",
        title: `Verified code excerpts — ${candidateRow.title}`,
        content: evidenceChecks,
      });
    }
    this.events.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      type: "verification.completed",
      payload: {
        verification_id: verificationId,
        candidate_id: candidateRow.id,
        kind: "confirmation",
        verdict: effectiveVerdict,
        claimed_verdict: raw.verdict,
        verified_excerpts: verifiedCount,
      },
    });
    return { ...raw, verdict: raw.verdict, effective_verdict: effectiveVerdict, evidence_checks: evidenceChecks };
  }

  private async handleRetest(
    task: TaskRow,
    ctx: ReturnType<AuditEngine["context"]>,
    raw: RetestResult,
    result: HarnessRunResult,
    sessionId: string,
  ): Promise<RetestResult & { effective_decision: string; evidence_checks: unknown[] }> {
    const payload = parseJson<Record<string, unknown>>(task.payload, {});
    const finding = this.store.get<FindingRow>("SELECT * FROM findings WHERE id = ?", String(payload.finding_id));
    if (!finding) throw new Error("Finding not found for retest task");
    if (finding.discovery_session_id === sessionId || finding.verification_session_id === sessionId) {
      throw new Error("Independence violation: discovery or first-validation session cannot reverify this finding");
    }
    const repoRoot = await assertAuthorizedRoot(ctx.repository.path, this.config.allowedRoots);
    const findingPaths = new Set(parseJson<Array<{ path: string }>>(finding.files, []).map((file) => file.path));
    const evaluation = await evaluateEvidence(repoRoot, ctx.scope, raw.verified_excerpts, findingPaths);
    const evidenceChecks = evaluation.checks;
    const verifiedCount = evaluation.verifiedCount;
    const relevantCount = evaluation.relevantCount;
    let effectiveDecision = raw.decision;
    let rationale = raw.rationale;
    if (raw.decision === "REVERIFIED" && relevantCount === 0) {
      effectiveDecision = "NEEDS_CORRECTION";
      rationale = `${rationale}\n\nPlatform evidence gate: REVERIFIED requires at least one exact source excerpt on an affected finding file, verified against the audited commit. None was verifiable.`;
    }
    const verificationId = uid();
    const createdAt = now();
    const findingStatus =
      effectiveDecision === "REVERIFIED"
        ? "reverified"
        : effectiveDecision === "REJECTED"
          ? "rejected"
          : effectiveDecision === "NEEDS_CORRECTION"
            ? "needs_correction"
            : "unresolved";
    this.store.transaction(() => {
      this.store.run(
        `INSERT INTO verifications (id, audit_id, candidate_id, finding_id, kind, agent_session_id, discovery_session_id, verdict, rationale, evidence_check, payload, created_at)
         VALUES (?, ?, ?, ?, 'reverification', ?, ?, ?, ?, ?, ?, ?)`,
        verificationId,
        task.audit_id,
        finding.candidate_id,
        finding.id,
        sessionId,
        finding.discovery_session_id ?? "",
        effectiveDecision,
        rationale,
        toJson({ verified_count: verifiedCount, relevant_count: relevantCount, checks: evidenceChecks, original_decision: raw.decision, effective_decision: effectiveDecision }),
        toJson({ raw, evidence_checks: evidenceChecks }),
        createdAt,
      );
      this.store.run(
        `UPDATE findings SET status = ?, severity = ?, retest_decision = ?, retest_session_id = COALESCE(retest_session_id, ?), updated_at = ? WHERE id = ?`,
        findingStatus,
        raw.severity_assessment,
        effectiveDecision,
        sessionId,
        createdAt,
        finding.id,
      );
    });
    await this.evidence.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      findingId: finding.id,
      kind: "reverification_result",
      title: `Independent reverification — ${finding.code}`,
      content: { verification_id: verificationId, finding_id: finding.id, raw, effective_decision: effectiveDecision, evidence_checks: evidenceChecks },
    });
    this.events.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId,
      type: "finding.reverified",
      payload: {
        finding_id: finding.id,
        code: finding.code,
        decision: effectiveDecision,
        claimed_decision: raw.decision,
        verified_excerpts: verifiedCount,
        status: findingStatus,
      },
    });
    const reportTaskExists = this.store.get<{ id: string }>(
      "SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase6.report' LIMIT 1",
      task.audit_id,
    );
    if (reportTaskExists) {
      this.createTask({
        auditId: task.audit_id,
        phase: 6,
        kind: "phase6.report",
        taskKey: `phase6:report:retest:${verificationId}`,
        title: `Phase 6 — Regenerate reports after retest of ${finding.code}`,
        payload: { trigger: "manual_retest", finding_id: finding.id },
        agentRole: null,
        priority: 10,
        dependsOn: [task.id],
      });
      this.store.run(
        "UPDATE audits SET status = 'running', finished_at = NULL, current_phase = 6 WHERE id = ?",
        task.audit_id,
      );
    }
    return { ...raw, effective_decision: effectiveDecision, evidence_checks: evidenceChecks };
  }

  private async persistFinding(task: TaskRow, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const candidate = this.store.get<CandidateRow>("SELECT * FROM candidates WHERE id = ?", String(payload.candidate_id));
    if (!candidate) throw new Error("Candidate not found");
    const verification = this.store.get<VerificationRow>("SELECT * FROM verifications WHERE id = ?", String(payload.verification_id));
    if (!verification || verification.verdict !== "CONFIRMED") {
      throw new Error("Findings can only be persisted from a CONFIRMED verification");
    }
    const ctx = this.context(task.audit_id);
    const candidateData = parseJson<Candidate>(candidate.payload, {} as Candidate);
    const verificationRaw = parseJson<{ raw?: ConfirmationResult }>(verification.payload, {});
    const confirm = verificationRaw.raw;
    const checkData = parseJson<{
      verified_count?: number;
      checks?: Array<{ found: boolean; path: string; line_start: number | null; line_end: number | null }>;
    }>(verification.evidence_check, {});
    const checks = checkData.checks ?? [];
    const candidatePaths = new Set(candidateData.files.map((file) => file.path));
    const verifiedChecks = checks.filter((check) => check.found && candidatePaths.has(check.path));
    if (verifiedChecks.length === 0) {
      throw new Error("Cannot persist a finding without platform-verified code evidence on an affected file");
    }
    const files = [...new Set(verifiedChecks.map((check) => `${check.path}:${check.line_start ?? 1}:${check.line_end ?? check.line_start ?? 1}`))]
      .map((entry) => {
        const [path, start, end] = entry.split(":");
        return { path: path!, start_line: Number(start), end_line: Number(end) };
      });
    const existing = this.store.get<FindingRow>(
      `SELECT * FROM findings WHERE audit_id = ? AND (title = ? OR (category = ? AND files = ?)) LIMIT 1`,
      task.audit_id,
      candidate.title,
      candidate.category,
      toJson(files),
    );
    if (existing) {
      this.store.run("UPDATE candidates SET status = 'duplicate', finding_id = ? WHERE id = ?", existing.id, candidate.id);
      return { duplicate_of: existing.code, finding_id: existing.id };
    }
    const count = this.store.get<{ count: number }>(
      "SELECT COUNT(*) AS count FROM findings WHERE audit_id = ?",
      task.audit_id,
    )?.count ?? 0;
    const findingId = uid();
    const code = `ARG-${String(count + 1).padStart(3, "0")}`;
    const createdAt = now();
    const reproduction = [
      candidateData.reproduction_notes,
      ...(confirm?.reproduction_steps ?? []),
    ].filter((step) => typeof step === "string" && step.trim().length > 0);
    const severity = confirm?.severity_assessment ?? candidateData.severity;
    const impact = confirm?.impact_assessment?.trim() ? confirm.impact_assessment : candidateData.impact;
    const finding: FindingRow = {
      id: findingId,
      code,
      audit_id: task.audit_id,
      project_id: ctx.project.id,
      candidate_id: candidate.id,
      title: candidate.title,
      category: candidate.category,
      cwe: candidate.cwe,
      severity,
      status: "confirmed",
      repository_commit: ctx.repository.commit_sha,
      files: toJson(files),
      root_cause: candidateData.hypothesis,
      preconditions: toJson(candidateData.preconditions),
      reproduction: toJson(reproduction),
      expected: candidateData.expected,
      observed: candidateData.observed,
      impact,
      remediation: candidateData.remediation,
      discovery_session_id: candidate.discovery_session_id,
      verification_session_id: verification.agent_session_id,
      retest_session_id: null,
      verification_decision: "CONFIRMED",
      retest_decision: null,
      created_at: createdAt,
      updated_at: createdAt,
    };
    this.store.transaction(() => {
      this.store.run(
        `INSERT INTO findings (id, code, audit_id, project_id, candidate_id, title, category, cwe, severity, status, repository_commit, files, root_cause, preconditions, reproduction, expected, observed, impact, remediation, discovery_session_id, verification_session_id, retest_session_id, verification_decision, retest_decision, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'CONFIRMED', NULL, ?, ?)`,
        finding.id,
        finding.code,
        finding.audit_id,
        finding.project_id,
        finding.candidate_id,
        finding.title,
        finding.category,
        finding.cwe,
        finding.severity,
        finding.status,
        finding.repository_commit,
        finding.files,
        finding.root_cause,
        finding.preconditions,
        finding.reproduction,
        finding.expected,
        finding.observed,
        finding.impact,
        finding.remediation,
        finding.discovery_session_id,
        finding.verification_session_id,
        finding.created_at,
        finding.updated_at,
      );
      this.store.run("UPDATE candidates SET status = 'persisted', finding_id = ? WHERE id = ?", finding.id, candidate.id);
    });
    for (const check of verifiedChecks) {
      await this.evidence.append({
        auditId: task.audit_id,
        taskId: task.id,
        sessionId: verification.agent_session_id,
        findingId: finding.id,
        kind: "code_excerpt",
        title: `${check.path}:${check.line_start ?? 1}-${check.line_end ?? check.line_start ?? 1}`,
        content: {
          path: check.path,
          start_line: check.line_start ?? 1,
          end_line: check.line_end ?? check.line_start ?? 1,
          quote:
            confirm?.verified_excerpts.find(
              (excerpt) =>
                excerpt.path === check.path &&
                (check.line_start === null || excerpt.start_line === check.line_start),
            )?.quote ??
            candidateData.evidence_excerpts.find((excerpt) => excerpt.path === check.path)?.quote ??
            "",
          verification_id: verification.id,
        },
      });
    }
    await this.evidence.append({
      auditId: task.audit_id,
      taskId: task.id,
      sessionId: verification.agent_session_id,
      findingId: finding.id,
      kind: "finding_record",
      title: `${finding.code} structured finding`,
      content: {
        ...finding,
        verification_rationale: verification.rationale,
        evidence_checks: verifiedChecks,
      },
    });
    this.events.append({
      auditId: task.audit_id,
      taskId: task.id,
      type: "finding.created",
      payload: {
        finding_id: finding.id,
        code: finding.code,
        title: finding.title,
        severity: finding.severity,
        files,
      },
    });
    return { finding_id: finding.id, code: finding.code, files };
  }

  private completeTask(taskId: string, data: unknown): void {
    const timestamp = now();
    this.store.run(
      "UPDATE tasks SET status = 'completed', result = ?, error = NULL, failure_kind = NULL, finished_at = ? WHERE id = ?",
      toJson(data),
      timestamp,
      taskId,
    );
    const task = this.store.get<TaskRow>("SELECT * FROM tasks WHERE id = ?", taskId);
    if (task) {
      this.events.append({
        auditId: task.audit_id,
        taskId,
        sessionId: task.agent_session_id,
        type: "task.completed",
        payload: { kind: task.kind, phase: task.phase, title: task.title },
      });
    }
  }

  private finishTaskFailure(taskId: string, failureKind: string, rawError: string): void {
    const task = this.store.get<TaskRow>("SELECT * FROM tasks WHERE id = ?", taskId);
    if (!task || TERMINAL_TASK_STATES.has(task.status)) return;
    const audit = this.store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", task.audit_id);
    if (
      audit && (["cancelling", "cancelled"].includes(audit.status) ||
        (audit.status === "running" && !this.stopping && this.running.get(taskId)?.controller.signal.aborted))
    ) {
      failureKind = "cancelled";
    }
    const error = redactSecrets(rawError).text;
    const retryable = ![
      "cancelled",
      "budget_exceeded",
      "harness_missing",
      "harness_auth",
      "shell_tools_disabled",
      "harness_tool_policy",
      "audit_closed",
      "local_resources",
      "writable_workspace_disabled",
      "writable_workspace_not_approved",
    ].includes(failureKind);
    const retry = retryable && task.attempts < task.max_attempts && audit?.status === "running";
    if (retry) {
      this.store.run(
        "UPDATE tasks SET status = 'queued', error = ?, failure_kind = ?, started_at = NULL, finished_at = NULL WHERE id = ?",
        truncate(error, 8_000),
        failureKind,
        taskId,
      );
      this.events.append({
        auditId: task.audit_id,
        taskId,
        sessionId: task.agent_session_id,
        type: "task.retry",
        payload: { failure_kind: failureKind, error: truncate(error, 1_500), attempt: task.attempts, max_attempts: task.max_attempts },
      });
      return;
    }
    this.store.run(
      "UPDATE tasks SET status = ?, error = ?, failure_kind = ?, finished_at = ? WHERE id = ?",
      failureKind === "cancelled" ? "cancelled" : "failed",
      truncate(error, 8_000),
      failureKind,
      now(),
      taskId,
    );
    this.events.append({
      auditId: task.audit_id,
      taskId,
      sessionId: task.agent_session_id,
      type: failureKind === "cancelled" ? "task.cancelled" : "task.failed",
      payload: { failure_kind: failureKind, error: truncate(error, 1_500) },
    });
    if (task.approval_id) {
      this.store.run(
        "UPDATE approvals SET status = 'denied', reason = COALESCE(reason, ?), decided_at = COALESCE(decided_at, ?) WHERE task_id = ? AND status = 'pending'",
        failureKind === "cancelled" ? "Task cancelled before approval was decided" : "Task failed before approval was decided",
        now(),
        task.id,
      );
    }
    if (task.kind === "phase3.confirm" || task.kind === "phase4.persist") {
      const payload = parseJson<Record<string, unknown>>(task.payload, {});
      if (payload.candidate_id) {
        this.store.run(
          "UPDATE candidates SET status = 'inconclusive' WHERE id = ? AND status = 'confirming'",
          String(payload.candidate_id),
        );
      }
    }
    if (task.kind === "phase2.discover") {
      const payload = parseJson<Record<string, unknown>>(task.payload, {});
      this.store.run(
        "UPDATE coverage SET status = ?, notes = ?, updated_at = ? WHERE audit_id = ? AND area_id = ?",
        failureKind === "cancelled" ? "BLOCKED" : "FAILED",
        truncate(error, 2_000),
        now(),
        task.audit_id,
        String(payload.area_id ?? "unknown"),
      );
    }
    if (task.kind === "phase5.reverify") {
      const payload = parseJson<Record<string, unknown>>(task.payload, {});
      const finding = this.store.get<FindingRow>("SELECT * FROM findings WHERE id = ?", String(payload.finding_id));
      if (finding && finding.status === "confirmed") {
        this.store.run(
          "UPDATE findings SET status = 'unresolved', retest_decision = 'UNRESOLVED', updated_at = ? WHERE id = ?",
          now(),
          finding.id,
        );
      }
    }
  }

  private async reconcile(auditId: string): Promise<void> {
    await this.withAuditLock(auditId, async () => {
      const audit = this.store.get<AuditRow>("SELECT * FROM audits WHERE id = ?", auditId);
      if (!audit) return;
      if (audit.status === "cancelling") {
        const pending = this.store.all<{ id: string }>(
          "SELECT id FROM tasks WHERE audit_id = ? AND status IN ('queued','waiting_approval')",
          auditId,
        );
        for (const task of pending) this.finishTaskFailure(task.id, "cancelled", "Audit cancelled by operator");
        const active = this.store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND status IN ('running','queued','waiting_approval')",
          auditId,
        )?.count ?? 0;
        if (active === 0) {
          this.store.run(
            "UPDATE audits SET status = 'cancelled', finished_at = ?, error = 'Cancelled by operator' WHERE id = ?",
            now(),
            auditId,
          );
          this.store.run(
            "UPDATE audit_phases SET status = 'skipped', finished_at = COALESCE(finished_at, ?) WHERE audit_id = ? AND status IN ('pending','running')",
            now(),
            auditId,
          );
          this.events.append({ auditId, type: "audit.cancelled", payload: {} });
        }
        return;
      }
      if (audit.status !== "running") return;

      const maxCost = audit.config ? parseJson<Record<string, unknown>>(audit.config, {}).max_cost_usd : null;
      if (maxCost) {
        const sessions = this.store.all<{ usage: string | null }>(
          "SELECT usage FROM agent_sessions WHERE audit_id = ?",
          auditId,
        );
        const total = sessions.reduce(
          (sum, session) => sum + Number(parseJson<{ cost_usd?: number }>(session.usage ?? "{}", {}).cost_usd ?? 0),
          0,
        );
        if (total > Number(maxCost)) {
          this.store.run(
            "UPDATE audits SET status = 'failed', finished_at = ?, error = ? WHERE id = ?",
            now(),
            `Audit cost budget exceeded: $${total.toFixed(4)} > $${Number(maxCost).toFixed(4)}`,
            auditId,
          );
          this.store.run(
            "UPDATE tasks SET status = 'cancelled', finished_at = ? WHERE audit_id = ? AND status IN ('queued','waiting_approval')",
            now(),
            auditId,
          );
          this.abortAuditRuns(auditId);
          this.events.append({ auditId, type: "audit.budget_exceeded", payload: { total, max: Number(maxCost) } });
          return;
        }
      }

      const tasks = this.store.all<TaskRow>("SELECT * FROM tasks WHERE audit_id = ? ORDER BY phase", auditId);
      const phaseStats = new Map<number, { total: number; terminal: number; completed: number; failed: number; active: number }>();
      for (let phase = 1; phase <= 6; phase += 1) {
        const list = tasks.filter((task) => task.phase === phase);
        phaseStats.set(phase, {
          total: list.length,
          terminal: list.filter((task) => TERMINAL_TASK_STATES.has(task.status)).length,
          completed: list.filter((task) => task.status === "completed").length,
          failed: list.filter((task) => ["failed", "blocked", "cancelled"].includes(task.status)).length,
          active: list.filter((task) => ["queued", "running", "waiting_approval"].includes(task.status)).length,
        });
      }
      const phase1 = phaseStats.get(1)!;
      if (phase1.total > 0 && phase1.failed > 0 && phase1.active === 0 && phase1.completed === 0) {
        this.store.run(
          "UPDATE audits SET status = 'failed', finished_at = ?, error = 'Phase 1 codebase mapping failed' WHERE id = ?",
          now(),
          auditId,
        );
        this.store.run(
          "UPDATE audit_phases SET status = 'failed', finished_at = ? WHERE audit_id = ? AND phase = 1",
          now(),
          auditId,
        );
        this.store.run(
          "UPDATE audit_phases SET status = 'skipped', finished_at = ? WHERE audit_id = ? AND phase > 1 AND status = 'pending'",
          now(),
          auditId,
        );
        this.events.append({ auditId, type: "audit.failed", payload: { reason: "phase1_mapping_failed" } });
        return;
      }

      for (let phase = 1; phase <= 6; phase += 1) {
        const stats = phaseStats.get(phase)!;
        if (stats.total > 0) {
          const status =
            stats.active > 0
              ? "running"
              : stats.failed === stats.total
                ? "failed"
                : "completed";
          const summary = `${stats.completed}/${stats.total} tasks completed${stats.failed ? `, ${stats.failed} failed/blocked/cancelled` : ""}`;
          this.store.run(
            `UPDATE audit_phases SET status = ?, summary = CASE WHEN ? != 'running' THEN COALESCE(summary, ?) ELSE summary END, started_at = COALESCE(started_at, ?), finished_at = CASE WHEN ? != 'running' THEN COALESCE(finished_at, ?) ELSE finished_at END
             WHERE audit_id = ? AND phase = ?`,
            status,
            status,
            summary,
            now(),
            status,
            now(),
            auditId,
            phase,
          );
        }
      }

      const phase2 = phaseStats.get(2)!;
      if (phase2.total > 0 && phase2.active === 0 && phase2.terminal === phase2.total) {
        const candidates = this.store.all<CandidateRow>(
          "SELECT * FROM candidates WHERE audit_id = ? AND status = 'discovered' ORDER BY created_at",
          auditId,
        );
        const cap = Number(loadAuditNumber(audit, "max_confirmations", 12));
        for (const [index, candidate] of candidates.entries()) {
          if (index >= cap) {
            this.store.run("UPDATE candidates SET status = 'inconclusive' WHERE id = ?", candidate.id);
            this.events.append({
              auditId,
              type: "candidate.cap_exceeded",
              payload: { candidate_id: candidate.id, title: candidate.title, cap },
            });
            continue;
          }
          const existing = this.store.get<{ id: string }>(
            "SELECT id FROM tasks WHERE audit_id = ? AND task_key = ?",
            auditId,
            `phase3:candidate:${candidate.id}`,
          );
          if (existing) continue;
          this.createTask({
            auditId,
            phase: 3,
            kind: "phase3.confirm",
            taskKey: `phase3:candidate:${candidate.id}`,
            title: `Phase 3 — Independently confirm: ${candidate.title}`,
            payload: {
              candidate_id: candidate.id,
              discovery_task_id: candidate.discovery_task_id,
              discovery_session_id: candidate.discovery_session_id,
              area_title: candidate.area_id,
            },
            agentRole: "independent_validator",
            priority: 30,
            dependsOn: [candidate.discovery_task_id],
          });
          this.store.run("UPDATE candidates SET status = 'confirming' WHERE id = ?", candidate.id);
        }
        const phase3After = this.store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND phase = 3",
          auditId,
        )?.count ?? 0;
        const totalCandidates = this.store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM candidates WHERE audit_id = ?",
          auditId,
        )?.count ?? 0;
        if (phase3After === 0) {
          this.store.run(
            "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = COALESCE(summary, ?) WHERE audit_id = ? AND phase = 3",
            now(),
            totalCandidates === 0
              ? "No candidates required confirmation."
              : `${totalCandidates} candidate(s) discovered; none entered confirmation due to configuration limits.`,
            auditId,
          );
        }
        this.store.run(
          "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = COALESCE(summary, ?) WHERE audit_id = ? AND phase = 2",
          now(),
          `${phase2.completed} discovery area(s) completed; ${totalCandidates} candidate(s).`,
          auditId,
        );
      }

      const phase3CountAfter = this.store.get<{ count: number }>(
        "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND phase = 3",
        auditId,
      )?.count ?? 0;
      if (phase2.total > 0 && phase2.active === 0 && phase3CountAfter === 0) {
        this.store.run(
          "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = COALESCE(summary, 'No confirmable candidates remained.') WHERE audit_id = ? AND phase = 3",
          now(),
          auditId,
        );
        this.store.run(
          "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = COALESCE(summary, 'No finding persistence was possible.') WHERE audit_id = ? AND phase = 4",
          now(),
          auditId,
        );
        this.store.run(
          "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = COALESCE(summary, 'No findings required reverification.') WHERE audit_id = ? AND phase = 5",
          now(),
          auditId,
        );
      }
      const phase3 = phaseStats.get(3)!;
      if (phase3.total > 0 && phase3.active === 0 && phase3.terminal === phase3.total) {
        const confirmed = this.store.all<CandidateRow>(
          "SELECT * FROM candidates WHERE audit_id = ? AND status = 'confirmed' AND finding_id IS NULL",
          auditId,
        );
        for (const candidate of confirmed) {
          const verification = this.store.get<VerificationRow>(
            "SELECT * FROM verifications WHERE candidate_id = ? AND kind = 'confirmation' AND verdict = 'CONFIRMED' ORDER BY created_at DESC LIMIT 1",
            candidate.id,
          );
          if (!verification) continue;
          this.createTask({
            auditId,
            phase: 4,
            kind: "phase4.persist",
            taskKey: `phase4:candidate:${candidate.id}`,
            title: `Phase 4 — Persist structured finding: ${candidate.title}`,
            payload: { candidate_id: candidate.id, verification_id: verification.id },
            agentRole: null,
            priority: 20,
            dependsOn: [verificationTaskId(this.store, auditId, verification.agent_session_id) ?? candidate.discovery_task_id],
          });
          this.store.run("UPDATE candidates SET status = 'confirming' WHERE id = ?", candidate.id);
        }
        const phase4After = this.store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND phase = 4",
          auditId,
        )?.count ?? 0;
        const phase5After = this.store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND phase = 5",
          auditId,
        )?.count ?? 0;
        if (phase4After === 0 && phase5After === 0) {
          this.store.run(
            "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = ? WHERE audit_id = ? AND phase = 4",
            now(),
            "No candidate passed independent confirmation.",
            auditId,
          );
          this.store.run(
            "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = ? WHERE audit_id = ? AND phase = 5",
            now(),
            "No findings required reverification.",
            auditId,
          );
        }
      }

      const phase4 = phaseStats.get(4)!;
      if (phase4.total > 0 && phase4.active === 0 && phase4.terminal === phase4.total) {
        const findings = this.store.all<FindingRow>(
          "SELECT * FROM findings WHERE audit_id = ? AND status = 'confirmed'",
          auditId,
        );
        const reverificationCap = Number(loadAuditNumber(audit, "max_reverifications", 12));
        let canonicalRetests = this.store.get<{ count: number }>(
          "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND kind = 'phase5.reverify' AND task_key NOT LIKE '%:manual:%'",
          auditId,
        )?.count ?? 0;
        for (const finding of findings) {
          const existing = this.store.get<{ id: string }>(
            "SELECT id FROM tasks WHERE audit_id = ? AND task_key = ?",
            auditId,
            `phase5:finding:${finding.id}`,
          );
          if (existing) continue;
          if (canonicalRetests >= reverificationCap) {
            this.store.run(
              "UPDATE findings SET status = 'unresolved', retest_decision = 'UNRESOLVED', updated_at = ? WHERE id = ?",
              now(),
              finding.id,
            );
            this.events.append({
              auditId,
              type: "finding.reverification_cap_exceeded",
              payload: { finding_id: finding.id, code: finding.code, cap: reverificationCap },
            });
            continue;
          }
          this.createTask({
            auditId,
            phase: 5,
            kind: "phase5.reverify",
            taskKey: `phase5:finding:${finding.id}`,
            title: `Phase 5 — Independently reverify ${finding.code}`,
            payload: { finding_id: finding.id },
            agentRole: "retest_auditor",
            priority: 40,
          });
          canonicalRetests += 1;
        }
      }

      const phase4Final = phaseStats.get(4)!;
      const phase5Count = this.store.get<{ count: number }>(
        "SELECT COUNT(*) AS count FROM tasks WHERE audit_id = ? AND phase = 5",
        auditId,
      )?.count ?? 0;
      if (
        phase4Final.total > 0 &&
        phase4Final.active === 0 &&
        phase4Final.terminal === phase4Final.total &&
        phase5Count === 0
      ) {
        this.store.run(
          "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = ? WHERE audit_id = ? AND phase = 5",
          now(),
          "No reverification tasks were scheduled; see finding statuses and configured limits.",
          auditId,
        );
      }
      const phase5 = phaseStats.get(5)!;
      const anyActive = [2, 3, 4, 5].some((phase) => phaseStats.get(phase)!.active > 0);
      const latestReport = this.store.get<TaskRow>(
        "SELECT * FROM tasks WHERE audit_id = ? AND kind = 'phase6.report' ORDER BY created_at DESC, rowid DESC LIMIT 1",
        auditId,
      );
      const postValidationPhases = this.store.all<{ phase: number; status: string }>(
        "SELECT phase, status FROM audit_phases WHERE audit_id = ? AND phase BETWEEN 3 AND 5",
        auditId,
      );
      const postValidationComplete =
        postValidationPhases.length === 3 &&
        postValidationPhases.every((phase) => ["completed", "skipped", "failed"].includes(phase.status));
      const allEarlierTerminal =
        phase1.completed > 0 &&
        [2, 3, 4, 5].every((phase) => {
          const stats = phaseStats.get(phase)!;
          return stats.active === 0;
        }) &&
        (phase5.total === 0 || phase5.terminal === phase5.total);
      if (
        !latestReport &&
        allEarlierTerminal &&
        postValidationComplete &&
        phase1.completed > 0 &&
        phase2.total > 0 &&
        !anyActive
      ) {
        this.createTask({
          auditId,
          phase: 6,
          kind: "phase6.report",
          taskKey: "phase6:report",
          title: "Phase 6 — Generate final security reports",
          payload: {},
          agentRole: null,
          priority: 10,
        });
      }

      if (latestReport) {
        const reportActive = ["queued", "running", "waiting_approval"].includes(latestReport.status);
        const newestRetest = this.store.get<{ finished_at: string | null }>(
          "SELECT finished_at FROM tasks WHERE audit_id = ? AND phase = 5 AND status = 'completed' ORDER BY finished_at DESC LIMIT 1",
          auditId,
        );
        const staleReport =
          latestReport.status === "completed" &&
          Boolean(newestRetest?.finished_at) &&
          (latestReport.started_at ?? latestReport.created_at) < String(newestRetest!.finished_at);
        if (staleReport && !reportActive && !anyActive && postValidationComplete) {
          this.createTask({
            auditId,
            phase: 6,
            kind: "phase6.report",
            taskKey: `phase6:report:rebuild:${Date.now()}`,
            title: "Phase 6 — Regenerate reports after reverification",
            payload: { trigger: "stale_report_rebuild" },
            agentRole: null,
            priority: 10,
          });
          this.events.append({
            auditId,
            type: "report.rebuild_scheduled",
            payload: { previous_report_id: latestReport.id, newest_retest: newestRetest!.finished_at },
          });
        } else if (!reportActive && !anyActive && postValidationComplete) {
          if (latestReport.status === "completed") {
            const failures = tasks.filter((task) => ["failed", "blocked", "cancelled"].includes(task.status)).length;
            const coverageFailures = this.store.get<{ count: number }>(
              "SELECT COUNT(*) AS count FROM coverage WHERE audit_id = ? AND status IN ('FAILED','BLOCKED')",
              auditId,
            )?.count ?? 0;
            const finalStatus = failures > 0 || coverageFailures > 0 ? "completed_with_errors" : "completed";
            this.store.run(
              "UPDATE audits SET status = ?, finished_at = ? WHERE id = ?",
              finalStatus,
              now(),
              auditId,
            );
            this.store.run(
              "UPDATE audit_phases SET status = 'completed', finished_at = COALESCE(finished_at, ?), summary = ? WHERE audit_id = ? AND phase = 6",
              now(),
              `Generated ${REPORT_FORMATS.length} report formats; ${failures} failed task(s), ${coverageFailures} failed/blocked area(s).`,
              auditId,
            );
            this.events.append({
              auditId,
              type: "audit.completed",
              payload: {
                status: finalStatus,
                failed_tasks: failures,
                failed_areas: coverageFailures,
              },
            });
          } else if (["failed", "cancelled"].includes(latestReport.status)) {
            this.store.run(
              "UPDATE audits SET status = 'failed', finished_at = ?, error = COALESCE(error, ?) WHERE id = ?",
              now(),
              latestReport.error ?? "Report generation failed",
              auditId,
            );
            this.store.run(
              "UPDATE audit_phases SET status = 'failed', finished_at = ? WHERE audit_id = ? AND phase = 6",
              now(),
              auditId,
            );
            this.events.append({
              auditId,
              type: "audit.failed",
              payload: { reason: "report_generation_failed", error: latestReport.error },
            });
          }
        }
      }



      const currentPhaseTasks = tasks.filter((task) => task.phase === audit.current_phase);
      if (currentPhaseTasks.length > 0) {
        const highest = Math.max(...tasks.map((task) => task.phase));
        this.store.run("UPDATE audits SET current_phase = ? WHERE id = ? AND current_phase < ?", highest, auditId, highest);
      }
    });
  }
}

function loadAuditNumber(audit: AuditRow, key: string, fallback: number): number {
  const config = parseJson<Record<string, unknown>>(audit.config, {});
  const value = Number(config[key]);
  return Number.isFinite(value) ? value : fallback;
}

function verificationTaskId(store: Store, auditId: string, sessionId: string): string | null {
  const row = store.get<{ id: string }>(
    "SELECT id FROM tasks WHERE audit_id = ? AND kind = 'phase3.confirm' AND agent_session_id = ? ORDER BY finished_at DESC LIMIT 1",
    auditId,
    sessionId,
  );
  return row?.id ?? null;
}
