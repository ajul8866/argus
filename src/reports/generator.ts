import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { APP_NAME, APP_VERSION, REPORT_DIR } from "../config.ts";
import type { Store } from "../db/index.ts";
import type { EventLog } from "../events.ts";
import { getSetting } from "../settings.ts";
import { AppError, now, parseJson, sha256, truncate, uid } from "../util.ts";
import { redactObject, redactSecrets } from "../security/redact.ts";
import type { EvidenceStore, EvidenceRow } from "../orchestrator/evidence.ts";
import { buildFallbackPdf } from "./pdf.ts";

export type ReportFormat = "markdown" | "json" | "html" | "pdf";
export const REPORT_FORMATS: ReportFormat[] = ["markdown", "json", "html", "pdf"];

type ReportData = NonNullable<Awaited<ReturnType<ReportService["loadData"]>>>;

export class ReportService {
  constructor(
    private readonly config: Config,
    private readonly store: Store,
    private readonly evidence: EvidenceStore,
    private readonly events: EventLog,
  ) {}

  async generate(
    auditId: string,
    formats: ReportFormat[],
    actor: string,
  ): Promise<Array<{ id: string; format: ReportFormat; path: string; sha256: string; size: number }>> {
    const data = await this.loadData(auditId);
    if (!data) throw new Error(`Audit not found: ${auditId}`);
    const generated: Array<{ id: string; format: ReportFormat; path: string; sha256: string; size: number }> = [];
    const directory = join(REPORT_DIR(this.config), auditId);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    for (const format of [...new Set(formats)]) {
      const id = uid();
      const filename = join(directory, `${stamp}-${id}-${data.findingCodePrefix}-${format}.${extension(format)}`);
      let body: Uint8Array;
      try {
        body = await this.render(data, format);
      } catch (error) {
        this.store.run(
          `INSERT INTO reports (id, audit_id, format, status, path, sha256, size, meta, generated_at)
           VALUES (?, ?, ?, 'failed', NULL, NULL, NULL, ?, ?)`,
          id,
          auditId,
          format,
          JSON.stringify({ error: String(error), actor }),
          now(),
        );
        this.events.append({
          auditId,
          type: "report.failed",
          payload: { format, error: String(error) },
        });
        continue;
      }
      await writeFile(filename, body, { mode: 0o600, flag: "wx" });
      const digest = sha256(body);
      const size = (await stat(filename)).size;
      this.store.run(
        `INSERT INTO reports (id, audit_id, format, status, path, sha256, size, meta, generated_at)
         VALUES (?, ?, ?, 'generated', ?, ?, ?, ?, ?)`,
        id,
        auditId,
        format,
        filename,
        digest,
        size,
        JSON.stringify({
          actor,
          findings: data.findings.length,
          verified: data.findings.filter((finding) => finding.status === "reverified").length,
          chain_ok: data.chain.ok,
        }),
        now(),
      );
      generated.push({ id, format, path: filename, sha256: digest, size });
    }
    this.events.append({
      auditId,
      type: "report.generated",
      payload: { formats: generated.map((entry) => entry.format), count: generated.length },
    });
    return generated;
  }

  private async render(data: ReportData, format: ReportFormat): Promise<Uint8Array> {
    if (format === "json") return new TextEncoder().encode(this.renderJson(data));
    const markdown = this.renderMarkdown(data);
    if (format === "markdown") return new TextEncoder().encode(markdown);
    const html = this.renderHtml(data, markdown);
    if (format === "html") return new TextEncoder().encode(html);
    return this.renderPdf(data, html, markdown);
  }

  private async renderPdf(data: ReportData, html: string, markdown: string): Promise<Uint8Array> {
    const directory = join(REPORT_DIR(this.config), data.audit.id);
    const htmlPath = join(directory, `.render-${uid()}.html`);
    const pdfPath = join(directory, `.render-${uid()}.pdf`);
    await writeFile(htmlPath, html, { mode: 0o600 });
    try {
      const proc = Bun.spawn(
        [
          this.config.chromeBin,
          "--headless=new",
          "--disable-gpu",
          "--no-sandbox",
          "--disable-dev-shm-usage",
          "--no-pdf-header-footer",
          `--print-to-pdf=${pdfPath}`,
          `file://${htmlPath}`,
        ],
        { stdout: "ignore", stderr: "ignore", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } },
      );
      const timer = setTimeout(() => proc.kill("SIGKILL"), 90_000);
      const code = await proc.exited;
      clearTimeout(timer);
      if (code === 0) {
        const bytes = await readFile(pdfPath);
        if (bytes.length > 1_000 && bytes.subarray(0, 5).toString() === "%PDF-") return bytes;
      }
    } catch {
      // fall through to the dependency-free PDF writer
    } finally {
      await Promise.allSettled([Bun.file(htmlPath).delete(), Bun.file(pdfPath).delete()]);
    }
    return buildFallbackPdf(this.markdownLines(markdown), `${data.project.name} — Security Audit`);
  }

  private markdownLines(markdown: string): string[] {
    return markdown
      .split("\n")
      .map((line) =>
        line
          .replace(/^#{1,6}\s+/, "")
          .replace(/\*\*([^*]+)\*\*/g, "$1")
          .replace(/`([^`]+)`/g, "$1")
          .replace(/^\s*[-*]\s+/, "- ")
          .replace(/^\|/, "")
          .replace(/\|$/g, "")
          .replace(/\|/g, " · "),
      );
  }

  async loadData(auditId: string) {
    const audit = this.store.get<{
      id: string;
      project_id: string;
      repository_id: string;
      status: string;
      config: string;
      created_at: string;
      started_at: string | null;
      finished_at: string | null;
    }>("SELECT * FROM audits WHERE id = ?", auditId);
    if (!audit) return null;
    const project = this.store.get<{
      id: string;
      name: string;
      description: string;
      source_path: string;
      default_branch: string | null;
      scope_include: string;
      scope_exclude: string;
      authorized_by: string;
      authorization_ref: string;
      created_at: string;
    }>("SELECT * FROM projects WHERE id = ?", audit.project_id)!;
    const repository = this.store.get<{
      id: string;
      commit_sha: string | null;
      branch: string | null;
      languages: string;
      frameworks: string;
      inventory: string;
      graph: string;
      file_count: number;
      imported_at: string;
    }>("SELECT * FROM repositories WHERE id = ?", audit.repository_id)!;
    const phases = this.store.all<{
      phase: number;
      name: string;
      status: string;
      started_at: string | null;
      finished_at: string | null;
      summary: string | null;
    }>("SELECT * FROM audit_phases WHERE audit_id = ? ORDER BY phase", auditId);
    const coverage = this.store.all<{
      area_id: string;
      title: string;
      status: string;
      files: string;
      notes: string | null;
      updated_at: string;
    }>("SELECT * FROM coverage WHERE audit_id = ? ORDER BY area_id", auditId);
    const findings = this.store.all<{
      id: string;
      code: string;
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
    }>("SELECT * FROM findings WHERE audit_id = ? ORDER BY code", auditId);
    const evidenceRows = this.store.all<EvidenceRow>(
      "SELECT * FROM evidence WHERE audit_id = ? ORDER BY rowid",
      auditId,
    );
    const excerptsByFinding: Record<string, Array<{ path: string; start_line: number; end_line: number; quote: string }>> = {};
    for (const row of evidenceRows) {
      if (row.kind !== "code_excerpt" || !row.finding_id) continue;
      try {
        const verified = await this.evidence.content(row.id);
        if (!verified) continue;
        const content = JSON.parse(verified.content) as {
          path?: string;
          start_line?: number;
          end_line?: number;
          quote?: string;
        };
        if (!content || typeof content !== "object" || Array.isArray(content) || !content.path || !content.quote) continue;
        const list = excerptsByFinding[row.finding_id] ?? [];
        list.push({
          path: content.path,
          start_line: Number(content.start_line ?? 1),
          end_line: Number(content.end_line ?? content.start_line ?? 1),
          quote: content.quote,
        });
        excerptsByFinding[row.finding_id] = list;
      } catch (error) {
        // Integrity failures stay out of the report. verifyChain records the break.
        if (!(error instanceof AppError)) throw error;
      }
    }
    const verifications = this.store.all<{
      id: string;
      kind: string;
      verdict: string;
      rationale: string;
      agent_session_id: string;
      created_at: string;
      finding_id: string | null;
      evidence_check: string;
    }>("SELECT * FROM verifications WHERE audit_id = ? ORDER BY created_at", auditId);
    const tasks = this.store.all<{
      id: string;
      phase: number;
      kind: string;
      title: string;
      status: string;
      agent_role: string | null;
      harness: string | null;
      model: string | null;
      attempts: number;
      error: string | null;
      created_at: string;
      started_at: string | null;
      finished_at: string | null;
      result: string | null;
    }>("SELECT * FROM tasks WHERE audit_id = ? ORDER BY phase, created_at", auditId);
    const sessions = this.store.all<{
      id: string;
      role: string;
      harness: string;
      model: string | null;
      status: string;
      sandbox_mode: string;
      usage: string | null;
      started_at: string;
      ended_at: string | null;
    }>("SELECT * FROM agent_sessions WHERE audit_id = ? ORDER BY started_at", auditId);
    const reports = this.store.all<{
      id: string;
      format: string;
      status: string;
      path: string | null;
      sha256: string | null;
      size: number | null;
      generated_at: string;
    }>("SELECT * FROM reports WHERE audit_id = ? ORDER BY generated_at DESC", auditId);
    const mapTask = this.store.get<{ result: string }>(
      "SELECT result FROM tasks WHERE audit_id = ? AND kind = 'phase1.map' AND status = 'completed' ORDER BY finished_at DESC LIMIT 1",
      auditId,
    );
    const mapData = mapTask ? parseJson<{ data?: Record<string, unknown> }>(mapTask.result, {}).data ?? null : null;
    const chain = await this.evidence.verifyChain(auditId);
    const settings = {
      organization: getSetting(this.store, "reports.organization", "Argus Security"),
      classification: getSetting(this.store, "reports.classification", "Confidential"),
    };
    const usage = sessions.reduce(
      (total, session) => {
        const parsed = parseJson<{ cost_usd?: number; input_tokens?: number; output_tokens?: number }>(
          session.usage ?? "{}",
          {},
        );
        total.cost_usd += parsed.cost_usd ?? 0;
        total.input_tokens += parsed.input_tokens ?? 0;
        total.output_tokens += parsed.output_tokens ?? 0;
        return total;
      },
      { cost_usd: 0, input_tokens: 0, output_tokens: 0 },
    );
    const assessmentPhases = phases.filter((phase) => phase.phase <= 5);
    const assessmentComplete =
      assessmentPhases.length === 5 && assessmentPhases.every((phase) => ["completed", "skipped"].includes(phase.status));
    const assessmentErrors =
      assessmentPhases.some((phase) => ["failed", "blocked"].includes(phase.status)) ||
      tasks.some((task) => ["failed", "blocked"].includes(task.status)) ||
      coverage.some((row) => ["FAILED", "BLOCKED"].includes(row.status));
    const displayStatus =
      audit.status === "running" && assessmentComplete
        ? assessmentErrors
          ? "completed_with_errors"
          : "completed"
        : audit.status;
    const displayFinishedAt =
      audit.status === "running" && assessmentComplete ? now() : audit.finished_at;
    const phase6InProgress = audit.status === "running" && assessmentComplete;
    const displayPhases = phases.map((phase) =>
      phase.phase === 6 && phase6InProgress
        ? {
            ...phase,
            status: "completed",
            finished_at: phase.finished_at ?? now(),
            summary: phase.summary ?? "Report generated from immutable records.",
          }
        : phase,
    );
    const displayTasks = tasks.map((task) =>
      phase6InProgress && task.kind === "phase6.report" && task.status === "running"
        ? { ...task, status: "completed", finished_at: task.finished_at ?? now() }
        : task,
    );
    return {
      audit: {
        ...audit,
        config: parseJson<Record<string, unknown>>(audit.config, {}),
        display_status: displayStatus,
        display_finished_at: displayFinishedAt,
      },
      project: {
        ...project,
        scope: { include: parseJson<string[]>(project.scope_include, []), exclude: parseJson<string[]>(project.scope_exclude, []) },
      },
      repository: {
        ...repository,
        languages: parseJson<Record<string, number>>(repository.languages, {}),
        frameworks: parseJson<string[]>(repository.frameworks, []),
        inventory: parseJson<{ files?: Array<{ path: string; lines?: number }>; endpoints?: unknown[]; auth_boundaries?: unknown[]; total_bytes?: number; truncated?: boolean }>(repository.inventory, {}),
        graph: parseJson<Record<string, unknown>>(repository.graph, {}),
      },
      phases: displayPhases,
      coverage: coverage.map((row) => ({ ...row, files: parseJson<string[]>(row.files, []) })),
      findings: findings.map((finding) => ({
        ...finding,
        files: parseJson<Array<{ path: string; start_line: number; end_line: number }>>(finding.files, []),
        preconditions: parseJson<string[]>(finding.preconditions, []),
        reproduction: parseJson<string[]>(finding.reproduction, []),
      })),
      evidence: evidenceRows,
      evidence_by_finding: groupEvidenceByFinding(evidenceRows),
      excerpts_by_finding: excerptsByFinding,
      verifications: verifications.map((row) => ({ ...row, evidence_check: parseJson<Record<string, unknown>>(row.evidence_check, {}) })),
      tasks: displayTasks,
      sessions,
      reports,
      map_data: mapData,
      chain,
      settings,
      usage,
      generated_at: now(),
      findingCodePrefix: findings[0]?.code?.split("-")[0] ?? "ARG",
    };
  }

  private renderJson(rawData: ReportData): string {
    const data = redactObject(rawData);
    const verified = data.findings.filter((finding) => finding.status === "reverified");
    const unresolved = data.findings.filter((finding) =>
      ["confirmed", "needs_correction", "unresolved"].includes(finding.status),
    );
    const rejected = data.findings.filter((finding) => finding.status === "rejected");
    return `${JSON.stringify(
      {
        schema: "argus.audit-report/v1",
        generated_at: data.generated_at,
        tool: { name: APP_NAME, version: APP_VERSION },
        organization: data.settings.organization,
        classification: data.settings.classification,
        audit: {
          id: data.audit.id,
          status: data.audit.display_status,
          database_status: data.audit.status,
          created_at: data.audit.created_at,
          started_at: data.audit.started_at,
          finished_at: data.audit.display_finished_at,
          config: data.audit.config,
        },
        project: {
          name: data.project.name,
          description: data.project.description,
          authorized_by: data.project.authorized_by,
          authorization_ref: data.project.authorization_ref,
          scope: data.project.scope,
        },
        repository: {
          commit: data.repository.commit_sha,
          branch: data.repository.branch,
          file_count: data.repository.file_count,
          languages: data.repository.languages,
          frameworks: data.repository.frameworks,
          imported_at: data.repository.imported_at,
        },
        summary: {
          verified: verified.length,
          unresolved: unresolved.length,
          rejected: rejected.length,
          evidence_chain_ok: data.chain.ok,
          executions: {
            tasks: data.tasks.length,
            completed_tasks: data.tasks.filter((task) => task.status === "completed").length,
            failed_tasks: data.tasks.filter((task) => task.status === "failed").length,
            agent_sessions: data.sessions.length,
            harnesses: [...new Set(data.sessions.map((session) => session.harness))],
            cost_usd: Number(data.usage.cost_usd.toFixed(4)),
          },
        },
        phases: data.phases,
        coverage: data.coverage,
        findings: data.findings.map((finding) => ({
          ...finding,
          verified_excerpts: data.excerpts_by_finding[finding.id] ?? [],
        })),
        verifications: data.verifications,
        evidence: data.evidence.map((row) => ({
          id: row.id,
          kind: row.kind,
          title: row.title,
          sha256: row.sha256,
          prev_hash: row.prev_hash,
          chain_hash: row.chain_hash,
          finding_id: row.finding_id,
          task_id: row.task_id,
          created_at: row.created_at,
        })),
        evidence_chain: data.chain,
        tasks: data.tasks.map((task) => ({ ...task, result: task.result ? "[stored]" : null })),
        agent_sessions: data.sessions,
        reports: data.reports,
        limitations: this.limitations(data),
      },
      null,
      2,
    )}\n`;
  }

  private limitations(data: ReportData): string[] {
    const limitations = [
      "This assessment is source-code analysis. No live system was contacted and no exploit was executed unless a finding explicitly states otherwise.",
      "Agent output is treated as untrusted; only findings that passed the platform evidence gate and independent reverification are presented as verified.",
      "Coverage is bounded by the authorized scope, model context, and configured limits. Completion of scheduled tasks does not prove exhaustive vulnerability discovery.",
      "LLM-based analysis can miss issues, misinterpret framework behavior, or produce incorrect remediation advice. Human review is required before remediation or disclosure.",
    ];
    if (data.repository.inventory.truncated) limitations.push("The repository inventory was truncated by file-count limits; some authorized files were not analyzed.");
    const failedAreas = data.coverage.filter((row) => ["FAILED", "BLOCKED"].includes(row.status));
    if (failedAreas.length > 0) {
      limitations.push(`${failedAreas.length} assessment area(s) failed or were blocked: ${failedAreas.map((row) => row.area_id).join(", ")}.`);
    }
    if (!data.chain.ok) limitations.push(`Evidence chain verification failed at ${data.chain.broken_at}: ${data.chain.reason}.`);
    if (!data.repository.commit_sha) limitations.push("The repository was not a git worktree; findings are tied to the imported file hashes, not a commit.");
    const cap = Number(data.audit.config.max_confirmations ?? 0);
    if (cap > 0 && data.findings.length >= cap) limitations.push(`Confirmation was capped at ${cap} candidates by audit configuration.`);
    return limitations;
  }

  private renderMarkdown(data: ReportData): string {
    const verified = data.findings.filter((finding) => finding.status === "reverified");
    const unresolved = data.findings.filter((finding) => ["confirmed", "needs_correction", "unresolved"].includes(finding.status));
    const rejected = data.findings.filter((finding) => finding.status === "rejected");
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
    verified.sort((a, b) => (severityOrder[a.severity as keyof typeof severityOrder] ?? 9) - (severityOrder[b.severity as keyof typeof severityOrder] ?? 9));
    const counts = verified.reduce<Record<string, number>>((accumulator, finding) => {
      accumulator[finding.severity] = (accumulator[finding.severity] ?? 0) + 1;
      return accumulator;
    }, {});
    const lines: string[] = [];
    lines.push(`# ${data.project.name} — Security Audit Report`);
    lines.push("");
    lines.push(`**Audit ID:** ${data.audit.id}  `);
    lines.push(`**Status:** ${data.audit.display_status}  `);
    lines.push(`**Repository commit:** ${data.repository.commit_sha ?? "not a git repository"}  `);
    lines.push(`**Assessment window:** ${data.audit.started_at ?? data.audit.created_at} → ${data.audit.display_finished_at ?? "in progress"}  `);
    lines.push(`**Classification:** ${data.settings.classification}  `);
    lines.push(`**Generated:** ${data.generated_at} by ${APP_NAME} ${APP_VERSION}`);
    lines.push("");
    lines.push("## Executive summary");
    lines.push("");
    lines.push(`Argus performed a six-phase autonomous source-code security audit of **${data.project.name}** across ${data.repository.file_count} in-scope files. The workflow used independent agent sessions and required every verified finding to pass an exact-source evidence check plus an independent retest.`);
    lines.push("");
    lines.push(`- **Verified findings:** ${verified.length}${verified.length ? ` (${Object.entries(counts).map(([severity, count]) => `${count} ${severity}`).join(", ")})` : ""}`);
    lines.push(`- **Unresolved / awaiting retest:** ${unresolved.length}`);
    lines.push(`- **Rejected after retest:** ${rejected.length}`);
    lines.push(`- **Assessment areas:** ${data.coverage.length}`);
    lines.push(`- **Harnesses used:** ${[...new Set(data.sessions.map((session) => session.harness))].join(", ") || "none"}`);
    lines.push(`- **Total agent sessions:** ${data.sessions.length}; reported cost: $${data.usage.cost_usd.toFixed(4)}`);
    lines.push(`- **Evidence chain:** ${data.chain.ok ? `verified (${data.chain.count} records)` : `FAILED at ${data.chain.broken_at}`}`);
    lines.push("");
    if (verified.length === 0) {
      lines.push("No finding reached the REVERIFIED state. This is a coverage-bounded negative result and must not be read as proof that the repository is free of vulnerabilities.");
      lines.push("");
    }
    lines.push("## Scope and authorization");
    lines.push("");
    if (data.project.authorized_by) lines.push(`- **Authorized by:** ${data.project.authorized_by}`);
    if (data.project.authorization_ref) lines.push(`- **Authorization reference:** ${data.project.authorization_ref}`);
    lines.push(`- **Source path (platform-side):** ${data.project.source_path}`);
    lines.push(`- **Include globs:** ${data.project.scope.include.join(", ")}`);
    lines.push(`- **Exclude globs:** ${data.project.scope.exclude.join(", ")}`);
    lines.push(`- **Commit:** ${data.repository.commit_sha ?? "n/a"}; branch: ${data.repository.branch ?? "n/a"}`);
    lines.push("");
    lines.push("## Methodology");
    lines.push("");
    const phaseDescriptions = [
      "Codebase mapping: static inventory plus an agent-produced architecture and attack-surface map, divided into assessment areas.",
      "Systematic vulnerability discovery: independent researcher sessions per area, with source-to-sink reasoning and verbatim evidence excerpts.",
      "Independent confirmation: a fresh validator session that did not discover the candidate attempts to refute it; the platform verifies each excerpt against the audited commit.",
      "Structured findings: deterministic normalization and persistence with immutable provenance and hash-chained evidence.",
      "Independent reverification: another fresh session re-derives the issue from code and original evidence; previous verification history remains immutable.",
      "Final reporting: deterministic assembly from database records only. No result is invented or generated from memory.",
    ];
    for (const [index, description] of phaseDescriptions.entries()) {
      lines.push(`${index + 1}. ${description}`);
    }
    lines.push("");
    lines.push("## Repository architecture");
    lines.push("");
    lines.push(`- **Languages:** ${Object.entries(data.repository.languages).map(([language, count]) => `${language} (${count})`).join(", ") || "not detected"}`);
    lines.push(`- **Frameworks:** ${data.repository.frameworks.join(", ") || "not detected"}`);
    const mapSummary = data.map_data && typeof data.map_data.summary === "string" ? data.map_data.summary : null;
    if (mapSummary) {
      lines.push("");
      lines.push(mapSummary);
    }
    const modules = Array.isArray(data.map_data?.modules) ? (data.map_data!.modules as Array<{ name?: string; path?: string; purpose?: string }>) : [];
    if (modules.length > 0) {
      lines.push("");
      lines.push("| Module | Path | Purpose |");
      lines.push("| --- | --- | --- |");
      for (const module of modules.slice(0, 40)) {
        lines.push(`| ${escapeTable(module.name ?? "")} | \`${escapeTable(module.path ?? "")}\` | ${escapeTable(module.purpose ?? "")} |`);
      }
    }
    lines.push("");
    lines.push("## Coverage and limitations");
    lines.push("");
    lines.push("| Area | Status | Files | Notes |");
    lines.push("| --- | --- | ---: | --- |");
    for (const row of data.coverage) {
      lines.push(`| ${escapeTable(row.title)} (\`${escapeTable(row.area_id)}\`) | ${row.status} | ${row.files.length} | ${escapeTable(row.notes ?? "")} |`);
    }
    lines.push("");
    for (const limitation of this.limitations(data)) lines.push(`- ${limitation}`);
    lines.push("");
    lines.push("## Verified findings");
    lines.push("");
    if (verified.length === 0) {
      lines.push("_None._");
      lines.push("");
    }
    for (const finding of verified) {
      lines.push(`### ${finding.code} — ${finding.title}`);
      lines.push("");
      lines.push(`- **Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`- **Status:** ${finding.status}`);
      lines.push(`- **Category / CWE:** ${finding.category} / ${finding.cwe ?? "unclassified"}`);
      lines.push(`- **Commit:** ${finding.repository_commit ?? "n/a"}`);
      lines.push(`- **Discovery session:** ${finding.discovery_session_id ?? "n/a"}`);
      lines.push(`- **Verification session:** ${finding.verification_session_id ?? "n/a"}`);
      lines.push(`- **Retest session:** ${finding.retest_session_id ?? "n/a"}`);
      lines.push("");
      lines.push("**Affected locations**");
      for (const file of finding.files) lines.push(`- \`${file.path}:${file.start_line}-${file.end_line}\``);
      lines.push("");
      const excerpts = data.excerpts_by_finding[finding.id] ?? [];
      if (excerpts.length > 0) {
        lines.push("**Verified source evidence**");
        lines.push("");
        for (const excerpt of excerpts) {
          lines.push(`\`${excerpt.path}:${excerpt.start_line}-${excerpt.end_line}\``);
          lines.push("");
          lines.push("````text");
          lines.push(excerpt.quote);
          lines.push("````");
          lines.push("");
        }
      }
      lines.push("**Root cause**");
      lines.push("");
      lines.push(finding.root_cause);
      lines.push("");
      lines.push("**Preconditions**");
      lines.push("");
      for (const precondition of finding.preconditions) lines.push(`- ${precondition}`);
      if (finding.preconditions.length === 0) lines.push("- None recorded.");
      lines.push("");
      lines.push("**Reproduction reasoning**");
      lines.push("");
      for (const [index, step] of finding.reproduction.entries()) lines.push(`${index + 1}. ${step}`);
      if (finding.reproduction.length === 0) lines.push("_No reproduction steps recorded._");
      lines.push("");
      lines.push("**Expected vs. observed**");
      lines.push("");
      lines.push(`- Expected: ${finding.expected}`);
      lines.push(`- Observed: ${finding.observed}`);
      lines.push("");
      lines.push("**Impact**");
      lines.push("");
      lines.push(finding.impact);
      lines.push("");
      lines.push("**Remediation**");
      lines.push("");
      lines.push(finding.remediation);
      lines.push("");
      const evidence = data.evidence_by_finding[finding.id] ?? [];
      if (evidence.length > 0) {
        lines.push("**Evidence index**");
        lines.push("");
        lines.push("| Evidence | Kind | SHA-256 | Chain hash |");
        lines.push("| --- | --- | --- | --- |");
        for (const item of evidence) {
          lines.push(`| ${escapeTable(item.title)} | ${item.kind} | \`${item.sha256}\` | \`${item.chain_hash}\` |`);
        }
        lines.push("");
      }
    }
    lines.push("## Unresolved findings");
    lines.push("");
    if (unresolved.length === 0) {
      lines.push("_None._");
      lines.push("");
    }
    for (const finding of unresolved) {
      lines.push(`### ${finding.code} — ${finding.title}`);
      lines.push("");
      lines.push(`- **Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`- **Status:** ${finding.status}`);
      lines.push(`- **Category / CWE:** ${finding.category} / ${finding.cwe ?? "unclassified"}`);
      for (const file of finding.files) lines.push(`- **Location:** \`${file.path}:${file.start_line}-${file.end_line}\``);
      lines.push("");
      lines.push("**Root cause**");
      lines.push("");
      lines.push(finding.root_cause);
      lines.push("");
      lines.push("**Why it remains unresolved**");
      lines.push("");
      lines.push(
        finding.retest_decision === "NEEDS_CORRECTION"
          ? "Independent reverification accepted the code-level issue but found material impact, completeness, or accuracy corrections that the workflow did not resolve automatically."
          : finding.retest_decision === "UNRESOLVED"
            ? "Independent reverification did not reach a defensible final decision within the configured limits."
            : "The finding did not complete independent reverification before the audit closed.",
      );
      lines.push("");
      lines.push("**Impact as recorded**");
      lines.push("");
      lines.push(finding.impact);
      lines.push("");
      lines.push("_This item requires human review before remediation, disclosure, or closure._");
      lines.push("");
    }
    lines.push("");
    lines.push("## Rejected findings");
    lines.push("");
    if (rejected.length === 0) lines.push("_None._");
    for (const finding of rejected) {
      lines.push(`- **${finding.code} — ${finding.title}** was rejected during independent reverification. Retained for transparency; not a confirmed vulnerability.`);
    }
    lines.push("");
    lines.push("## Execution and evidence");
    lines.push("");
    lines.push(`- Tasks: ${data.tasks.length} total, ${data.tasks.filter((task) => task.status === "completed").length} completed, ${data.tasks.filter((task) => task.status === "failed").length} failed.`);
    lines.push(`- Agent sessions: ${data.sessions.length}. Harnesses: ${[...new Set(data.sessions.map((session) => session.harness))].join(", ") || "none"}.`);
    lines.push(`- Evidence records: ${data.chain.count}. Chain verification: ${data.chain.ok ? "OK" : "FAILED"}.`);
    lines.push(`- Reported token usage: ${data.usage.input_tokens} input, ${data.usage.output_tokens} output; reported cost $${data.usage.cost_usd.toFixed(4)}.`);
    lines.push("");
    lines.push("### Phase history");
    lines.push("");
    for (const phase of data.phases) {
      lines.push(`- Phase ${phase.phase} — ${phase.name}: ${phase.status}${phase.finished_at ? ` (finished ${phase.finished_at})` : ""}${phase.summary ? ` — ${phase.summary}` : ""}`);
    }
    lines.push("");
    lines.push("## Final assessment");
    lines.push("");
    lines.push(
      verified.length > 0
        ? `${verified.length} issue(s) were independently reverified. Remediation should prioritize the critical and high severity items, then re-run the audit against the fixed commit.`
        : "No issue reached independent reverification under the configured scope and limits. This does not establish the absence of vulnerabilities.",
    );
    lines.push("");
    lines.push("## Report integrity");
    lines.push("");
    lines.push(`This report was generated deterministically from the Argus database. Evidence records are hash-chained; verification result: **${data.chain.ok ? "intact" : "tampered or incomplete"}**.`);
    lines.push("");
    return redactSecrets(`${lines.join("\n")}\n`).text;
  }

  private renderHtml(data: ReportData, markdown: string): string {
    const verified = data.findings.filter((finding) => finding.status === "reverified");
    const body = markdownToHtml(markdown);
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(data.project.name)} — Security Audit Report</title>
<style>
:root { color-scheme: dark; --bg:#0b1016; --panel:#111a24; --line:#223140; --text:#dce7f1; --muted:#8ba0b4; --accent:#55d6be; --danger:#ff6b6b; --warn:#ffc857; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif; line-height:1.6; }
main { max-width: 980px; margin: 0 auto; padding: 56px 28px 96px; }
header { border-bottom: 1px solid var(--line); padding-bottom: 28px; margin-bottom: 40px; }
.badge { display:inline-block; border:1px solid var(--line); border-radius:999px; padding:4px 10px; font-size:12px; color:var(--muted); letter-spacing:.06em; text-transform:uppercase; }
h1 { font-size: 34px; line-height:1.2; margin: 16px 0 10px; letter-spacing:-.02em; }
h2 { margin-top: 48px; padding-top: 22px; border-top:1px solid var(--line); font-size: 23px; }
h3 { margin-top: 32px; color:#fff; font-size: 18px; }
p, li { color: #c8d6e2; }
a { color: var(--accent); }
code { background:#0a0f14; border:1px solid var(--line); padding:1px 5px; border-radius:5px; color:#a7f3e4; font-size:.9em; }
pre { background:#080d12; border:1px solid var(--line); padding:16px; overflow:auto; border-radius:10px; }
table { width:100%; border-collapse: collapse; margin: 16px 0 24px; font-size: 13px; }
th, td { text-align:left; border-bottom:1px solid var(--line); padding:9px 10px; vertical-align: top; }
th { color: var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.04em; font-size:11px; }
blockquote { border-left:3px solid var(--accent); margin:20px 0; padding:2px 18px; color:var(--muted); }
hr { border:0; border-top:1px solid var(--line); margin:36px 0; }
.meta { color: var(--muted); font-size:13px; }
.sev { font-weight:700; }
@media (max-width: 700px) { main { padding: 28px 16px 60px; } h1 { font-size: 26px; } table { display:block; overflow-x:auto; } }
@media print { :root { color-scheme: light; --bg:#fff; --panel:#fff; --line:#d8dee6; --text:#111; --muted:#555; } body { background:#fff; } main { max-width:none; padding:0; } h2 { page-break-after: avoid; } h3 { page-break-after: avoid; } table { page-break-inside: avoid; } }
</style>
</head>
<body>
<main>
<header>
<span class="badge">${escapeHtml(data.settings.classification)}</span>
<h1>${escapeHtml(data.project.name)} — Security Audit Report</h1>
<p class="meta">Audit ${escapeHtml(data.audit.id)} · Generated ${escapeHtml(data.generated_at)} · ${escapeHtml(APP_NAME)} ${escapeHtml(APP_VERSION)}</p>
</header>
${body}
</main>
</body>
</html>
`;
  }
}

function extension(format: ReportFormat): string {
  return format === "markdown" ? "md" : format;
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function escapeTable(value: string): string {
  return value.replaceAll("|", "\\|").replaceAll("\n", " ");
}

function markdownToHtml(markdown: string): string {
  const lines = markdown.split("\n");
  const out: string[] = [];
  let inList = false;
  let inTable = false;
  let inCode = false;
  const closeList = () => {
    if (inList) {
      out.push("</ul>");
      inList = false;
    }
  };
  const closeTable = () => {
    if (inTable) {
      out.push("</tbody></table>");
      inTable = false;
    }
  };
  for (const line of lines) {
    if (line.startsWith("```")) {
      closeList();
      closeTable();
      out.push(inCode ? "</code></pre>" : "<pre><code>");
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      out.push(escapeHtml(line));
      continue;
    }
    if (/^\|/.test(line)) {
      closeList();
      const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
      if (/^\|[\s:-]+\|/.test(line) || cells.every((cell) => /^[-: ]+$/.test(cell))) continue;
      if (!inTable) {
        out.push("<table><thead><tr>", ...cells.map((cell) => `<th>${inline(cell)}</th>`), "</tr></thead><tbody>");
        inTable = true;
      } else {
        out.push("<tr>", ...cells.map((cell) => `<td>${inline(cell)}</td>`), "</tr>");
      }
      continue;
    }
    closeTable();
    if (line.startsWith("### ")) {
      closeList();
      out.push(`<h3>${inline(line.slice(4))}</h3>`);
      continue;
    }
    if (line.startsWith("## ")) {
      closeList();
      out.push(`<h2>${inline(line.slice(3))}</h2>`);
      continue;
    }
    if (line.startsWith("# ")) {
      closeList();
      out.push(`<h1>${inline(line.slice(2))}</h1>`);
      continue;
    }
    if (/^\s*[-*] /.test(line)) {
      if (!inList) {
        out.push("<ul>");
        inList = true;
      }
      out.push(`<li>${inline(line.replace(/^\s*[-*] /, ""))}</li>`);
      continue;
    }
    if (/^\d+\. /.test(line)) {
      closeList();
      out.push(`<p>${inline(line)}</p>`);
      continue;
    }
    if (line.trim() === "") {
      closeList();
      out.push("");
      continue;
    }
    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }
  closeList();
  closeTable();
  if (inCode) out.push("</code></pre>");
  return out.join("\n");
}

function inline(value: string): string {
  let text = escapeHtml(value);
  text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
  text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  return text;
}

function groupEvidenceByFinding(rows: EvidenceRow[]): Record<string, EvidenceRow[]> {
  const grouped: Record<string, EvidenceRow[]> = {};
  for (const row of rows) {
    if (!row.finding_id) continue;
    (grouped[row.finding_id] ??= []).push(row);
  }
  return grouped;
}
