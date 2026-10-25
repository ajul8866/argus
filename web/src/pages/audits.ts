import { api, session } from "../api.ts";
import { openAuditCreate } from "../components/audit-create.ts";
import { openFindingDetail, openTaskDetail } from "../components/execution-detail.ts";
import { previewReport } from "../components/report-preview.ts";
import {
  badge,
  button,
  confirmAction,
  emptyState,
  errorState,
  formatDate,
  formatFullDate,
  h,
  loading,
  modal,
  pageHeader,
  phaseLabel,
  phaseName,
  progress,
  section,
  severityBadge,
  statusBadge,
  timeAgo,
  toast,
} from "../ui.ts";

type Audit = {
  id: string;
  project_id: string;
  repository_id: string;
  status: string;
  current_phase: number;
  phase_name: string;
  config: Record<string, unknown>;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
};

type Phase = { phase: number; name: string; status: string; started_at: string | null; finished_at: string | null; summary: string | null };
type Coverage = { area_id: string; title: string; status: string; files: string[]; notes: string | null; updated_at: string };
type Session = { id: string; role: string; harness: string; model: string | null; status: string; sandbox_mode: string; started_at: string; ended_at: string | null };
type Report = { id: string; format: string; status: string; sha256: string | null; size: number | null; generated_at: string };
type Chain = { ok: boolean; count: number; broken_at: string | null; reason: string | null };

type Detail = {
  audit: Audit;
  project: { id: string; name: string; description: string; source_path: string; authorized_by: string; authorization_ref: string } | null;
  repository: { id: string; commit_sha: string | null; branch: string | null; file_count: number; total_bytes: number; languages: string; frameworks: string; imported_at: string } | null;
  phases: Phase[];
  coverage: Coverage[];
  task_counts: Record<string, number>;
  finding_counts: Array<{ status: string; severity: string; count: number }>;
  sessions: Session[];
  reports: Report[];
  evidence: { count: number; chain: Chain };
};

type Task = {
  id: string;
  phase: number;
  kind: string;
  title: string;
  status: string;
  agent_role: string | null;
  harness: string | null;
  model: string | null;
  attempts: number;
  max_attempts: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

type Finding = {
  id: string;
  code: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  verification_count: number;
  updated_at: string;
};

type EventRow = { id: number; type: string; payload: Record<string, unknown>; created_at: string; seq: number };
type Approval = { id: string; action: string; scope: string; status: string; audit_id: string | null; created_at: string };

export async function renderAudits(root: HTMLElement): Promise<void> {
  root.replaceChildren(loading("Loading audits"));
  try {
    const { audits } = await api<{ audits: Array<Record<string, unknown>> }>("/api/audits");
    const rows = audits.map((audit) =>
      h("tr", {},
        h("td", { "data-label": "Project / audit" },
          h("a", { class: "table-title", href: `#/audits/${String(audit.id)}` }, String(audit.project_name)),
          h("div", { class: "table-sub mono" }, `${String(audit.id).slice(0, 10)} / ${String(audit.commit_sha ?? "no commit").slice(0, 10)}`),
        ),
        h("td", { "data-label": "Status" }, statusBadge(String(audit.status))),
        h("td", { class: "small", "data-label": "Phase" }, `Phase ${String(audit.current_phase)} / ${phaseLabel(Number(audit.current_phase))}`),
        h("td", { class: "small", "data-label": "Findings" }, String(audit.finding_count ?? 0)),
        h("td", { class: "small", "data-label": "Active" }, String(audit.active_tasks ?? 0)),
        h("td", { class: "small muted", "data-label": "Created" }, formatDate(String(audit.created_at))),
        h("td", { "data-label": "Actions" }, h("div", { class: "table-actions" }, h("a", { class: "btn btn-sm btn-secondary", href: `#/audits/${String(audit.id)}` }, "Open"))),
      ),
    );
    root.replaceChildren(
      pageHeader("Audits", "Six-phase autonomous assessments, execution history, and final reports.", button("New audit", () => void openAuditCreate(), "primary")),
      audits.length
        ? section(`${audits.length} audits`, h("div", { class: "table-wrap" }, h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Project / audit"), h("th", {}, "Status"), h("th", {}, "Phase"), h("th", {}, "Findings"), h("th", {}, "Active"), h("th", {}, "Created"), h("th", {}, ""))),
            h("tbody", {}, ...rows),
          )))
        : emptyState("No audits", "Create a project, import a repository, and start the first six-phase audit.", button("New audit", () => void openAuditCreate(), "primary")),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load audits", () => void renderAudits(root)));
  }
}

export async function renderAuditDetail(root: HTMLElement, auditId: string, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Loading audit"));
  try {
    const detail = await api<Detail>(`/api/audits/${auditId}`);
    const audit = detail.audit;
    const activeTab = params.get("tab") ?? "tasks";
    const [tasksResult, findingsResult, eventsResult, approvalsResult, evidenceResult] = await Promise.all([
      api<{ tasks: Task[] }>(`/api/audits/${auditId}/tasks`),
      api<{ findings: Finding[] }>(`/api/audits/${auditId}/findings`),
      api<{ events: EventRow[] }>(`/api/audits/${auditId}/events?after=0`),
      api<{ approvals: Approval[] }>("/api/approvals?status=pending"),
      api<{ evidence: Array<Record<string, unknown>>; chain: Chain }>(`/api/audits/${auditId}/evidence`),
    ]);
    const findings = findingsResult.findings;
    const verified = findings.filter((finding) => finding.status === "reverified").length;
    const unresolved = findings.filter((finding) => ["confirmed", "needs_correction", "unresolved"].includes(finding.status)).length;
    const runningTasks = detail.task_counts.running ?? 0;
    const queuedTasks = (detail.task_counts.queued ?? 0) + (detail.task_counts.waiting_approval ?? 0);
    const activeSessions = detail.sessions.filter((agentSession) => ["starting", "running"].includes(agentSession.status)).length;
    const completedPhases = detail.phases.filter((phase) => ["completed", "skipped"].includes(phase.status)).length;
    const approvals = approvalsResult.approvals.filter((approval) => approval.audit_id === auditId);

    const startButton = audit.status === "queued"
      ? button("Start audit", async () => {
          try {
            await api(`/api/audits/${auditId}/start`, { method: "POST" });
            toast("Audit started.", "success");
            await renderAuditDetail(root, auditId, params);
          } catch (error) {
            toast(error instanceof Error ? error.message : "Unable to start audit", "error");
          }
        }, "primary")
      : null;
    const cancelButton = ["running", "cancelling"].includes(audit.status)
      ? button("Cancel audit", async () => {
          if (!(await confirmAction("Cancel audit", "Active harness tasks will be stopped, queued tasks cancelled, and the audit closed as cancelled.", "Cancel audit"))) return;
          try {
            await api(`/api/audits/${auditId}/cancel`, { method: "POST" });
            toast("Cancellation requested.", "success");
            await renderAuditDetail(root, auditId, params);
          } catch (error) {
            toast(error instanceof Error ? error.message : "Unable to cancel audit", "error");
          }
        }, "danger")
      : null;

    const phaseRows = detail.phases.map((phase) =>
      h("div", { class: `phase-row is-${phase.status}` },
        h("div", { class: "phase-num" }, String(phase.phase)),
        h("div", {},
          h("div", { class: "phase-name" }, phase.name),
          h("div", { class: "phase-meta" }, phase.summary || (phase.started_at ? `started ${formatFullDate(phase.started_at)}` : "not started")),
        ),
        statusBadge(phase.status),
      ),
    );

    const tabs: Array<[string, string, string]> = [
      ["tasks", "Tasks", String(tasksResult.tasks.length)],
      ["findings", "Findings", String(findings.length)],
      ["coverage", "Coverage", String(detail.coverage.length)],
      ["decisions", "Decisions", String(approvals.length)],
      ["evidence", "Evidence", String(detail.evidence.count)],
      ["reports", "Reports", String(detail.reports.length)],
      ["activity", "Activity", String(eventsResult.events.length)],
      ["sessions", "Sessions", String(detail.sessions.length)],
    ];
    const tabBar = h("div", { class: "tabs" }, ...tabs.map(([key, label, count]) =>
      h("button", {
        class: `tab ${activeTab === key ? "active" : ""}`,
        onclick: () => {
          location.hash = `#/audits/${auditId}?tab=${key}`;
        },
      }, `${label} (${count})`),
    ));

    let tabContent: HTMLElement;
    if (activeTab === "findings") tabContent = findingsTab(findings, () => void renderAuditDetail(root, auditId, params));
    else if (activeTab === "coverage") tabContent = coverageTab(detail);
    else if (activeTab === "decisions") tabContent = decisionsTab(approvals, () => void renderAuditDetail(root, auditId, params));
    else if (activeTab === "evidence") tabContent = evidenceTab(evidenceResult.evidence, evidenceResult.chain);
    else if (activeTab === "reports") tabContent = reportsTab(detail.reports, auditId, () => void renderAuditDetail(root, auditId, params));
    else if (activeTab === "activity") tabContent = activityTab(eventsResult.events);
    else if (activeTab === "sessions") tabContent = sessionsTab(detail.sessions);
    else tabContent = tasksTab(tasksResult.tasks, () => void renderAuditDetail(root, auditId, params));

    root.replaceChildren(
      pageHeader(
        detail.project?.name ?? "Audit",
        `Autonomous six-phase assessment / ${audit.id}`,
        h("div", { class: "row" },
          startButton,
          cancelButton,
          h("a", { class: "btn btn-secondary", href: `#/projects/${audit.project_id}` }, "Project"),
          button("New audit", () => void openAuditCreate(audit.project_id), "ghost"),
        ),
      ),
      h("div", { class: "grid grid-main" },
        h("div", { class: "stack" },
          section("Assessment progress",
            h("div", { class: "stack" },
              h("div", { class: "row", style: { justifyContent: "space-between" } },
                h("div", { class: "row" }, statusBadge(audit.status), h("span", { class: "small muted" }, `Phase ${audit.current_phase}/6 / ${audit.phase_name ?? phaseName(audit.current_phase)}`)),
                h("span", { class: "tiny muted" }, `${completedPhases}/6 phases complete`),
              ),
              progress(completedPhases, 6, `${completedPhases} of 6 phases complete`),
              audit.error ? h("div", { class: "callout bad" }, audit.error) : null,
            ),
          ),
          section("Phase timeline", h("div", { class: "phase-list" }, ...phaseRows)),
        ),
        h("div", { class: "stack" },
          section("Run state", h("div", { class: "metric-row" },
            metric("Verified findings", String(verified), verified ? "bad" : "good"),
            metric("Unresolved", String(unresolved), unresolved ? "warn" : "good"),
            metric("Active tasks", String(runningTasks), runningTasks ? "warn" : "good"),
            metric("Queued", String(queuedTasks), ""),
          )),
          section("Repository", detail.repository ? h("dl", { class: "kv" },
            h("dt", {}, "Commit"), h("dd", { class: "mono" }, detail.repository.commit_sha?.slice(0, 16) ?? "no git"),
            h("dt", {}, "Branch"), h("dd", {}, detail.repository.branch ?? "—"),
            h("dt", {}, "Files"), h("dd", {}, String(detail.repository.file_count)),
            h("dt", {}, "Languages"), h("dd", {}, Object.entries(JSON.parse(detail.repository.languages || "{}") as Record<string, number>).map(([language, count]) => `${language} (${count})`).join(", ") || "—"),
            h("dt", {}, "Imported"), h("dd", {}, formatDate(detail.repository.imported_at)),
          ) : h("p", { class: "muted small" }, "Repository unavailable.")),
          section("Evidence integrity", h("div", { class: "stack" },
            h("div", { class: "row-between" }, h("span", { class: "small" }, "Hash chain"), badge(detail.evidence.chain.ok ? "intact" : "broken", detail.evidence.chain.ok ? "good" : "bad")),
            h("div", { class: "tiny muted" }, `${detail.evidence.chain.count} evidence records, ${detail.evidence.chain.reason ?? "all hashes verified"}`),
            detail.evidence.chain.broken_at ? h("div", { class: "callout bad mono tiny" }, detail.evidence.chain.broken_at) : null,
          )),
          section("Sessions", h("div", { class: "stack" },
            h("div", { class: "row-between" }, h("span", { class: "small" }, "Active agent sessions"), badge(String(activeSessions), activeSessions ? "warn" : "neutral")),
            h("div", { class: "tiny muted" }, `${detail.sessions.length} total sessions recorded`),
          ), h("a", { class: "btn btn-ghost btn-sm", href: `#/audits/${auditId}?tab=sessions` }, "Inspect")),
          approvals.length > 0
            ? section("Approvals waiting", h("div", { class: "stack" }, ...approvals.map((approval) =>
                h("div", { class: "callout warn" }, h("div", { class: "small strong" }, approval.action.replaceAll("_", " ")), h("div", { class: "tiny" }, approval.scope)),
              ), h("a", { class: "btn btn-ghost btn-sm", href: `#/audits/${auditId}?tab=decisions` }, "Review")))
            : null,
        ),
      ),
      h("div", { class: "panel audit-tabs", style: { marginTop: "var(--space-md)" } }, tabBar, tabContent),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load audit", () => void renderAuditDetail(root, auditId, params)));
  }
}

function metric(label: string, value: string, tone: string): HTMLElement {
  return h("div", { class: "metric" },
    h("div", { class: "metric-label" }, label),
    h("div", { class: `metric-value ${tone === "bad" ? "sev-critical" : tone === "warn" ? "sev-medium" : tone === "good" ? "sev-low" : ""}` }, value),
  );
}

function tasksTab(tasks: Task[], refresh: () => void): HTMLElement {
  if (tasks.length === 0) return emptyState("No tasks yet", "Tasks appear when the audit is started or when a phase transition schedules work.");
  return h("div", { class: "table-wrap" },
    h("table", { class: "tasks-table" },
      h("thead", {}, h("tr", {},
        h("th", {}, "Phase"), h("th", {}, "Task"), h("th", {}, "Role / harness"), h("th", {}, "Status"), h("th", {}, "Attempt"), h("th", {}, "Started"), h("th", {}, ""),
      )),
      h("tbody", {}, ...tasks.map((task) =>
        h("tr", {},
          h("td", { class: "small nowrap", "data-label": "Phase" }, `${task.phase} / ${phaseLabel(task.phase)}`),
          h("td", { "data-label": "Task" },
            h("div", { class: "table-title" }, task.title),
            h("div", { class: "table-sub mono" }, task.kind),
          ),
          h("td", { "data-label": "Role / harness" },
            h("div", { class: "small" }, task.agent_role ?? "deterministic"),
            h("div", { class: "table-sub" }, task.harness ? `${task.harness}${task.model ? ` / ${task.model}` : ""}` : "platform"),
          ),
          h("td", { "data-label": "Status" }, h("div", { class: "stack", style: { gap: "var(--space-2xs)" } }, statusBadge(task.status), task.error ? h("span", { class: "tiny muted truncate", title: task.error }, task.error) : null)),
          h("td", { class: "small mono", "data-label": "Attempt" }, `${task.attempts}/${task.max_attempts}`),
          h("td", { class: "small muted", "data-label": "Started" }, task.started_at ? timeAgo(task.started_at) : "—"),
          h("td", { "data-label": "Actions" }, h("div", { class: "table-actions" }, button("Inspect", () => void openTaskDetail(task.id, refresh), "ghost", { class: "btn-sm" }))),
        ),
      )),
    ),
  );
}

function findingsTab(findings: Finding[], refresh: () => void): HTMLElement {
  if (findings.length === 0) return emptyState("No findings recorded", "Candidates only become findings after independent confirmation and the platform evidence gate.");
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Finding"), h("th", {}, "Severity"), h("th", {}, "Status"), h("th", {}, "Verifications"), h("th", {}, ""))),
      h("tbody", {}, ...findings.map((finding) =>
        h("tr", {},
          h("td", { "data-label": "Finding" },
            h("div", { class: "row", style: { gap: "var(--space-xs)" } }, h("span", { class: "mono tiny muted" }, finding.code), h("span", { class: "table-title" }, finding.title)),
            h("div", { class: "table-sub" }, finding.category),
          ),
          h("td", { "data-label": "Severity" }, severityBadge(finding.severity)),
          h("td", { "data-label": "Status" }, statusBadge(finding.status)),
          h("td", { class: "small mono", "data-label": "Verifications" }, String(finding.verification_count)),
          h("td", { "data-label": "Actions" }, h("div", { class: "table-actions" }, button("Open", () => void openFindingDetail(finding.id, refresh), "ghost", { class: "btn-sm" }))),
        ),
      )),
    ),
  );
}

function coverageTab(detail: Detail): HTMLElement {
  if (detail.coverage.length === 0) return emptyState("No coverage rows", "Coverage is created after Phase 1 maps the codebase into assessment areas.");
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Area"), h("th", {}, "Status"), h("th", {}, "Files"), h("th", {}, "Notes"))),
      h("tbody", {}, ...detail.coverage.map((row) =>
        h("tr", {},
          h("td", { "data-label": "Area" }, h("div", { class: "table-title" }, row.title), h("div", { class: "table-sub mono" }, row.area_id)),
          h("td", { "data-label": "Status" }, statusBadge(row.status)),
          h("td", { class: "mono small", "data-label": "Files" }, String(row.files.length)),
          h("td", { class: "small muted", "data-label": "Notes" }, row.notes ?? "—"),
        ),
      )),
    ),
  );
}

function decisionsTab(approvals: Approval[], refresh: () => void): HTMLElement {
  if (approvals.length === 0) return emptyState("No pending decisions", "Read-only audit tasks do not require approval. Shell or destructive actions would appear here.");
  const canDecide = session.user?.role === "admin";
  return h("div", { class: "stack" }, ...approvals.map((approval) =>
    h("div", { class: "callout warn" },
      h("div", { class: "row-between" },
        h("div", {},
          h("div", { class: "small strong" }, approval.action.replaceAll("_", " ")),
          h("div", { class: "tiny" }, approval.scope),
        ),
        canDecide
          ? h("div", { class: "action-row" },
              button("Deny", async () => {
                try {
                  await api(`/api/approvals/${approval.id}/decide`, { method: "POST", body: { approved: false, reason: "Denied from dashboard" } });
                  toast("Approval denied.", "success");
                  refresh();
                } catch (error) {
                  toast(error instanceof Error ? error.message : "Decision failed", "error");
                }
              }, "danger", { class: "btn-sm" }),
              button("Approve", async () => {
                try {
                  await api(`/api/approvals/${approval.id}/decide`, { method: "POST", body: { approved: true, reason: "Approved from dashboard" } });
                  toast("Approval granted.", "success");
                  refresh();
                } catch (error) {
                  toast(error instanceof Error ? error.message : "Decision failed", "error");
                }
              }, "secondary", { class: "btn-sm" }),
            )
          : h("span", { class: "tiny muted" }, "Admin approval required"),
      ),
    ),
  ));
}

function evidenceTab(evidence: Array<Record<string, unknown>>, chain: Chain): HTMLElement {
  if (evidence.length === 0) return emptyState("No evidence", "Agent prompts, transcripts, verification results, and code excerpts are hash-chained here.");
  return h("div", { class: "stack" },
    h("div", { class: `callout ${chain.ok ? "good" : "bad"}` },
      h("div", { class: "row-between" },
        h("span", { class: "small strong" }, chain.ok ? "Evidence chain intact" : "Evidence chain verification failed"),
        h("span", { class: "tiny muted" }, `${chain.count} records`),
      ),
      chain.reason ? h("div", { class: "tiny", style: { marginTop: "var(--space-2xs)" } }, chain.reason) : null,
    ),
    h("div", { class: "table-wrap" },
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Evidence"), h("th", {}, "Kind"), h("th", {}, "SHA-256"), h("th", {}, "Created"), h("th", {}, ""))),
        h("tbody", {}, ...evidence.map((row) =>
          h("tr", {},
            h("td", { "data-label": "Evidence" }, h("div", { class: "table-title" }, String(row.title)), row.finding_id ? h("div", { class: "table-sub mono" }, String(row.finding_id).slice(0, 12)) : null),
            h("td", { class: "small", "data-label": "Kind" }, String(row.kind)),
            h("td", { class: "mono tiny", "data-label": "SHA-256" }, String(row.sha256).slice(0, 20)),
            h("td", { class: "small muted", "data-label": "Created" }, formatDate(String(row.created_at))),
            h("td", { "data-label": "Actions" }, h("div", { class: "table-actions" }, button("View", async () => {
              try {
                const result = await api<{ content: string }>(`/api/evidence/${String(row.id)}`);
                modal(String(row.title), h("pre", { class: "json-block", style: { maxHeight: "60vh" } }, result.content), null, { wide: true });
              } catch (error) {
                toast(error instanceof Error ? error.message : "Unable to load evidence", "error");
              }
            }, "ghost", { class: "btn-sm" }))),
          ),
        )),
      ),
    ),
  );
}

function reportsTab(reports: Report[], auditId: string, refresh: () => void): HTMLElement {
  const canGenerate = session.user && ["admin", "auditor"].includes(session.user.role);
  return h("div", { class: "stack" },
    h("div", { class: "row-between" },
      h("p", { class: "hint" }, "Reports are assembled deterministically from verified database records. Markdown, JSON, HTML, and PDF are generated together."),
      canGenerate
        ? button("Generate all formats", async () => {
            try {
              await api(`/api/audits/${auditId}/reports`, { method: "POST", body: {} });
              toast("Reports generated.", "success");
              refresh();
            } catch (error) {
              toast(error instanceof Error ? error.message : "Report generation failed", "error");
            }
          }, "primary")
        : null,
    ),
    reports.length === 0
      ? emptyState("No reports yet", "Phase 6 generates all four report formats after reverification.")
      : h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "Format"), h("th", {}, "Status"), h("th", {}, "Size"), h("th", {}, "Generated"), h("th", {}, "SHA-256"), h("th", {}, ""))),
          h("tbody", {}, ...reports.map((report) =>
            h("tr", {},
              h("td", { class: "strong", "data-label": "Format" }, report.format.toUpperCase()),
              h("td", { "data-label": "Status" }, statusBadge(report.status)),
              h("td", { class: "mono small", "data-label": "Size" }, report.size ? `${Math.round(report.size / 1024)} KiB` : "—"),
              h("td", { class: "small muted", "data-label": "Generated" }, formatDate(report.generated_at)),
              h("td", { class: "mono tiny", "data-label": "SHA-256" }, report.sha256?.slice(0, 18) ?? "—"),
              h("td", { "data-label": "Actions" }, h("div", { class: "table-actions" },
                report.status === "generated" && report.format !== "pdf" ? button("Preview", () => void previewReport(report.id, report.format, "Audit report"), "ghost", { class: "btn-sm" }) : null,
                report.status === "generated" ? h("a", { class: "btn btn-sm btn-secondary", href: `/api/reports/${report.id}/download` }, "Download") : null,
              )),
            ),
          )),
        )),
  );
}

function activityTab(events: EventRow[]): HTMLElement {
  if (events.length === 0) return emptyState("No activity", "Runtime events stream in as soon as the audit runs.");
  return h("div", { class: "event-feed", style: { maxHeight: "620px" } }, ...events.slice(-300).reverse().map((event) =>
    h("div", { class: "event-row" },
      h("span", { class: "event-time" }, new Date(event.created_at).toLocaleTimeString()),
      h("span", { class: "event-type" }, event.type),
      h("span", { class: "event-detail" }, Object.entries(event.payload).slice(0, 4).map(([key, value]) => `${key}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`).join(", ")),
    ),
  ));
}

function sessionsTab(sessions: Session[]): HTMLElement {
  if (sessions.length === 0) return emptyState("No agent sessions", "Sessions appear when the first harness task starts.");
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Session"), h("th", {}, "Role"), h("th", {}, "Harness"), h("th", {}, "Model"), h("th", {}, "Status"), h("th", {}, "Sandbox"), h("th", {}, "Started"))),
      h("tbody", {}, ...sessions.map((agentSession) =>
        h("tr", {},
          h("td", { class: "mono tiny", "data-label": "Session" }, agentSession.id.slice(0, 12)),
          h("td", { class: "small", "data-label": "Role" }, agentSession.role),
          h("td", { class: "small", "data-label": "Harness" }, agentSession.harness),
          h("td", { class: "small mono", "data-label": "Model" }, agentSession.model ?? "default"),
          h("td", { "data-label": "Status" }, statusBadge(agentSession.status)),
          h("td", { class: "small", "data-label": "Sandbox" }, agentSession.sandbox_mode),
          h("td", { class: "small muted", "data-label": "Started" }, formatDate(agentSession.started_at)),
        ),
      )),
    ),
  );
}
