import { api, session } from "../api.ts";
import {
  badge,
  button,
  emptyState,
  errorState,
  formatDate,
  h,
  loading,
  pageHeader,
  phaseLabel,
  progress,
  section,
  severityBadge,
  statCard,
  statusBadge,
  timeAgo,
} from "../ui.ts";
import { openAuditCreate } from "../components/audit-create.ts";

type Overview = {
  projects: number;
  audits: number;
  running_audits: number;
  tasks: { running: number; queued: number; failed: number };
  agents: { active_sessions: number; sessions: number };
  findings: { total: number; by_status: Record<string, number>; by_severity: Record<string, number> };
  coverage: Record<string, number>;
  harnesses: Array<{ kind: string; label: string; status: string; version: string | null; detail: string }>;
  recent_audits: Array<{
    id: string;
    status: string;
    current_phase: number;
    created_at: string;
    project_name: string;
    commit_sha: string | null;
  }>;
  recent_events: Array<{
    id: number;
    audit_id: string;
    type: string;
    payload: Record<string, unknown>;
    created_at: string;
  }>;
  pending_approvals: number;
};

type Approval = {
  id: string;
  action: string;
  scope: string;
  status: string;
  created_at: string;
  audit_id: string | null;
  task_id: string | null;
};

export async function renderDashboard(root: HTMLElement): Promise<void> {
  root.replaceChildren(loading("Loading control room"));
  try {
    const [overview, approvals] = await Promise.all([
      api<Overview>("/api/overview"),
      api<{ approvals: Approval[] }>("/api/approvals?status=pending"),
    ]);
    const verified = overview.findings.by_status.reverified ?? 0;
    const unresolved =
      (overview.findings.by_status.confirmed ?? 0) +
      (overview.findings.by_status.needs_correction ?? 0) +
      (overview.findings.by_status.unresolved ?? 0);
    const coverageTotal = Object.values(overview.coverage).reduce((sum, value) => sum + value, 0);
    const coverageCompleted = overview.coverage.COMPLETED ?? 0;

    const findingMix = ["critical", "high", "medium", "low", "info"].map((severity) =>
      h(
        "div",
        { class: "row-between" },
        h("div", { class: "row" }, severityBadge(severity), h("span", { class: "muted tiny" }, `${overview.findings.by_severity[severity] ?? 0} verified`)),
        h("div", { class: "progress-track severity-track" },
          h("div", {
            class: `progress-fill severity-fill-${severity}`,
            style: {
              width: `${Math.min(100, ((overview.findings.by_severity[severity] ?? 0) / Math.max(1, verified)) * 100)}%`,
            },
          }),
        ),
      ),
    );

    const harnesses = overview.harnesses.map((harness) =>
      h(
        "div",
        { class: "row-between runtime-row" },
        h("div", {},
          h("div", { class: "row" },
            h("span", { class: "strong small" }, harness.label),
            statusBadge(harness.status),
          ),
          h("div", { class: "tiny muted" }, harness.detail || "No health check yet"),
        ),
        h("a", { class: "btn btn-ghost btn-sm", href: "#/harnesses" }, harness.version ? `v${harness.version}` : "Configure"),
      ),
    );

    const auditRows = overview.recent_audits.length
      ? overview.recent_audits.map((audit) =>
          h(
            "div",
            { class: "audit-list-item" },
            h("div", { class: "truncate" },
              h("div", { class: "row" },
                h("a", { class: "table-title", href: `#/audits/${audit.id}` }, audit.project_name),
                statusBadge(audit.status),
              ),
              h("div", { class: "table-sub audit-row-meta" },
                h("span", {}, `Phase ${audit.current_phase}: ${phaseLabel(audit.current_phase)}`),
                h("span", { class: "mono" }, audit.commit_sha?.slice(0, 10) ?? "no commit"),
              ),
            ),
            h("div", { class: "tiny muted nowrap" }, timeAgo(audit.created_at)),
          ),
        )
      : [emptyState("No audits yet", "Create a project, import an authorized repository, then launch the six-phase workflow.")];

    const events = overview.recent_events.length
      ? h(
          "div",
          { class: "event-feed" },
          ...overview.recent_events.slice(0, 14).map((event) =>
            h(
              "div",
              { class: "event-row" },
              h("span", { class: "event-time" }, timeAgo(event.created_at)),
              h("span", { class: "event-type" }, event.type),
              h("span", { class: "event-detail" }, eventDetail(event)),
            ),
          ),
        )
      : emptyState("No runtime activity", "Events appear here as soon as an audit begins.");

    const approvalsPanel =
      approvals.approvals.length > 0
        ? section(
            "Pending approvals",
            h(
              "div",
              { class: "stack" },
              ...approvals.approvals.map((approval) =>
                h(
                  "div",
                  { class: "callout warn" },
                  h("div", { class: "row-between" },
                    h("div", {},
                      h("div", { class: "strong small" }, `Approval required: ${approval.action.replaceAll("_", " ")}`),
                      h("div", { class: "tiny" }, approval.scope),
                    ),
                    h("a", { class: "btn btn-sm btn-secondary", href: "#/approvals" }, "Review"),
                  ),
                ),
              ),
            ),
          )
        : null;

    root.replaceChildren(
      pageHeader(
        "Control room",
        "Autonomous source-code security auditing across Pi and Claude Code harnesses.",
        h("div", { class: "row" },
          button("New audit", () => void openAuditCreate(), "primary"),
          h("a", { class: "btn btn-secondary", href: "#/findings" }, "Review findings"),
        ),
      ),
      h(
        "div",
        { class: "stat-grid" },
        statCard("Running audits", overview.running_audits, `${overview.audits} total audit${overview.audits === 1 ? "" : "s"}`, overview.running_audits ? "warn" : "good"),
        statCard("Active agents", overview.agents.active_sessions, `${overview.agents.sessions} historical sessions`),
        statCard("Verified findings", verified, unresolved ? `${unresolved} unresolved` : "independent retest complete", verified ? "bad" : "good"),
        statCard("Pending approvals", overview.pending_approvals, "Shell / destructive actions", overview.pending_approvals ? "warn" : "good"),
      ),
      h(
        "div",
        { class: "dashboard-workspace" },
        h(
          "div",
          { class: "stack dashboard-lead" },
          section(
            "Recent audits",
            h("div", {}, ...auditRows),
            h("a", { class: "btn btn-ghost btn-sm", href: "#/audits" }, "All audits"),
          ),
          section("Live activity", events, h("a", { class: "btn btn-ghost btn-sm", href: "#/tasks" }, "Task queue")),
        ),
        h(
          "div",
          { class: "stack" },
          section(
            "Coverage matrix",
            h(
              "div",
              { class: "stack" },
              progress(coverageCompleted, coverageTotal, `${coverageCompleted} completed / ${coverageTotal} total areas`),
              h(
                "div",
                { class: "coverage-statuses" },
                ...["PENDING", "RUNNING", "COMPLETED", "BLOCKED", "FAILED", "NOT_APPLICABLE"].map((status) =>
                  h("span", { class: `chip ${status === "COMPLETED" ? "on" : ""}` },
                    h("span", {}, status.toLowerCase().replaceAll("_", " ")),
                    h("span", { class: "coverage-count" }, overview.coverage[status] ?? 0),
                  ),
                ),
              ),
              h("p", { class: "tiny muted" },
                "Completed tasks do not prove exhaustive vulnerability discovery. Unmapped files and blocked areas remain explicit limitations.",
              ),
            ),
          ),
          section("Runtime health", h("div", {}, ...harnesses)),
          section("Verified severity mix", verified ? h("div", { class: "stack" }, ...findingMix) : emptyState("No verified findings", "Findings only appear here after independent reverification.")),
          approvalsPanel,
        ),
      ),
      h(
        "div",
        { class: "row dashboard-footer" },
        h("span", { class: "hint" }, `Signed in as ${session.user?.name ?? ""} (${session.user?.role ?? ""}).`),
        h("a", { class: "hint", href: "#/settings" }, "Runtime settings"),
      ),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load overview", () => void renderDashboard(root)));
  }
}

function eventDetail(event: { type: string; payload: Record<string, unknown>; audit_id: string }): string {
  const payload = event.payload;
  const keys = ["title", "kind", "message", "phase", "decision", "status", "verdict", "code", "area_id"];
  const parts: string[] = [];
  for (const key of keys) {
    if (payload[key] !== undefined && payload[key] !== null && payload[key] !== "") {
      parts.push(`${key}: ${String(payload[key])}`);
    }
  }
  if (parts.length === 0) parts.push(`audit ${event.audit_id.slice(0, 8)}`);
  return parts.join(", ");
}
