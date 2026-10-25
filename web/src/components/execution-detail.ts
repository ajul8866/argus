import { api, session } from "../api.ts";
import {
  button,
  confirmAction,
  drawer,
  fill,
  errorState,
  formatFullDate,
  h,
  jsonBlock,
  modal,
  severityBadge,
  statusBadge,
  timelineEntry,
  toast,
  truncate,
  verificationTimelineTone,
} from "../ui.ts";

type Evidence = {
  id: string;
  kind: string;
  title: string;
  sha256: string;
  prev_hash: string;
  chain_hash: string;
  size: number;
  created_at: string;
};

type Finding = {
  id: string;
  code: string;
  title: string;
  category: string;
  cwe: string | null;
  severity: string;
  status: string;
  repository_commit: string | null;
  files: Array<{ path: string; start_line: number; end_line: number }>;
  root_cause: string;
  preconditions: string[];
  reproduction: string[];
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

type Verification = {
  id: string;
  kind: string;
  verdict: string;
  rationale: string;
  agent_session_id: string;
  created_at: string;
  evidence_check: Record<string, unknown>;
};

type Detail = {
  finding: Finding;
  candidate: Record<string, unknown> | null;
  verifications: Verification[];
  evidence: Evidence[];
  sessions: Array<{ id: string; role: string; harness: string; model: string | null; status: string; sandbox_mode: string; started_at: string }>;
};

export async function openFindingDetail(findingId: string, onChange?: () => void): Promise<void> {
  const body = h("div", { class: "stack" }, h("div", { class: "loading-state" }, h("span", { class: "spinner" }), "Loading finding…"));
  const close = drawer("Finding details", body);
  try {
    const detail = await api<Detail>(`/api/findings/${findingId}`);
    const finding = detail.finding;
    body.replaceChildren(
      h("div", { class: "row-between" },
        h("div", {},
          h("div", { class: "row", style: { gap: "var(--space-xs)" } },
            h("span", { class: "mono muted" }, finding.code),
            severityBadge(finding.severity),
            statusBadge(finding.status),
          ),
          h("h2", { style: { margin: "var(--space-xs) 0 var(--space-2xs)", fontSize: "19px", letterSpacing: "-.02em" } }, finding.title),
          h("div", { class: "tiny muted" }, `${finding.category}${finding.cwe ? ` / ${finding.cwe}` : ""} / commit ${finding.repository_commit?.slice(0, 12) ?? "n/a"}`),
        ),
        session.user && ["admin", "auditor"].includes(session.user.role)
          ? button("Request retest", async () => {
              if (!(await confirmAction("Independent retest", "This creates a fresh retest session. Previous verification history remains immutable.", "Create retest task"))) return;
              try {
                await api(`/api/findings/${finding.id}/retest`, { method: "POST" });
                toast("Retest task queued.", "success");
                close.close();
                onChange?.();
              } catch (error) {
                toast(error instanceof Error ? error.message : "Unable to queue retest", "error");
              }
            }, "secondary")
          : null,
      ),
      h("div", { class: "callout" },
        h("div", { class: "row", style: { justifyContent: "space-between" } },
          h("span", { class: "tiny muted" }, "Verification decision"),
          h("span", { class: "strong small" }, finding.verification_decision ?? "—"),
        ),
        h("div", { class: "row", style: { justifyContent: "space-between", marginTop: "var(--space-2xs)" } },
          h("span", { class: "tiny muted" }, "Retest decision"),
          h("span", { class: "strong small" }, finding.retest_decision ?? "pending"),
        ),
      ),
      h("div", { class: "finding-split" },
        h("div", { class: "stack" },
          sectionBlock("Root cause", h("p", { class: "narrative" }, finding.root_cause)),
          sectionBlock("Preconditions", listOrNone(finding.preconditions)),
          sectionBlock("Reproduction reasoning", finding.reproduction.length ? h("ol", { class: "narrative" }, ...finding.reproduction.map((step) => h("li", {}, step))) : h("p", { class: "muted small" }, "No reproduction steps recorded.")),
          sectionBlock("Expected vs. observed",
            h("div", { class: "stack" },
              h("div", { class: "callout" }, h("div", { class: "tiny muted" }, "Expected"), h("div", { class: "small" }, finding.expected)),
              h("div", { class: "callout bad" }, h("div", { class: "tiny muted" }, "Observed"), h("div", { class: "small" }, finding.observed)),
            ),
          ),
          sectionBlock("Impact", h("p", { class: "narrative" }, finding.impact)),
          sectionBlock("Remediation", h("p", { class: "narrative" }, finding.remediation)),
        ),
        h("div", { class: "stack" },
          sectionBlock("Affected locations", h("div", { class: "stack" }, ...finding.files.map((file) =>
            h("div", { class: "mono tiny" }, `${file.path}:${file.start_line}-${file.end_line}`),
          ))),
          sectionBlock("Provenance", h("dl", { class: "kv" },
            h("dt", {}, "Discovery session"), h("dd", { class: "mono tiny" }, finding.discovery_session_id ?? "—"),
            h("dt", {}, "Verification session"), h("dd", { class: "mono tiny" }, finding.verification_session_id ?? "—"),
            h("dt", {}, "Retest session"), h("dd", { class: "mono tiny" }, finding.retest_session_id ?? "pending"),
            h("dt", {}, "Created"), h("dd", {}, formatFullDate(finding.created_at)),
            h("dt", {}, "Updated"), h("dd", {}, formatFullDate(finding.updated_at)),
          )),
          sectionBlock("Verification history", detail.verifications.length ? h("div", { class: "timeline" }, ...detail.verifications.map((verification) =>
            timelineEntry(verificationTimelineTone(verification.verdict),
              h("div", { class: "row", style: { gap: "var(--space-2xs)" } }, h("span", { class: "strong small" }, verification.verdict), h("span", { class: "tiny muted" }, verification.kind)),
              h("div", { class: "tiny muted" }, `${verification.agent_session_id.slice(0, 8)} / ${formatFullDate(verification.created_at)}`),
              h("p", { class: "small", style: { margin: "var(--space-2xs) 0 0", color: "var(--text-soft)" } }, truncate(verification.rationale, 800)),
            ),
          )) : h("p", { class: "muted small" }, "No verification history.")),
          sectionBlock("Evidence", detail.evidence.length ? h("div", { class: "evidence-list" }, ...detail.evidence.map((evidence) =>
            h("div", { class: "evidence-item" },
              h("div", { class: "row-between" },
                h("span", { class: "small strong" }, evidence.title),
                h("div", { class: "row" },
                  h("span", { class: "tiny muted" }, evidence.kind),
                  session.user && ["admin", "auditor"].includes(session.user.role)
                    ? button("Content", async () => {
                        try {
                          const result = await api<{ content: string }>(`/api/evidence/${evidence.id}`);
                          modal(evidence.title, h("pre", { class: "json-block", style: { maxHeight: "60vh" } }, result.content), null, { wide: true });
                        } catch (error) {
                          toast(error instanceof Error ? error.message : "Unable to load evidence", "error");
                        }
                      }, "ghost", { class: "btn-sm" })
                    : null,
                ),
              ),
              h("div", { class: "hash" }, `sha256 ${evidence.sha256}`),
              h("div", { class: "hash" }, `chain ${evidence.chain_hash}`),
            ),
          )) : h("p", { class: "muted small" }, "No evidence linked.")),
          sectionBlock("Sessions", detail.sessions.length ? h("div", { class: "stack" }, ...detail.sessions.map((agentSession) =>
            h("div", { class: "row-between" },
              h("div", {},
                h("div", { class: "small" }, `${agentSession.role} / ${agentSession.harness}`),
                h("div", { class: "tiny muted mono" }, agentSession.id.slice(0, 12)),
              ),
              h("div", { class: "tiny muted" }, agentSession.sandbox_mode),
            ),
          )) : h("p", { class: "muted small" }, "No sessions.")),
        ),
      ),
    );
  } catch (error) {
    body.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load finding"));
  }
}

function sectionBlock(title: string, content: HTMLElement): HTMLElement {
  return h("section", {}, h("div", { class: "section-title" }, title), content);
}

function listOrNone(items: string[]): HTMLElement {
  return items.length
    ? h("ul", { class: "narrative" }, ...items.map((item) => h("li", {}, item)))
    : h("p", { class: "muted small" }, "None recorded.");
}

export async function openTaskDetail(taskId: string, onChange?: () => void): Promise<void> {
  const body = h("div", { class: "stack" }, h("div", { class: "loading-state" }, h("span", { class: "spinner" }), "Loading task…"));
  const close = drawer("Task execution", body);
  try {
    const detail = await api<{
      task: Record<string, unknown>;
      dependencies: Array<{ depends_on_task_id: string; status: string; title: string }>;
      events: Array<{ id: number; type: string; payload: Record<string, unknown>; created_at: string }>;
      session: Record<string, unknown> | null;
      evidence: Evidence[];
    }>(`/api/tasks/${taskId}`);
    const task = detail.task;
    fill(body, [
      h("div", {},
        h("div", { class: "row", style: { gap: "var(--space-xs)" } },
          h("span", { class: "mono muted" }, `phase ${String(task.phase)}`),
          statusBadge(String(task.status)),
          task.harness ? h("span", { class: "chip" }, String(task.harness)) : null,
        ),
        h("h2", { style: { margin: "var(--space-xs) 0 var(--space-3xs)", fontSize: "18px", letterSpacing: "-.02em" } }, String(task.title)),
        h("div", { class: "tiny muted" }, `${String(task.kind)} / ${String(task.agent_role ?? "deterministic")} / attempts ${String(task.attempts)}/${String(task.max_attempts)}`),
      ),
      String(task.error ?? "").length > 0
        ? h("div", { class: "callout bad" }, h("div", { class: "tiny muted" }, "Failure"), h("div", { class: "small" }, String(task.error)), h("div", { class: "tiny muted", style: { marginTop: "var(--space-2xs)" } }, String(task.failure_kind ?? "")))
        : null,
      h("div", { class: "action-row" },
        ["failed", "cancelled", "blocked"].includes(String(task.status))
          ? button("Retry task", async () => {
              try {
                await api(`/api/tasks/${task.id}/retry`, { method: "POST" });
                toast("Task queued for retry.", "success");
                close.close();
                onChange?.();
              } catch (error) {
                toast(error instanceof Error ? error.message : "Retry failed", "error");
              }
            }, "secondary")
          : null,
        ["running", "queued", "waiting_approval"].includes(String(task.status))
          ? button("Cancel task", async () => {
              if (!(await confirmAction("Cancel task", "The active harness process will be stopped. The audit continues with a recorded limitation.", "Cancel task"))) return;
              try {
                await api(`/api/tasks/${task.id}/cancel`, { method: "POST" });
                toast("Cancellation requested.", "success");
                close.close();
                onChange?.();
              } catch (error) {
                toast(error instanceof Error ? error.message : "Cancellation failed", "error");
              }
            }, "danger")
          : null,
      ),
      h("div", { class: "section-title" }, "Payload"),
      jsonBlock(task.payload),
      h("div", { class: "section-title" }, "Structured result"),
      task.result ? jsonBlock(task.result) : h("p", { class: "muted small" }, "No result recorded."),
      h("div", { class: "section-title" }, "Dependencies"),
      detail.dependencies.length
        ? h("div", { class: "stack" }, ...detail.dependencies.map((dependency) =>
            h("div", { class: "row-between small" }, h("span", {}, dependency.title), statusBadge(dependency.status)),
          ))
        : h("p", { class: "muted small" }, "No dependencies recorded."),
      h("div", { class: "section-title" }, "Session"),
      detail.session ? jsonBlock(detail.session) : h("p", { class: "muted small" }, "This task did not execute an agent session."),
      h("div", { class: "section-title" }, "Evidence"),
      detail.evidence.length
        ? h("div", { class: "evidence-list" }, ...detail.evidence.map((evidence) =>
            h("div", { class: "evidence-item" },
              h("div", { class: "row-between" }, h("span", { class: "small strong" }, evidence.title), h("span", { class: "tiny muted" }, evidence.kind)),
              h("div", { class: "hash" }, evidence.sha256),
            ),
          ))
        : h("p", { class: "muted small" }, "No evidence linked."),
      h("div", { class: "section-title" }, "Events"),
      h("div", { class: "event-feed" }, ...detail.events.slice(-80).map((event) =>
        h("div", { class: "event-row" },
          h("span", { class: "event-time" }, new Date(event.created_at).toLocaleTimeString()),
          h("span", { class: "event-type" }, event.type),
          h("span", { class: "event-detail" }, eventSummary(event.payload)),
        ),
      )),
    ]);
  } catch (error) {
    body.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load task"));
  }
}

function eventSummary(payload: Record<string, unknown>): string {
  return Object.entries(payload)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${typeof value === "object" ? truncate(JSON.stringify(value), 120) : truncate(String(value), 160)}`)
    .join(", ");
}
