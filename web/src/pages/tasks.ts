import { api, session } from "../api.ts";
import { openAuditCreate } from "../components/audit-create.ts";
import { openTaskDetail } from "../components/execution-detail.ts";
import {
  badge,
  button,
  emptyState,
  fill,
  errorState,
  formatDate,
  h,
  loading,
  pageHeader,
  phaseLabel,
  section,
  statusBadge,
  timeAgo,
  toast,
} from "../ui.ts";

type TaskRow = {
  id: string;
  audit_id: string;
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
  failure_kind: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  project_name: string;
};

type Approval = {
  id: string;
  audit_id: string | null;
  task_id: string | null;
  action: string;
  scope: string;
  status: string;
  created_at: string;
};

const STATUS_FILTERS = ["all", "running", "queued", "waiting_approval", "failed", "completed", "cancelled"];

export async function renderTasks(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Loading task queue"));
  try {
    const status = params.get("status") ?? "all";
    const [{ tasks }, { approvals }] = await Promise.all([
      api<{ tasks: TaskRow[] }>(`/api/tasks${status !== "all" ? `?status=${encodeURIComponent(status)}` : ""}`),
      api<{ approvals: Approval[] }>("/api/approvals?status=pending"),
    ]);
    const canDecide = session.user?.role === "admin";
    const rows = tasks.map((task) =>
      h("tr", {},
        h("td", {},
          h("a", { class: "table-title", href: `#/audits/${task.audit_id}?tab=tasks` }, task.title),
          h("div", { class: "table-sub" }, `${task.project_name}, ${task.kind}`),
          task.error ? h("div", { class: "table-sub task-error" }, task.error) : null,
          h("div", { class: "phone-only" }, statusBadge(task.status)),
        ),
        h("td", { class: "small nowrap col-optional" }, `${task.phase}, ${phaseLabel(task.phase)}`),
        h("td", { class: "col-optional" },
          h("div", { class: "small" }, task.agent_role ?? "deterministic"),
          h("div", { class: "tiny muted" }, task.harness ? `${task.harness}${task.model ? `, ${task.model}` : ""}` : "platform"),
        ),
        h("td", { class: "col-optional" }, statusBadge(task.status)),
        h("td", { class: "small mono col-optional" }, `${task.attempts}/${task.max_attempts}`),
        h("td", { class: "small muted col-optional" }, task.started_at ? timeAgo(task.started_at) : "—"),
        h("td", {}, h("div", { class: "table-actions" }, button("Inspect", () => void openTaskDetail(task.id, () => void renderTasks(root, params)), "ghost", { class: "btn-sm" }))),
      ),
    );

    const approvalPanel = approvals.length
      ? section("Pending approvals", h("div", { class: "stack" }, ...approvals.map((approval) =>
          h("div", { class: "callout warn" },
            h("div", { class: "row-between" },
              h("div", {},
                h("div", { class: "small strong" }, approval.action.replaceAll("_", " ")),
                h("div", { class: "tiny" }, approval.scope),
                approval.audit_id ? h("a", { class: "tiny", href: `#/audits/${approval.audit_id}` }, "Open audit") : null,
              ),
              canDecide ? h("div", { class: "action-row" },
                button("Deny", async () => {
                  await decide(approval.id, false, root, params);
                }, "danger", { class: "btn-sm" }),
                button("Approve", async () => {
                  await decide(approval.id, true, root, params);
                }, "secondary", { class: "btn-sm" }),
              ) : h("span", { class: "tiny muted" }, "admin"),
            ),
          ),
        )))
      : null;

    fill(root, [
      pageHeader("Tasks", "Durable task graph, retries, deadlines, and execution evidence across both harnesses.", button("New audit", () => void openAuditCreate(), "primary")),
      approvalPanel,
      h("div", { class: "toolbar" },
        h("div", { class: "chip-row" }, ...STATUS_FILTERS.map((filter) =>
          h("a", {
            class: `chip ${status === filter ? "on" : ""}`,
            href: filter === "all" ? "#/tasks" : `#/tasks?status=${filter}`,
          }, filter.replaceAll("_", " ")),
        )),
        h("span", { class: "tiny muted" }, `${tasks.length} tasks shown`),
      ),
      tasks.length
        ? section("Task queue", h("div", { class: "table-wrap" }, h("table", { class: "tasks-table" },
            h("thead", {}, h("tr", {}, h("th", {}, "Task"), h("th", { class: "col-optional" }, "Phase"), h("th", { class: "col-optional" }, "Agent"), h("th", { class: "col-optional" }, "Status"), h("th", { class: "col-optional" }, "Attempt"), h("th", { class: "col-optional" }, "Started"), h("th", {}, ""))),
            h("tbody", {}, ...rows),
          )))
        : emptyState("No tasks match this filter", "Start an audit or select a different status."),
    ]);
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load tasks", () => void renderTasks(root, params)));
  }
}

async function decide(approvalId: string, approved: boolean, root: HTMLElement, params: URLSearchParams): Promise<void> {
  try {
    await api(`/api/approvals/${approvalId}/decide`, {
      method: "POST",
      body: { approved, reason: approved ? "Approved from task queue" : "Denied from task queue" },
    });
    toast(approved ? "Approval granted; task queued." : "Approval denied.", "success");
    await renderTasks(root, params);
  } catch (error) {
    toast(error instanceof Error ? error.message : "Decision failed", "error");
  }
}
