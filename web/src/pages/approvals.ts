import { api, session } from "../api.ts";
import {
  button,
  emptyState,
  fill,
  errorState,
  formatDate,
  h,
  loading,
  pageHeader,
  section,
  statusBadge,
  toast,
} from "../ui.ts";

type Approval = {
  id: string;
  audit_id: string | null;
  task_id: string | null;
  action: string;
  scope: string;
  status: string;
  requested_by: string | null;
  decided_by: string | null;
  reason: string | null;
  created_at: string;
  decided_at: string | null;
};

export async function renderApprovals(root: HTMLElement): Promise<void> {
  root.replaceChildren(loading("Loading approvals"));
  try {
    const { approvals } = await api<{ approvals: Approval[] }>("/api/approvals");
    const canDecide = session.user?.role === "admin";
    const pending = approvals.filter((approval) => approval.status === "pending");
    const history = approvals.filter((approval) => approval.status !== "pending");
    const rows = approvals.map((approval) =>
      h("tr", {},
        h("td", {},
          h("div", { class: "table-title" }, approval.action.replaceAll("_", " ")),
          h("div", { class: "table-sub" }, approval.scope),
        ),
        h("td", {}, statusBadge(approval.status)),
        h("td", { class: "small" }, approval.audit_id ? h("a", { href: `#/audits/${approval.audit_id}` }, approval.audit_id.slice(0, 8)) : "—"),
        h("td", { class: "small muted" }, formatDate(approval.created_at)),
        h("td", { class: "small muted" }, approval.decided_by ?? "—"),
        h("td", {}, approval.status === "pending" && canDecide
          ? h("div", { class: "action-row" },
              button("Deny", async () => decide(approval.id, false, root), "danger", { class: "btn-sm" }),
              button("Approve", async () => decide(approval.id, true, root), "secondary", { class: "btn-sm" }),
            )
          : h("span", { class: "tiny muted" }, approval.reason ?? "—")),
      ),
    );
    fill(root, [
      pageHeader("Approvals", "Destructive or external-system actions never bypass a failed approval gate.", null),
      h("div", { class: "grid grid-3" },
        h("div", { class: "stat-card stat-warn" }, h("div", { class: "stat-label" }, "Pending"), h("div", { class: "stat-value" }, String(pending.length))),
        h("div", { class: "stat-card" }, h("div", { class: "stat-label" }, "Approved"), h("div", { class: "stat-value" }, String(approvals.filter((approval) => approval.status === "approved").length))),
        h("div", { class: "stat-card" }, h("div", { class: "stat-label" }, "Denied"), h("div", { class: "stat-value" }, String(approvals.filter((approval) => approval.status === "denied").length))),
      ),
      h("div", { style: { height: "14px" } }),
      approvals.length
        ? section("Decision queue", h("div", { class: "table-wrap" }, h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Request"), h("th", {}, "Status"), h("th", {}, "Audit"), h("th", {}, "Requested"), h("th", {}, "Decided by"), h("th", {}, ""))),
            h("tbody", {}, ...rows),
          )))
        : emptyState("No approval requests", "Read-only audit roles do not generate approvals. Shell actions would appear here and remain blocked until decided."),
      history.length ? h("p", { class: "tiny muted" }, `${history.length} decided request(s) retained in the security log.`) : null,
    ]);
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load approvals", () => void renderApprovals(root)));
  }
}

async function decide(approvalId: string, approved: boolean, root: HTMLElement): Promise<void> {
  try {
    await api(`/api/approvals/${approvalId}/decide`, {
      method: "POST",
      body: { approved, reason: approved ? "Approved by administrator" : "Denied by administrator" },
    });
    toast(approved ? "Approval recorded; task queued." : "Approval denied; task cancelled.", "success");
    await renderApprovals(root);
  } catch (error) {
    toast(error instanceof Error ? error.message : "Decision failed", "error");
  }
}
