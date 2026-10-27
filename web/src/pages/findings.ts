import { api } from "../api.ts";
import { openFindingDetail } from "../components/execution-detail.ts";
import {
  emptyState,
  errorState,
  formatDate,
  h,
  loading,
  pageHeader,
  section,
  severityBadge,
  statusBadge,
  statCard,
} from "../ui.ts";

type Finding = {
  id: string;
  audit_id: string;
  code: string;
  title: string;
  category: string;
  cwe: string | null;
  severity: string;
  status: string;
  files: Array<{ path: string }>;
  verification_decision: string | null;
  retest_decision: string | null;
  updated_at: string;
};

type AuditOption = { id: string; project_name: string; status: string; created_at: string };

const FILTERS = ["all", "reverified", "confirmed", "unresolved", "needs_correction", "rejected"];

export async function renderFindings(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Loading findings"));
  try {
    const status = params.get("status") ?? "all";
    const auditId = params.get("audit") ?? "";
    const query = new URLSearchParams();
    if (status !== "all") query.set("status", status);
    if (auditId) query.set("audit_id", auditId);
    const [{ findings }, { audits }] = await Promise.all([
      api<{ findings: Finding[] }>(`/api/findings${query.toString() ? `?${query.toString()}` : ""}`),
      api<{ audits: AuditOption[] }>("/api/audits"),
    ]);
    const verified = findings.filter((finding) => finding.status === "reverified").length;
    const unresolved = findings.filter((finding) => ["confirmed", "needs_correction", "unresolved"].includes(finding.status)).length;
    const rejected = findings.filter((finding) => finding.status === "rejected").length;

    const rows = findings.map((finding) =>
      h("tr", {},
        h("td", {},
          h("div", { class: "row", style: { gap: "7px" } }, h("span", { class: "mono tiny muted" }, finding.code), h("span", { class: "table-title" }, finding.title)),
          h("div", { class: "table-sub" }, `${finding.category}${finding.cwe ? `, ${finding.cwe}` : ""}, ${finding.files[0]?.path ?? "no location"}`),
          h("div", { class: "phone-only" }, severityBadge(finding.severity), statusBadge(finding.status)),
        ),
        h("td", { class: "col-optional" }, severityBadge(finding.severity)),
        h("td", { class: "col-optional" }, statusBadge(finding.status)),
        h("td", { class: "small col-optional" }, String(finding.retest_decision ?? finding.verification_decision ?? "pending").replaceAll("_", " ").toLowerCase()),
        h("td", { class: "small muted col-optional" }, formatDate(finding.updated_at)),
        h("td", {}, h("div", { class: "action-row" },
          h("a", { class: "btn btn-sm btn-secondary", href: `#/evidence/${finding.id}`, "aria-label": `Open evidence for ${finding.code}: ${finding.title}` }, "Evidence"),
          h("a", { class: "btn btn-sm btn-secondary", href: `#/audits/${finding.audit_id}?tab=findings`, "aria-label": `Open audit for ${finding.code}: ${finding.title}` }, "Audit"),
        )),
      ),
    );

    root.replaceChildren(
      pageHeader("Findings", "Evidence-backed candidates, independent confirmation, reverification, and retained decisions.", null),
      h("div", { class: "stat-grid" },
        statCard("Verified", verified, "passed independent reverification", "good"),
        statCard("Unresolved", unresolved, "awaiting or incomplete retest", "warn"),
        statCard("Rejected", rejected, "removed by reverification", "good"),
        statCard("Total records", findings.length, "including retained false positives", "good"),
      ),
      h("div", { style: { height: "14px" } }),
      h("div", { class: "toolbar" },
        h("div", { class: "chip-row" }, ...FILTERS.map((filter) =>
          h("a", {
            class: `chip ${status === filter ? "on" : ""}`,
            href: buildHref(filter, auditId),
          }, filter.replaceAll("_", " ")),
        )),
        h("div", { class: "row" },
          h("span", { class: "tiny muted" }, "Audit"),
          h("select", {
            class: "input select",
            "aria-label": "Filter findings by audit",
            style: { width: "260px" },
            onchange: (event: Event) => {
              const value = (event.target as HTMLSelectElement).value;
              location.hash = `#/findings?status=${status}${value ? `&audit=${value}` : ""}`;
            },
          },
            h("option", { value: "" }, "All audits"),
            ...audits.map((audit) => h("option", { value: audit.id, selected: audit.id === auditId }, `${audit.project_name}, ${audit.id.slice(0, 8)}, ${audit.status}`)),
          ),
        ),
      ),
      findings.length
        ? section(`${findings.length} findings`, h("div", { class: "table-wrap" }, h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Finding"), h("th", { class: "col-optional" }, "Severity"), h("th", { class: "col-optional" }, "Status"), h("th", { class: "col-optional" }, "Decision"), h("th", { class: "col-optional" }, "Updated"), h("th", {}, ""))),
            h("tbody", {}, ...rows),
          )))
        : emptyState("No findings match", "Findings are created only after a candidate passes independent confirmation and the exact-source evidence gate."),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load findings", () => void renderFindings(root, params)));
  }
}

function buildHref(status: string, auditId: string): string {
  const query = new URLSearchParams();
  if (status !== "all") query.set("status", status);
  if (auditId) query.set("audit", auditId);
  return `#/findings${query.toString() ? `?${query.toString()}` : ""}`;
}
