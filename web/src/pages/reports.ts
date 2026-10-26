import { api, session } from "../api.ts";
import { previewReport } from "../components/report-preview.ts";
import {
  badge,
  button,
  emptyState,
  errorState,
  formatDate,
  h,
  loading,
  pageHeader,
  section,
  statusBadge,
  toast,
} from "../ui.ts";

type Audit = { id: string; project_name: string; status: string; current_phase: number; created_at: string };
type Report = { id: string; audit_id: string; format: string; status: string; path: string | null; sha256: string | null; size: number | null; generated_at: string };

export async function renderReports(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Loading reports"));
  try {
    const [{ audits }, allReports] = await Promise.all([
      api<{ audits: Audit[] }>("/api/audits"),
      api<{ reports: Report[] }>("/api/reports"),
    ]);
    if (audits.length === 0) {
      root.replaceChildren(
        pageHeader("Reports", "Deterministic Markdown, JSON, HTML, and PDF reports from verified records.", null),
        emptyState("No audits yet", "A report can only be generated after an audit exists.", h("a", { class: "btn btn-primary", href: "#/projects" }, "Open projects")),
      );
      return;
    }
    let selected = params.get("audit") ?? audits.find((audit) => ["completed", "completed_with_errors"].includes(audit.status))?.id ?? audits[0]!.id;
    if (!audits.some((audit) => audit.id === selected)) selected = audits[0]!.id;
    const reports = allReports.reports.filter((report) => report.audit_id === selected);
    const audit = audits.find((entry) => entry.id === selected)!;
    const canGenerate = Boolean(
      session.user &&
        ["admin", "auditor"].includes(session.user.role) &&
        ["completed", "completed_with_errors"].includes(audit.status),
    );

    const formatRows = ["markdown", "json", "html", "pdf"].map((format) => {
      const report = reports.find((entry) => entry.format === format);
      return h("tr", {},
        h("td", { class: "strong" }, format === "markdown" ? "Markdown" : format.toUpperCase(),
          h("div", { class: "phone-only" },
            report ? statusBadge(report.status) : badge("not generated", "neutral"),
            h("span", { class: "tiny muted" }, report?.size ? `${Math.round(report.size / 1024)} KiB` : "—"),
            h("span", { class: "tiny muted" }, report ? formatDate(report.generated_at) : "—"),
          ),
        ),
        h("td", { class: "col-optional" }, report ? statusBadge(report.status) : badge("not generated", "neutral")),
        h("td", { class: "mono small col-optional" }, report?.size ? `${Math.round(report.size / 1024)} KiB` : "—"),
        h("td", { class: "small muted col-optional" }, report ? formatDate(report.generated_at) : "—"),
        h("td", { class: "mono tiny col-optional" }, report?.sha256?.slice(0, 24) ?? "—"),
        h("td", {}, report?.status === "generated" ? h("div", { class: "action-row" },
          report.format !== "pdf" ? button("Preview", () => void previewReport(report.id, report.format, "Audit report"), "ghost", { class: "btn-sm", "aria-label": `Preview ${report.format} report` }) : null,
          h("a", { class: "btn btn-sm btn-secondary", href: `/api/reports/${report.id}/download`, "aria-label": `Download ${report.format} report` }, "Download"),
        ) : h("span", { class: "tiny muted" }, "—")),
      );
    });

    root.replaceChildren(
      pageHeader(
        "Reports",
        "Professional deliverables are assembled from immutable findings, verification history, coverage, and hash-chained evidence.",
        canGenerate ? button("Generate selected audit", async () => {
          try {
            await api(`/api/audits/${selected}/reports`, { method: "POST", body: {} });
            toast("All four report formats generated.", "success");
            await renderReports(root, params);
          } catch (error) {
            toast(error instanceof Error ? error.message : "Report generation failed", "error");
          }
        }, "primary") : h("span", { class: "tiny muted" }, "Reports are generated automatically after reverification; manual regeneration is available for completed audits."),
      ),
      h("div", { class: "toolbar" },
        h("div", { class: "row" },
          h("span", { class: "tiny muted" }, "Audit"),
          h("select", {
            class: "input select",
            "aria-label": "Select audit for reports",
            style: { minWidth: "340px" },
            onchange: (event: Event) => {
              location.hash = `#/reports?audit=${(event.target as HTMLSelectElement).value}`;
            },
          }, ...audits.map((entry) => h("option", { value: entry.id, selected: entry.id === selected }, `${entry.project_name}, ${entry.id.slice(0, 8)}, ${entry.status}`))),
        ),
        h("div", { class: "row" }, statusBadge(audit.status), h("span", { class: "tiny muted" }, `Phase ${audit.current_phase}/6`)),
      ),
      h("div", { class: "grid grid-main" },
        section("Report formats", h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "Format"), h("th", { class: "col-optional" }, "Status"), h("th", { class: "col-optional" }, "Size"), h("th", { class: "col-optional" }, "Generated"), h("th", { class: "col-optional" }, "SHA-256"), h("th", {}, ""))),
          h("tbody", {}, ...formatRows),
        ))),
        section("Integrity and scope", h("div", { class: "narrative" },
          h("p", {}, "Every report includes the authorized scope, commit, methodology, coverage limitations, verified findings, unresolved records, and an evidence index with SHA-256 and chain hashes."),
          h("p", {}, "PDF generation uses headless Chrome when available and a built-in deterministic PDF writer otherwise. Report bytes are hashed and recorded."),
          h("div", { class: "callout warn" }, "Reports are not a substitute for human security review. LLM analytical coverage is bounded and is explicitly labeled as such."),
          h("div", { class: "action-row", style: { marginTop: "12px" } },
            h("a", { class: "btn btn-secondary", href: `#/audits/${selected}` }, "Open audit"),
            h("a", { class: "btn btn-ghost", href: `#/audits/${selected}?tab=evidence` }, "Evidence chain"),
          ),
        )),
      ),
      h("div", { style: { height: "14px" } }),
      section("Report history", reports.length
        ? h("div", { class: "table-wrap" }, h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Format"), h("th", { class: "col-optional" }, "Generated"), h("th", { class: "col-optional" }, "Size"), h("th", { class: "col-optional" }, "SHA-256"), h("th", {}, ""))),
            h("tbody", {}, ...reports.map((report) =>
              h("tr", {},
                h("td", { class: "strong" }, report.format === "markdown" ? "Markdown" : report.format.toUpperCase(),
                  h("div", { class: "phone-only" },
                    h("span", { class: "tiny muted" }, formatDate(report.generated_at)),
                    h("span", { class: "tiny muted" }, report.size ? `${Math.round(report.size / 1024)} KiB` : "—"),
                  ),
                ),
                h("td", { class: "small muted col-optional" }, formatDate(report.generated_at)),
                h("td", { class: "mono small col-optional" }, report.size ? `${Math.round(report.size / 1024)} KiB` : "—"),
                h("td", { class: "mono tiny col-optional" }, report.sha256?.slice(0, 32) ?? "—"),
                h("td", {}, report.status === "generated" ? h("div", { class: "action-row" },
                  report.format !== "pdf" ? button("Preview", () => void previewReport(report.id, report.format, "Audit report"), "ghost", { class: "btn-sm", "aria-label": `Preview ${report.format} report` }) : null,
                  h("a", { class: "btn btn-sm btn-secondary", href: `/api/reports/${report.id}/download`, "aria-label": `Download ${report.format} report` }, "Download"),
                ) : null),
              ),
            )),
          ))
        : emptyState("No reports generated for this audit", "Phase 6 creates all four formats after reverification finishes.")),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load reports", () => void renderReports(root, params)));
  }
}
