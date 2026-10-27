import { api } from "../api.ts";
import { coverageRows, selectAudit, type ExplorationPayload } from "../exploration-data.ts";
import {
  badge,
  emptyState,
  errorState,
  h,
  loading,
  pageHeader,
  section,
  statCard,
} from "../ui.ts";

export { coverageRows, selectAudit } from "../exploration-data.ts";
export type {
  Audit,
  CoverageEntry,
  CoverageRow,
  ExplorationAsset,
  ExplorationEdge,
  ExplorationNode,
  ExplorationPayload,
} from "../exploration-data.ts";

export async function renderCoverage(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Loading coverage"));
  try {
    const audit = await selectAudit(params);
    if (!audit) {
      root.replaceChildren(
        pageHeader("Target & coverage", "Assets discovered during dynamic exploration and whether each was actually tested.", null),
        emptyState("No audits yet", "Coverage appears after an audit with an authorized target starts.", h("a", { class: "btn btn-primary", href: "#/audits" }, "Open audits")),
      );
      return;
    }
    const payload = await api<ExplorationPayload>(`/api/audits/${audit.id}/exploration`);
    const rows = coverageRows(payload);
    const tested = rows.filter((row) => row.tested).length;
    const findings = rows.reduce((total, row) => total + row.findings, 0);
    const table = rows.length === 0
      ? emptyState("No assets recorded", "The exploration graph has no assets yet. Static audits use the code map instead.")
      : h("table", { class: "table" },
          h("thead", {},
            h("tr", {},
              h("th", {}, "Asset"),
              h("th", { class: "col-optional" }, "Kind"),
              h("th", {}, "Status"),
              h("th", { class: "col-optional" }, "Nodes"),
              h("th", { class: "col-optional" }, "Findings"),
              h("th", {}, ""),
            ),
          ),
          h("tbody", {}, ...rows.map((row) =>
            h("tr", {},
              h("td", {},
                h("div", { class: "table-title mono" }, row.assetKey),
                h("div", { class: "table-sub" }, row.assetId),
              ),
              h("td", { class: "small col-optional" }, row.kind.replaceAll("_", " ")),
              h("td", {}, badge(row.tested ? "tested" : "not tested", row.tested ? "good" : "warn")),
              h("td", { class: "small col-optional" }, String(row.nodes)),
              h("td", { class: "small col-optional" }, String(row.findings)),
              h("td", {}, h("a", { class: "btn btn-sm btn-secondary", href: `#/exploration?audit=${audit.id}&asset=${row.assetId}` }, "Explore")),
            ),
          )),
        );

    root.replaceChildren(
      pageHeader("Target & coverage", "Assets discovered during dynamic exploration and whether each was actually tested.", h("a", { class: "btn btn-secondary", href: `#/audits/${audit.id}` }, "Open audit")),
      h("div", { class: "stat-grid" },
        statCard("Assets", rows.length, audit.project_name, "accent"),
        statCard("Tested", tested, "at least one completed anchored node", "good"),
        statCard("Not tested", rows.length - tested, "no completed anchor yet", "warn"),
        statCard("Findings", findings, "anchored finding nodes", "accent"),
      ),
      h("div", { style: { height: "14px" } }),
      section("Coverage", table),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : String(error)));
  }
}
