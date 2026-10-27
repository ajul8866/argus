import { api } from "../api.ts";
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

export type ExplorationAsset = { id: string; kind: string; assetKey: string };
export type ExplorationNode = {
  id: string;
  kind: string;
  status: string;
  payload: Record<string, unknown>;
  taskId: string | null;
  sessionId: string | null;
};
export type ExplorationEdge = { fromNodeId: string; toNodeId: string; kind: string };
export type CoverageEntry = { assetId: string; kind: string; assetKey: string; tested: boolean };
export type ExplorationPayload = {
  assets: ExplorationAsset[];
  nodes: ExplorationNode[];
  edges: ExplorationEdge[];
  anchors: Array<{ nodeId: string; assetId: string }>;
  coverage: CoverageEntry[];
};

export type CoverageRow = {
  assetId: string;
  kind: string;
  assetKey: string;
  tested: boolean;
  nodes: number;
  findings: number;
};

export function coverageRows(payload: ExplorationPayload): CoverageRow[] {
  const nodes = new Map(payload.nodes.map((node) => [node.id, node]));
  return payload.coverage
    .map((entry) => {
      const anchored = payload.anchors
        .filter((anchor) => anchor.assetId === entry.assetId)
        .map((anchor) => nodes.get(anchor.nodeId))
        .filter((node): node is ExplorationNode => Boolean(node));
      return {
        ...entry,
        nodes: anchored.length,
        findings: anchored.filter((node) => node.kind === "finding").length,
      };
    })
    .sort((left, right) => Number(left.tested) - Number(right.tested) || left.assetKey.localeCompare(right.assetKey));
}

export type Audit = { id: string; project_name: string; mode?: string; status: string };

export async function selectAudit(params: URLSearchParams): Promise<Audit | null> {
  const projectId = params.get("project");
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  const { audits } = await api<{ audits: Audit[] }>(`/api/audits${query}`);
  if (audits.length === 0) return null;
  const requested = params.get("audit");
  if (requested && audits.some((audit) => audit.id === requested)) {
    return audits.find((audit) => audit.id === requested)!;
  }
  return audits.find((audit) => audit.mode === "dynamic" || audit.mode === "hybrid") ?? audits[0]!;
}

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
