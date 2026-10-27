import { api } from "../api.ts";
import {
  badge,
  emptyState,
  errorState,
  h,
  jsonBlock,
  loading,
  pageHeader,
  section,
  statCard,
} from "../ui.ts";
import { explorationRows, selectAudit, type ExplorationPayload } from "../exploration-data.ts";

export { explorationRows } from "../exploration-data.ts";
export type { ExplorationRow } from "../exploration-data.ts";

export async function renderExploration(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Loading exploration"));
  try {
    const audit = await selectAudit(params);
    if (!audit) {
      root.replaceChildren(
        pageHeader("Exploration", "The lineage from goal to intent to fact to finding.", null),
        emptyState("No audits yet", "The exploration graph appears after a dynamic or hybrid audit starts.", h("a", { class: "btn btn-primary", href: "#/audits" }, "Open audits")),
      );
      return;
    }
    const payload = await api<ExplorationPayload>(`/api/audits/${audit.id}/exploration`);
    const allRows = explorationRows(payload);
    const assetFilter = params.get("asset");
    const anchoredNodes = assetFilter
      ? new Set(payload.anchors.filter((anchor) => anchor.assetId === assetFilter).map((anchor) => anchor.nodeId))
      : null;
    const rows = anchoredNodes
      ? allRows.filter((row) => anchoredNodes.has(row.id))
      : allRows;
    const nodeIds = new Set(rows.map((row) => row.id));
    const edges = payload.edges.filter((edge) => nodeIds.has(edge.fromNodeId) && nodeIds.has(edge.toNodeId));
    const labels = new Map(allRows.map((row) => [row.id, row.label]));

    const items = rows.length === 0
      ? emptyState("No exploration nodes", "The planner has not proposed an intent yet, or this asset has no anchored work.")
      : h("div", { class: "stack" }, ...rows.map((row) =>
          h("details", { class: "panel", open: row.kind === "goal" || row.findingId !== null },
            h("summary", {},
              h("span", { class: "row", style: { gap: "8px", display: "inline-flex" } },
                badge(row.kind, row.kind === "finding" ? "good" : "neutral"),
                h("span", { class: "strong" }, row.label),
                badge(row.status, row.status === "completed" ? "good" : row.status === "failed" ? "bad" : "warn"),
              ),
            ),
            h("div", { class: "small muted", style: { margin: "8px 0" } },
              row.assets.length > 0 ? `Assets: ${row.assets.join(", ")}` : "No anchored asset",
              row.taskId ? ` · Task ${row.taskId}` : "",
              row.sessionId ? ` · Session ${row.sessionId}` : "",
            ),
            row.findingId
              ? h("a", { class: "btn btn-sm btn-secondary", href: `#/evidence/${row.findingId}` }, "Open finding evidence")
              : null,
            jsonBlock(row.payload),
          ),
        ));

    const edgeList = edges.length === 0
      ? h("p", { class: "small muted" }, "No edges recorded.")
      : h("ul", { class: "list" }, ...edges.map((edge) =>
          h("li", { class: "small" },
            `${labels.get(edge.fromNodeId) ?? edge.fromNodeId} → ${edge.kind} → ${labels.get(edge.toNodeId) ?? edge.toNodeId}`,
          ),
        ));

    root.replaceChildren(
      pageHeader("Exploration", "The lineage from goal to intent to fact to finding.", h("a", { class: "btn btn-secondary", href: `#/coverage?audit=${audit.id}` }, "Coverage")),
      h("div", { class: "stat-grid" },
        statCard("Nodes", rows.length, assetFilter ? "filtered by asset" : "goal, intent, fact, finding, hint", "accent"),
        statCard("Intents", rows.filter((row) => row.kind === "intent").length, "planner hypotheses", "accent"),
        statCard("Findings", rows.filter((row) => row.kind === "finding").length, "anchored proofs", "good"),
        statCard("Edges", edges.length, "spawns, derived_from, yields, proves, rejects", "accent"),
      ),
      h("div", { style: { height: "14px" } }),
      section("Nodes", items),
      section("Lineage edges", edgeList),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : String(error)));
  }
}
