import type { CatalogView, LocalMcp, LocalSkill, ResourceCall, ResourceStats } from "../../../src/local/types.ts";
import { badge, formatDate, h, section, statCard } from "../ui.ts";

export type Usage = { stats: ResourceStats; recent: ResourceCall[] };

export function localStatus(resource: LocalSkill | LocalMcp): HTMLElement {
  if (!resource.present) return badge("Missing locally", "bad");
  if (resource.error) return badge("Configuration error", "bad");
  if ("source_enabled" in resource && !resource.source_enabled) return badge("Disabled in source", "neutral");
  if (!resource.enabled) return badge("Disabled in Argus", "neutral");
  return badge("Detected", "good");
}

export function sourceList(sources: string[]): HTMLElement {
  return h("ul", { class: "local-sources" }, ...sources.map((source) => h("li", { class: "mono tiny" }, source)));
}

export function usagePanel(usage: Usage, kind: "skill" | "mcp"): HTMLElement {
  const countLabel = kind === "skill" ? "Session loads" : "Tool calls";
  return section(kind === "skill" ? "Skill usage" : "MCP usage", h("div", {},
    h("div", { class: "local-stats" },
      statCard(countLabel, usage.stats.total_calls),
      statCard("Tasks covered", usage.stats.tasks_covered),
      statCard("Last used", formatDate(usage.stats.last_call)),
    ),
    h("p", { class: "small muted" }, kind === "skill"
      ? "A load is recorded when an agent session starts with this skill assigned."
      : "Calls are recorded from harness tool-start events. Detection alone does not establish a connection."),
    usage.recent.length > 0 ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["Time", "Agent", "Task", kind === "mcp" ? "Tool" : "Harness"].map((label) => h("th", {}, label)))),
      h("tbody", {}, ...usage.recent.map((call) => h("tr", {},
        h("td", { class: "tiny" }, formatDate(call.created_at)),
        h("td", { class: "tiny mono" }, call.role),
        h("td", {}, h("a", { class: "tiny", href: `#/tasks?audit_id=${encodeURIComponent(call.audit_id)}&task_id=${encodeURIComponent(call.task_id)}` }, call.task_id.slice(0, 8))),
        h("td", { class: "tiny mono" }, kind === "mcp" ? call.tool_name ?? "" : call.harness),
      ))),
    )) : h("p", { class: "muted small" }, "No usage recorded yet."),
  ));
}

export function discoveryDetails(view: CatalogView): HTMLElement {
  return h("details", { class: "local-discovery" },
    h("summary", {}, `Automatic local discovery · ${formatDate(view.scan.scanned_at)}${view.scan.errors.length ? ` · ${view.scan.errors.length} source issue(s)` : ""}`),
    h("p", { class: "small muted" }, "The catalog refreshes automatically every 30 seconds while this page is open. Local files remain the source of truth."),
    sourceList(view.scan.roots),
    ...view.scan.errors.map((error) => h("p", { class: "small local-warning" }, h("span", { class: "mono tiny" }, error.source), h("br"), error.message)),
  );
}

export function autoRefresh(container: HTMLElement, refresh: () => Promise<void>): void {
  const timer = setInterval(() => {
    if (!container.isConnected) { clearInterval(timer); return; }
    if (document.visibilityState === "visible") void refresh();
  }, 30_000);
}
