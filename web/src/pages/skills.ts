import type { CatalogView } from "../../../src/local/types.ts";
import { api, session } from "../api.ts";
import { badge, button, emptyState, errorState, h, input, loading, pageHeader } from "../ui.ts";
import { autoRefresh, discoveryDetails, localStatus, usagePanel, type Usage } from "../components/local-resources.ts";
import { renderSkillDetail, type SkillDraft } from "../components/skill-detail.ts";

export async function renderSkills(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Discovering local skills"));
  try {
    let catalog = await api<CatalogView>("/api/skills");
    const frame = h("div", { class: "local-page" });
    const list = h("nav", { class: "local-resource-list", "aria-label": "Local skills" });
    const detail = h("div", { class: "local-resource-detail" });
    const diagnostics = h("div");
    const count = h("span", { class: "small muted", role: "status" });
    const search = input("skill_search", { type: "search", placeholder: "Search local skills" });
    search.setAttribute("aria-label", "Search local skills");
    const drafts = new Map<string, SkillDraft>();
    let selected = params.get("skill_id") ?? catalog.skills.find((skill) => skill.present && !skill.error)?.id ?? catalog.skills[0]?.id;
    const select = async (id: string) => {
      selected = id;
      const skill = catalog.skills.find((item) => item.id === id);
      renderList();
      if (skill) {
        try { await renderSkillDetail(detail, skill, catalog, drafts, () => refresh(false)); }
        catch (error) { detail.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load skill")); }
      }
    };
    const renderList = () => {
      const query = search.value.toLowerCase().trim();
      const matches = catalog.skills.filter((skill) => `${skill.name} ${skill.description} ${skill.sources.join(" ")}`.toLowerCase().includes(query));
      count.textContent = `${matches.length} of ${catalog.skills.length} skills`;
      list.replaceChildren(...matches.map((skill) => h("button", { type: "button", class: `local-resource-item${skill.id === selected ? " selected" : ""}`,
        "aria-current": skill.id === selected ? "true" : "false", onclick: () => void select(skill.id),
      }, h("span", { class: "local-resource-name" }, skill.name),
      h("span", { class: "tiny muted" }, skill.description.slice(0, 100) || skill.sources[0] || "Local skill"),
      h("span", { class: "local-resource-meta" }, localStatus(skill), badge(`${skill.stats.total_calls} loads`)),
      )));
      if (!matches.length) list.append(h("p", { class: "small muted" }, "No skills match this search."));
    };
    let refreshing = false;
    const refresh = async (force: boolean) => {
      if (refreshing) return;
      refreshing = true;
      try {
        catalog = await api<CatalogView>(force ? "/api/skills/rescan" : "/api/skills", force ? { method: "POST" } : {});
        if (!frame.isConnected) return;
        renderList();
        diagnostics.replaceChildren(discoveryDetails(catalog));
        if (!selected && catalog.skills[0]) void select(catalog.skills[0].id);
        else if (selected) {
          const skill = catalog.skills.find((item) => item.id === selected);
          if (skill) detail.querySelector(`[data-local-status="${selected}"]`)?.replaceChildren(localStatus(skill));
          const outlet = detail.querySelector(`[data-local-usage="${selected}"]`);
          if (outlet) {
            const usage = await api<Usage>(`/api/skills/${selected}/usage`);
            if (outlet.isConnected) outlet.replaceChildren(usagePanel(usage, "skill"));
          }
          if (force) void select(selected);
        }
      } catch (error) {
        if (frame.isConnected) diagnostics.replaceChildren(errorState(error instanceof Error ? error.message : "Discovery refresh failed", () => void refresh(false)));
      } finally { refreshing = false; }
    };
    search.addEventListener("input", renderList);
    frame.append(
      pageHeader("Skills", "Local skills are discovered automatically. Control which agent roles load them and which MCP servers they unlock.",
        h("div", { class: "row" }, h("a", { class: "btn btn-secondary", href: "#/mcp" }, "MCP servers"),
          session.user?.role === "admin" ? button("Rescan local", () => void refresh(true), "secondary") : null)),
      diagnostics,
      h("div", { class: "local-catalog-layout" }, h("aside", { class: "local-catalog-sidebar" }, search, count, list), detail),
    );
    root.replaceChildren(frame);
    diagnostics.replaceChildren(discoveryDetails(catalog));
    renderList();
    if (selected) void select(selected);
    else detail.replaceChildren(emptyState("No local skills detected", "Skills installed in Agents, Codex, Claude, Pi, or this project's skill directories will appear automatically."));
    autoRefresh(frame, () => refresh(false));
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Local discovery failed", () => void renderSkills(root, params)));
  }
}
