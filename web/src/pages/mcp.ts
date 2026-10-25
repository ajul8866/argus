import type { CatalogView, LocalMcp } from "../../../src/local/types.ts";
import { api, session } from "../api.ts";
import { badge, button, emptyState, errorState, h, input, loading, pageHeader, section } from "../ui.ts";
import { autoRefresh, discoveryDetails, localStatus, sourceList, usagePanel, type Usage } from "../components/local-resources.ts";

export async function renderMcp(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Discovering local MCP configuration"));
  try {
    let catalog = await api<CatalogView>("/api/mcp");
    const frame = h("div", { class: "local-page" });
    const table = h("div", { class: "table-wrap" });
    const detail = h("div", { class: "local-detail" });
    const diagnostics = h("div");
    const search = input("mcp_search", { type: "search", placeholder: "Search local MCP servers" });
    search.setAttribute("aria-label", "Search local MCP servers");
    let selected = params.get("server_id") ?? catalog.servers[0]?.id;
    let version = 0;
    const select = async (server: LocalMcp) => {
      selected = server.id;
      const current = ++version;
      renderTable();
      detail.replaceChildren(loading("Reading MCP usage"));
      try {
        const data = await api<{ usage: Usage }>(`/api/mcp/${server.id}`);
        if (!frame.isConnected || current !== version) return;
        const enabled = h("input", { type: "checkbox", checked: server.enabled, disabled: session.user?.role !== "admin" }) as HTMLInputElement;
        const message = h("p", { class: "small muted", role: "status" }, "Changes apply to new sessions. The source configuration is never rewritten.");
        enabled.addEventListener("change", async () => {
          enabled.disabled = true;
          const desired = enabled.checked;
          try {
            await api(`/api/mcp/${server.id}`, { method: "PUT", body: { enabled: desired } });
            message.textContent = "MCP access setting saved.";
            await refresh(false);
            const updated = catalog.servers.find((item) => item.id === server.id);
            if (updated) status.replaceChildren(localStatus(updated));
          } catch (error) {
            enabled.checked = !desired;
            message.textContent = error instanceof Error ? error.message : "Unable to update access";
          } finally { enabled.disabled = session.user?.role !== "admin"; }
        });
        const status = h("div", { "data-local-status": server.id }, localStatus(server));
        const linked = catalog.skills.filter((skill) => skill.mcp_ids.includes(server.id));
        detail.replaceChildren(
          section(server.name, h("div", {}, status,
            h("p", {}, server.description || "Automatically detected from local MCP configuration."),
            h("dl", { class: "local-definition" }, h("dt", {}, "Transport"), h("dd", {}, server.transport),
              h("dt", {}, server.transport === "stdio" ? "Executable" : "Host"), h("dd", { class: "mono small" }, server.endpoint || "Unavailable")),
            h("h3", { class: "local-subheading" }, "Configuration sources"), sourceList(server.sources),
            server.error ? h("p", { class: "local-warning" }, server.error) : null,
            !server.source_enabled ? h("p", { class: "local-warning" }, "Disabled in the local client configuration. Argus keeps this server disabled until its source is enabled.") : null,
            h("label", { class: "checkbox local-checkbox" }, enabled, "Allow use by linked skills in Argus"), message,
            h("p", { class: "small muted" }, "Discovery reads configuration only. Credentials stay in the session configuration; servers connect when an assigned skill is loaded by an agent."),
          )),
          section("Linked skills", linked.length ? h("ul", { class: "local-links" }, ...linked.map((skill) => h("li", {},
            h("a", { href: `#/skills?skill_id=${encodeURIComponent(skill.id)}` }, skill.name),
            h("span", { class: "small muted" }, ` · ${skill.roles.length} agent role(s)`))))
            : h("p", { class: "muted small" }, "No skills linked. Open a skill to grant access to this MCP server.")),
          h("div", { "data-local-usage": server.id }, usagePanel(data.usage, "mcp")),
        );
      } catch (error) {
        if (frame.isConnected && current === version) detail.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load MCP server"));
      }
    };
    const renderTable = () => {
      const query = search.value.toLowerCase().trim();
      const matches = catalog.servers.filter((server) => `${server.name} ${server.transport} ${server.endpoint} ${server.sources.join(" ")}`.toLowerCase().includes(query));
      table.replaceChildren(h("table", { class: "local-mcp-table" },
        h("thead", {}, h("tr", {}, ...["Server", "Transport", "Availability", "Tool calls"].map((label) => h("th", {}, label)))),
        h("tbody", {}, ...matches.map((server) => h("tr", { class: server.id === selected ? "local-selected-row" : "" },
          h("td", {}, button(server.name, () => void select(server), "ghost", { class: "local-server-button", "aria-pressed": server.id === selected }),
            h("div", { class: "tiny muted local-endpoint" }, server.endpoint)),
          h("td", {}, badge(server.transport)), h("td", {}, localStatus(server)),
          h("td", { class: "mono" }, String(server.stats.total_calls)),
        ))),
      ));
      if (!matches.length) table.append(h("p", { class: "muted small" }, "No MCP servers match this search."));
    };
    let refreshing = false;
    const refresh = async (force: boolean) => {
      if (refreshing) return;
      refreshing = true;
      try {
        catalog = await api<CatalogView>(force ? "/api/mcp/rescan" : "/api/mcp", force ? { method: "POST" } : {});
        if (!frame.isConnected) return;
        renderTable();
        diagnostics.replaceChildren(discoveryDetails(catalog));
        if (!selected && catalog.servers[0]) void select(catalog.servers[0]);
        else if (selected) {
          const server = catalog.servers.find((item) => item.id === selected);
          if (server) detail.querySelector(`[data-local-status="${selected}"]`)?.replaceChildren(localStatus(server));
          const outlet = detail.querySelector(`[data-local-usage="${selected}"]`);
          if (outlet) {
            const usage = await api<Usage>(`/api/mcp/${selected}/usage`);
            if (outlet.isConnected) outlet.replaceChildren(usagePanel(usage, "mcp"));
          }
          if (force && server) void select(server);
        }
      } catch (error) {
        if (frame.isConnected) diagnostics.replaceChildren(errorState(error instanceof Error ? error.message : "Discovery refresh failed"));
      } finally { refreshing = false; }
    };
    search.addEventListener("input", renderTable);
    frame.append(
      pageHeader("MCP servers", "Discovered automatically from local Pi, Claude and Codex configuration. Access follows the skills assigned to each agent role.",
        h("div", { class: "row" }, h("a", { class: "btn btn-secondary", href: "#/skills" }, "Skills"),
          session.user?.role === "admin" ? button("Rescan local", () => void refresh(true), "secondary") : null)),
      diagnostics,
      h("div", { class: "local-mcp-layout" }, section("Local server catalog", h("div", {}, search, table)), detail),
    );
    root.replaceChildren(frame);
    diagnostics.replaceChildren(discoveryDetails(catalog));
    renderTable();
    const initial = catalog.servers.find((server) => server.id === selected);
    if (initial) void select(initial);
    else detail.replaceChildren(emptyState("No local MCP servers detected", "Servers added to a local Pi, Claude or Codex configuration will appear automatically."));
    autoRefresh(frame, () => refresh(false));
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "MCP discovery failed", () => void renderMcp(root, params)));
  }
}
