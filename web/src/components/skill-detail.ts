import type { CatalogView, LocalSkill } from "../../../src/local/types.ts";
import { api, session } from "../api.ts";
import { button, errorState, h, loading, section, toast } from "../ui.ts";
import { localStatus, sourceList, usagePanel, type Usage } from "./local-resources.ts";

export type SkillDraft = { enabled: boolean; roles: string[]; mcp_ids: string[] };

export async function renderSkillDetail(root: HTMLElement, skill: LocalSkill, catalog: CatalogView,
  drafts: Map<string, SkillDraft>, refresh: () => Promise<void>): Promise<void> {
  const frame = h("div", { class: "local-detail" });
  root.replaceChildren(frame);
  const admin = session.user?.role === "admin";
  if (!skill.present) {
    frame.append(section(skill.name, h("div", {}, localStatus(skill), h("p", { class: "muted" }, "The local skill directory is missing. Access settings and usage history are retained."), sourceList(skill.sources))));
    const usage = await api<Usage>(`/api/skills/${skill.id}/usage`);
    if (frame.isConnected) frame.append(h("div", { "data-local-usage": skill.id }, usagePanel(usage, "skill")));
    return;
  }
  frame.append(loading("Reading local skill"));
  try {
    const data = await api<{ files: string[]; usage: Usage }>(`/api/skills/${skill.id}`);
    if (!frame.isConnected) return;
    const draft = drafts.get(skill.id) ?? { enabled: skill.enabled, roles: [...skill.roles], mcp_ids: [...skill.mcp_ids] };
    const save = button("Save access", () => void saveAccess(), "primary");
    save.disabled = !drafts.has(skill.id);
    const message = h("span", { class: "small muted", role: "status" }, drafts.has(skill.id) ? "Unsaved changes" : "Applies to new agent sessions");
    const markChanged = () => { drafts.set(skill.id, draft); save.disabled = false; message.textContent = "Unsaved changes"; };
    const checkbox = (label: string, checked: boolean, changed: (value: boolean) => void, detail?: string) => {
      const control = h("input", { type: "checkbox", checked, disabled: !admin, onchange: (event: Event) => { changed((event.target as HTMLInputElement).checked); markChanged(); } });
      return h("label", { class: "checkbox local-checkbox" }, control, h("span", {}, label, detail ? h("span", { class: "local-option-detail" }, detail) : null));
    };
    const toggle = (values: string[], id: string, checked: boolean) => checked ? [...new Set([...values, id])] : values.filter((value) => value !== id);
    const permissions = h("fieldset", { class: "local-permissions" },
      h("legend", { class: "sr-only" }, "Skill access settings"),
      checkbox("Skill enabled in Argus", draft.enabled, (value) => { draft.enabled = value; }),
      h("h3", { class: "local-subheading" }, "Agent visibility"),
      h("p", { class: "small muted" }, "Assigned skills load automatically when these roles start a session."),
      h("div", { class: "local-check-grid" }, ...catalog.roles.map((role) => checkbox(role.label, draft.roles.includes(role.role),
        (value) => { draft.roles = toggle(draft.roles, role.role, value); }, role.enabled ? undefined : "Role disabled"))),
      h("h3", { class: "local-subheading" }, "Linked MCP servers"),
      h("p", { class: "small muted" }, "Only enabled servers linked to a loaded skill are included in the session."),
      catalog.servers.length ? h("div", { class: "local-check-grid" }, ...catalog.servers.map((server) => checkbox(server.name,
        draft.mcp_ids.includes(server.id), (value) => { draft.mcp_ids = toggle(draft.mcp_ids, server.id, value); },
        `${!server.present ? "Missing locally" : server.error ? server.error : !server.source_enabled ? "Disabled in source" : server.transport}${catalog.servers.filter((item) => item.name === server.name).length > 1 ? ` · ${server.sources[0]?.split("/").slice(-2).join("/") ?? ""}` : ""}`)))
        : h("p", { class: "small muted" }, "No local MCP configuration detected."),
    );
    const saveAccess = async () => {
      save.disabled = true;
      permissions.disabled = true;
      message.textContent = "Saving access…";
      try {
        await api(`/api/skills/${skill.id}`, { method: "PUT", body: draft });
        drafts.delete(skill.id);
        message.textContent = "Saved. Applies to new agent sessions.";
        toast("Skill access saved", "success");
        await refresh();
      } catch (error) {
        message.textContent = error instanceof Error ? error.message : "Unable to save access";
        save.disabled = false;
      } finally { permissions.disabled = false; }
    };
    const preview = h("pre", { class: "local-file-preview", tabindex: 0, "aria-label": "Skill file contents" });
    const filename = h("span", { class: "mono small" }, "SKILL.md");
    const fileTree = h("nav", { class: "local-files", "aria-label": "Skill files" });
    let readVersion = 0;
    const openFile = async (path: string) => {
      const version = ++readVersion;
      filename.textContent = path;
      preview.textContent = "Loading file…";
      for (const item of fileTree.querySelectorAll<HTMLElement>("[data-file]")) item.setAttribute("aria-current", item.dataset.file === path ? "true" : "false");
      try {
        const file = await api<{ content: string }>(`/api/skills/${skill.id}/file?path=${encodeURIComponent(path)}`);
        if (version === readVersion && frame.isConnected) preview.textContent = file.content;
      } catch (error) { if (version === readVersion) preview.textContent = error instanceof Error ? error.message : "Unable to read file"; }
    };
    for (const path of data.files) fileTree.append(button(path, () => void openFile(path), "ghost", { class: "local-file", "data-file": path, title: path }));
    frame.replaceChildren(
      section(skill.name, h("div", {}, h("div", { "data-local-status": skill.id }, localStatus(skill)), h("p", {}, skill.description || "Local skill instructions"), sourceList([skill.path, ...skill.sources]),
        skill.error ? h("p", { class: "local-warning" }, skill.error) : null,
        permissions, admin ? h("div", { class: "form-actions" }, message, save) : h("p", { class: "small muted" }, "An administrator can change access settings."))),
      section("Skill files", h("div", { class: "local-file-layout" }, fileTree, h("div", { class: "local-file-content" }, filename, preview))),
      h("div", { "data-local-usage": skill.id }, usagePanel(data.usage, "skill")),
    );
    void openFile("SKILL.md");
  } catch (error) {
    if (frame.isConnected) frame.replaceChildren(section(skill.name, h("div", {}, localStatus(skill), sourceList(skill.sources))),
      errorState(error instanceof Error ? error.message : "Unable to read local skill"));
  }
}
