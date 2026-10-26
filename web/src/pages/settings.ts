import { api, session } from "../api.ts";
import {
  badge,
  button,
  confirmAction,
  emptyState,
  disclosure,
  errorState,
  field,
  formatDate,
  h,
  input,
  loading,
  modal,
  pageHeader,
  section,
  select,
  statusBadge,
  toast,
} from "../ui.ts";

type SettingsResponse = {
  settings: Record<string, unknown>;
  credentials: Array<{ id: string; provider: string; env_var: string; last4: string; updated_at: string }>;
  sandbox: string;
  allowed_roots: string[];
  data_dir: string;
  version: string;
};

type User = { id: string; email: string; name: string; role: "admin" | "auditor" | "viewer"; disabled: number; created_at: string };
type AuditLog = { id: number; actor: string | null; action: string; target: string | null; detail: unknown; ip: string | null; created_at: string };

const SETTING_DEFS: Array<{ key: string; label: string; description: string; type: "number" | "boolean" | "text" | "harness" | "nullable-text" | "sandbox" }> = [
  { key: "audit.max_areas", label: "Maximum assessment areas", description: "Phase 1 caps how many code areas are scheduled.", type: "number" },
  { key: "audit.max_candidates_per_area", label: "Candidates per area", description: "Upper bound accepted from each discovery session.", type: "number" },
  { key: "audit.max_confirmations", label: "Confirmation cap", description: "Candidates beyond this cap remain explicit limitations.", type: "number" },
  { key: "audit.max_reverifications", label: "Reverification cap", description: "Upper bound on independent retests.", type: "number" },
  { key: "audit.max_concurrent_agents", label: "Concurrent agents", description: "Global scheduler ceiling; audited projects may set lower limits.", type: "number" },
  { key: "audit.task_timeout_ms", label: "Task timeout (ms)", description: "Harness execution deadline; cancellation leaves durable evidence.", type: "number" },
  { key: "audit.require_distinct_harness_for_retest", label: "Prefer distinct retest harness", description: "Harness diversity is recorded but never substitutes for fresh contexts.", type: "boolean" },
  { key: "security.allow_shell_tools", label: "Allow shell tools", description: "Permit command execution when a runtime includes a shell tool. Task approval follows the setting below.", type: "boolean" },
  { key: "security.allow_writable_workspace", label: "Allow writable workspaces", description: "Permit audits to request file changes in their workspace copies, with task approval.", type: "boolean" },
  { key: "security.require_approval_for_shell", label: "Require approval for shell", description: "Every shell task remains blocked until an administrator decides.", type: "boolean" },
  { key: "security.sandbox_mode", label: "Sandbox mode", description: "auto tries Bubblewrap; none is explicit workspace-copy isolation in the host/container.", type: "sandbox" },
  { key: "reports.organization", label: "Report organization", description: "Shown on every exported report.", type: "text" },
  { key: "reports.classification", label: "Report classification", description: "Shown on every exported report.", type: "text" },
];

export async function renderSettings(root: HTMLElement): Promise<void> {
  root.replaceChildren(loading("Loading settings"));
  try {
    const isAdmin = session.user?.role === "admin";
    const [settingsResponse, { users }, { entries }] = await Promise.all([
      api<SettingsResponse>("/api/settings"),
      isAdmin ? api<{ users: User[] }>("/api/users") : Promise.resolve({ users: [] }),
      isAdmin ? api<{ entries: AuditLog[] }>("/api/audit-log") : Promise.resolve({ entries: [] }),
    ]);
    const settings = settingsResponse.settings;
    const controls = new Map<string, HTMLElement>();

    const settingRows = SETTING_DEFS.map((definition) => {
      const value = settings[definition.key];
      const labelId = `setting-${definition.key.replace(/[^a-z0-9]+/gi, "-")}-label`;
      const descriptionId = `${labelId}-description`;
      let control: HTMLElement;
      if (definition.type === "boolean") {
        const toggle = h("button", {
          class: `toggle ${value === true ? "on" : ""}`,
          type: "button",
          role: "switch",
          "aria-checked": value === true ? "true" : "false",
          "aria-labelledby": labelId,
          "aria-describedby": descriptionId,
          onclick: () => {
            const next = !toggle.classList.contains("on");
            toggle.classList.toggle("on", next);
            toggle.setAttribute("aria-checked", String(next));
          },
        });
        controls.set(definition.key, toggle);
        control = toggle;
      } else if (definition.type === "harness") {
        const element = select("setting", [
          { value: "pi", label: "Pi Coding Agent" },
          { value: "claude-code", label: "Claude Code" },
        ], String(value ?? "pi"));
        controls.set(definition.key, element);
        control = element;
      } else if (definition.type === "sandbox") {
        const element = select("setting", [
          { value: "auto", label: "auto (prefer Bubblewrap)" },
          { value: "bwrap", label: "bwrap (fail if unavailable)" },
          { value: "none", label: "none (workspace-copy only)" },
        ], String(value ?? "auto"));
        controls.set(definition.key, element);
        control = element;
      } else {
        const element = input("setting", {
          type: definition.type === "number" ? "number" : "text",
          value: value === null || value === undefined ? "" : String(value),
        });
        controls.set(definition.key, element);
        control = element;
      }
      if (control instanceof HTMLInputElement || control instanceof HTMLSelectElement) {
        control.setAttribute("aria-labelledby", labelId);
        control.setAttribute("aria-describedby", descriptionId);
      }
      return h("div", { class: "setting-row", dataset: { settingKey: definition.key } },
        h("div", {}, h("div", { id: labelId, class: "setting-name" }, definition.label), h("div", { id: descriptionId, class: "setting-desc" }, definition.description)),
        h("div", { class: "setting-control" }, control),
      );
    });

    if (!isAdmin) {
      for (const control of controls.values()) {
        if (control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLButtonElement) {
          control.disabled = true;
        }
      }
    }

    const setBooleanControl = (key: string, on: boolean) => {
      const control = controls.get(key);
      if (!(control instanceof HTMLButtonElement)) return;
      control.classList.toggle("on", on);
      control.setAttribute("aria-checked", String(on));
    };
    const resetDangerousToggles = () => {
      setBooleanControl("security.allow_shell_tools", settings["security.allow_shell_tools"] === true);
      setBooleanControl("security.allow_writable_workspace", settings["security.allow_writable_workspace"] === true);
    };

    const saveSettings = async () => {
      const saveButton = root.querySelector<HTMLButtonElement>("[data-save-settings]");
      if (saveButton?.disabled) return;
      if (saveButton) saveButton.disabled = true;
      try {
        const updates: Record<string, unknown> = {};
        for (const definition of SETTING_DEFS) {
          const control = controls.get(definition.key);
          if (!control) continue;
          if (definition.type === "boolean") {
            updates[definition.key] = control.classList.contains("on");
          } else if (definition.type === "number") {
            updates[definition.key] = Number((control as HTMLInputElement).value);
          } else if (definition.type === "nullable-text") {
            updates[definition.key] = (control as HTMLInputElement).value.trim() || null;
          } else {
            updates[definition.key] = (control as HTMLInputElement).value;
          }
        }
        for (const key of Object.keys(updates)) {
          if (Object.is(updates[key], settings[key])) delete updates[key];
        }
        if (Object.keys(updates).length === 0) {
          toast("No changes to save.", "info");
          return;
        }
        if (updates["security.allow_shell_tools"] === true) {
          if (!(await confirmAction("Enable shell tools?", "This permits agents assigned shell tools to request command execution. Each task still requires explicit administrator approval, but the risk surface expands.", "Enable shell tools"))) {
            resetDangerousToggles();
            queueMicrotask(() => saveButton?.focus());
            return;
          }
        }
        if (updates["security.allow_writable_workspace"] === true) {
          if (!(await confirmAction("Enable writable workspaces?", "This lets an audit request a writable workspace copy for agents, so approved tasks can create scratch files and run PoCs inside the disposable copy. The imported snapshot and evidence quotes stay read-only, but each task still needs its own approval and the risk surface expands.", "Enable writable workspaces"))) {
            resetDangerousToggles();
            queueMicrotask(() => saveButton?.focus());
            return;
          }
        }
        await api("/api/settings", { method: "PUT", body: { settings: updates, confirm_shell: updates["security.allow_shell_tools"] === true, confirm_writable_workspace: updates["security.allow_writable_workspace"] === true } });
        toast("Runtime settings saved.", "success");
        await renderSettings(root);
      } catch (error) {
        toast(error instanceof Error ? error.message : "Unable to save settings", "error");
      } finally {
        if (saveButton) saveButton.disabled = false;
      }
    };

    root.replaceChildren(
      pageHeader("Settings", "Your account, AI connection, and audit defaults.", null),
      h("div", { class: "grid grid-main" },
        h("div", { class: "stack" },
          isAdmin ? section("AI connection", h("div", { class: "stack" },
            h("p", { class: "small muted" }, "Choose your audit runtime in AI setup. Add a credential below if its environment does not already provide one."),
            h("a", { class: "btn btn-secondary", href: "#/harnesses" }, "Open AI setup"),
          )) : null,
          isAdmin ? section("Audit defaults", h("div", {},
            ...settingRows.filter((row) => ["audit.max_concurrent_agents", "reports.organization", "reports.classification"].includes(row.dataset.settingKey ?? "")),
            disclosure("Advanced execution settings", ...settingRows.filter((row) => !["audit.max_concurrent_agents", "reports.organization", "reports.classification"].includes(row.dataset.settingKey ?? ""))),
            h("div", { class: "form-actions" }, button("Save settings", () => void saveSettings(), "primary", { "data-save-settings": "" })),
          )) : null,
          isAdmin ? credentialsSection(settingsResponse, root) : null,
          isAdmin ? disclosure("Manage users", usersSection(users, root)) : null,
        ),
        h("div", { class: "stack" },
          section("Your account", accountSection(root)),
          disclosure("Runtime details", section("Runtime posture", h("dl", { class: "kv" },
            h("dt", {}, "Version"), h("dd", {}, settingsResponse.version),
            h("dt", {}, "Sandbox mode"), h("dd", {}, h("span", { class: `badge ${settingsResponse.sandbox === "none" ? "badge-warn" : "badge-good"}` }, settingsResponse.sandbox)),
            h("dt", {}, "Data directory"), h("dd", { class: "mono tiny" }, settingsResponse.data_dir),
            h("dt", {}, "Allowed roots"), h("dd", { class: "mono tiny" }, settingsResponse.allowed_roots.join("\n")),
          ))),
          disclosure("How execution and credentials are protected", section("Security model", h("div", { class: "narrative" },
            h("p", {}, "All assessments are restricted to authorized repositories. Scope is enforced by copying only in-scope files into isolated workspaces; agent prompts never define authorization."),
            h("p", {}, "Harness tools are read-only by default. Shell access is globally disabled, requires administrator enablement, and remains blocked per task until approval is recorded. Writable workspaces are also disabled by default, require an explicit per-audit request and a per-task approval, and never make the imported snapshot writable."),
            h("p", { class: "muted small" }, "Credentials are encrypted at rest with AES-256-GCM. Values are write-only through the API and are injected only into harness child processes."),
          ))),
        ),
      ),
      ...(isAdmin ? [disclosure("Security activity", auditLogSection(entries))] : []),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load settings", () => void renderSettings(root)));
  }
}

function accountSection(root: HTMLElement): HTMLElement {
  const currentPassword = input("current_password", { type: "password", autocomplete: "current-password", required: true });
  const newPassword = input("new_password", { type: "password", autocomplete: "new-password", required: true });
  newPassword.minLength = 12;
  return h("form", {
    class: "stack",
    onsubmit: async (event: Event) => {
      event.preventDefault();
      try {
        await api("/api/auth/password", { method: "POST", body: { current_password: currentPassword.value, new_password: newPassword.value } });
        toast("Password changed; other sessions were revoked.", "success");
        currentPassword.value = "";
        newPassword.value = "";
      } catch (error) {
        toast(error instanceof Error ? error.message : "Password change failed", "error");
      }
    },
  },
    h("div", { class: "row-between" }, h("span", { class: "small strong" }, session.user?.name ?? ""), badge(session.user?.role ?? "", "accent")),
    h("div", { class: "tiny muted" }, session.user?.email ?? ""),
    field("Current password", currentPassword),
    field("New password", newPassword, "At least 12 characters; other sessions are revoked"),
    h("div", { class: "form-actions" }, h("button", { class: "btn btn-secondary", type: "submit" }, "Change password")),
  );
}

function credentialsSection(settings: SettingsResponse, root: HTMLElement): HTMLElement {
  const provider = input("provider", { value: "global", placeholder: "Provider name" });
  const envVar = input("env_var", { placeholder: "MCODE_PROVIDER_API_KEY", required: true });
  const value = input("value", { type: "password", placeholder: "write-only secret", required: true });
  const form = h("form", {
    class: "form",
    onsubmit: async (event: Event) => {
      event.preventDefault();
      try {
        await api("/api/credentials", {
          method: "PUT",
          body: { provider: provider.value.trim().toLowerCase() || "global", env_var: envVar.value.trim().toUpperCase(), value: value.value },
        });
        toast("Credential encrypted and stored.", "success");
        await renderSettings(root);
      } catch (error) {
        toast(error instanceof Error ? error.message : "Unable to store credential", "error");
      }
    },
  },
    h("div", { class: "form-grid" },
      field("Environment variable", envVar, "Injected only into the harness process"),
      field("Secret value", value, "Never returned by the API; only last four characters are shown"),
    ),
    disclosure("Limit to a provider (optional)", field("Provider", provider, "Global makes this variable available to both runtimes.")),
    h("div", { class: "form-actions" }, h("button", { class: "btn btn-secondary", type: "submit" }, "Store credential")),
  );
  return section("Provider credentials",
    h("div", { class: "stack" },
      settings.credentials.length
        ? h("div", { class: "table-wrap" }, h("table", { class: "small-table" },
            h("thead", {}, h("tr", {}, h("th", {}, "Provider"), h("th", {}, "Variable"), h("th", {}, "Last four"), h("th", {}, "Updated"), h("th", {}, ""))),
            h("tbody", {}, ...settings.credentials.map((credential) =>
              h("tr", {},
                h("td", { class: "small" }, credential.provider),
                h("td", { class: "mono tiny" }, credential.env_var),
                h("td", { class: "mono" }, `••••${credential.last4}`),
                h("td", { class: "small muted" }, formatDate(credential.updated_at)),
                h("td", {}, h("div", { class: "table-actions" }, button("Delete", async () => {
                  if (!(await confirmAction("Delete credential", "Harness authentication may fail until a replacement is stored.", "Delete"))) return;
                  try {
                    await api(`/api/credentials/${credential.id}`, { method: "DELETE" });
                    toast("Credential deleted.", "success");
                    await renderSettings(root);
                  } catch (error) {
                    toast(error instanceof Error ? error.message : "Delete failed", "error");
                  }
                }, "ghost", { class: "btn-sm" }))),
              ),
            )),
          ))
        : h("p", { class: "muted small" }, "No platform-managed credentials. Harnesses may still use their normally configured authentication."),
      disclosure("Add credential (optional)", form),
    ),
  );
}

function usersSection(users: User[], root: HTMLElement): HTMLElement {
  const canManage = session.user?.role === "admin";
  return section("Users and roles",
    h("div", { class: "stack" },
      users.length
        ? h("div", { class: "table-wrap" }, h("table", { class: "small-table" },
            h("thead", {}, h("tr", {}, h("th", {}, "User"), h("th", {}, "Role"), h("th", {}, "Status"), h("th", {}, "Created"), h("th", {}, ""))),
            h("tbody", {}, ...users.map((user) =>
              h("tr", {},
                h("td", {}, h("div", { class: "small" }, user.name), h("div", { class: "tiny muted" }, user.email)),
                h("td", {}, badge(user.role, user.role === "admin" ? "accent" : "neutral")),
                h("td", {}, user.disabled ? badge("disabled", "bad") : badge("active", "good")),
                h("td", { class: "small muted" }, formatDate(user.created_at)),
                h("td", {}, canManage ? button("Manage", () => openUserManage(user, root), "ghost", { class: "btn-sm" }) : null),
              ),
            )),
          ))
        : h("p", { class: "muted small" }, "No users available."),
      canManage ? h("div", { class: "action-row" }, button("Add user", () => openUserCreate(root), "secondary")) : null,
    ),
  );
}

function openUserManage(user: User, root: HTMLElement): void {
  const role = select("role", [
    { value: "admin", label: "Administrator" },
    { value: "auditor", label: "Auditor" },
    { value: "viewer", label: "Viewer" },
  ], user.role);
  const disabled = h("input", { type: "checkbox", checked: user.disabled === 1 }) as HTMLInputElement;
  const name = input("name", { value: user.name });
  const instance = modal(`Manage ${user.email}`,
    h("form", {
      class: "form",
      onsubmit: async (event: Event) => {
        event.preventDefault();
        try {
          await api(`/api/users/${user.id}`, { method: "PATCH", body: { role: role.value, disabled: disabled.checked, name: name.value } });
          toast("User updated.", "success");
          instance.close();
          await renderSettings(root);
        } catch (error) {
          toast(error instanceof Error ? error.message : "Update failed", "error");
        }
      },
    },
    field("Name", name),
    field("Role", role),
    h("label", { class: "checkbox" }, disabled, "Disable account and revoke sessions"),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Save user"),
    ),
    ),
    null,
  );
}

function openUserCreate(root: HTMLElement): void {
  const email = input("email", { type: "email", placeholder: "auditor@example.com" });
  const name = input("name", { placeholder: "Display name" });
  const password = input("password", { type: "password" });
  const role = select("role", [
    { value: "auditor", label: "Auditor" },
    { value: "viewer", label: "Viewer" },
    { value: "admin", label: "Administrator" },
  ], "auditor");
  const instance = modal("Create user",
    h("form", {
      class: "form",
      onsubmit: async (event: Event) => {
        event.preventDefault();
        try {
          await api("/api/users", { method: "POST", body: { email: email.value, name: name.value, password: password.value, role: role.value } });
          toast("User created.", "success");
          instance.close();
          await renderSettings(root);
        } catch (error) {
          toast(error instanceof Error ? error.message : "Unable to create user", "error");
        }
      },
    },
    h("div", { class: "form-grid" },
      field("Email", email),
      field("Name", name),
      field("Temporary password", password, "At least 12 characters"),
      field("Role", role),
    ),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Create user"),
    ),
    ),
    null,
  );
}

function auditLogSection(entries: AuditLog[]): HTMLElement {
  return section("Security audit log", entries.length
    ? h("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": "Security audit log", style: { maxHeight: "420px" } }, h("table", { class: "small-table" },
        h("thead", {}, h("tr", {}, h("th", {}, "Time"), h("th", { class: "col-optional" }, "Actor"), h("th", {}, "Action"), h("th", { class: "col-optional" }, "Target"), h("th", { class: "col-optional" }, "IP"))),
        h("tbody", {}, ...entries.slice(0, 100).map((entry) =>
          h("tr", {},
            h("td", { class: "tiny muted nowrap" }, formatDate(entry.created_at)),
            h("td", { class: "tiny col-optional" }, entry.actor ?? "system"),
            h("td", { class: "mono tiny" },
              entry.action,
              h("div", { class: "phone-only tiny muted" }, `${entry.actor ?? "system"}, ${entry.target ?? "no target"}, ${entry.ip ?? "no ip"}`),
            ),
            h("td", { class: "tiny muted truncate col-optional" }, entry.target ?? "—"),
            h("td", { class: "tiny muted col-optional" }, entry.ip ?? "—"),
          ),
        )),
      ))
    : emptyState("No security events", "Authentication, configuration, approvals, and audit controls are recorded here."));
}
