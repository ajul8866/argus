import { api, session } from "../api.ts";
import {
  badge,
  button,
  emptyState,
  disclosure,
  errorState,
  field,
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

type Agent = {
  role: string;
  label: string;
  harness: "pi" | "claude-code";
  model: string | null;
  system_instructions: string;
  allowed_tools: string[];
  max_duration_ms: number;
  max_retries: number;
  concurrency_limit: number;
  budget_usd: number | null;
  allow_shell: boolean;
  enabled: boolean;
  updated_at: string;
};

type Harness = { kind: string; status: string; models: Array<{ id: string; label: string }> };

export async function renderAgents(root: HTMLElement): Promise<void> {
  root.replaceChildren(loading("Loading agent roles"));
  try {
    const [{ agents }, { harnesses }] = await Promise.all([
      api<{ agents: Agent[] }>("/api/agents"),
      api<{ harnesses: Harness[] }>("/api/harnesses"),
    ]);
    const isAdmin = session.user?.role === "admin";
    const auditAgents = agents.filter((agent) => ["codebase_mapper", "security_researcher", "independent_validator", "retest_auditor"].includes(agent.role));
    const rows = auditAgents.map((agent) =>
      h("tr", {},
        h("td", {},
          h("div", { class: "row", style: { gap: "7px" } }, h("span", { class: "table-title" }, agent.label), agent.enabled ? null : badge("disabled", "bad")),
          h("div", { class: "table-sub mono" }, agent.role),
        ),
        h("td", {}, h("span", { class: `chip ${agent.harness === "pi" ? "on" : ""}` }, agent.harness)),
        h("td", { class: "mono small" }, agent.model ?? "harness default"),
        h("td", { class: "mono tiny" }, agent.allowed_tools.join(", ") || "none"),
        h("td", { class: "small" }, `${Math.round(agent.max_duration_ms / 60000)}m`),
        h("td", { class: "small" }, agent.budget_usd === null ? "unlimited" : `$${agent.budget_usd.toFixed(2)}`),
        h("td", { class: "small" }, String(agent.concurrency_limit)),
        h("td", {}, h("div", { class: "table-actions" }, isAdmin ? button("Edit", () => openAgentEdit(agent, harnesses, () => void renderAgents(root)), "ghost", { class: "btn-sm" }) : h("span", { class: "tiny muted" }, "admin"))),
      ),
    );

    root.replaceChildren(
      pageHeader(
        "Agents",
        "Roles, harness assignments, models, tool permissions, budgets, and concurrency limits.",
        h("a", { class: "btn btn-secondary", href: "#/harnesses" }, "Harness health"),
      ),
      section(`${auditAgents.length} audit roles`, h("div", { class: "table-wrap" }, h("table", { class: "agents-table" },
        h("thead", {}, h("tr", {}, h("th", {}, "Role"), h("th", {}, "Harness"), h("th", {}, "Model"), h("th", {}, "Tools"), h("th", {}, "Timeout"), h("th", {}, "Budget"), h("th", {}, "Conc."), h("th", {}, ""))),
        h("tbody", {}, ...rows),
      ))),
      disclosure("How audit roles work", h("div", { class: "grid grid-2" },
        section("Independence rules", h("div", { class: "narrative" },
          h("p", {}, "Discovery, confirmation, and reverification always run in separate agent sessions. The platform rejects a confirmation or retest executed by the session that discovered the issue."),
          h("p", {}, "The default assignments use Claude Code for independent validation and Pi for mapping, discovery, and reverification. This creates harness diversity, but independence is established by fresh contexts, immutable provenance, and exact-source evidence checks — not by the harness name alone."),
          h("p", { class: "muted small" }, "The findings manager and report writer roles are disabled by default. Phase 4 and Phase 6 are deterministic platform operations so that persisted findings and reports cannot invent evidence."),
        )),
        section("Configured harnesses", h("div", { class: "stack" }, ...harnesses.map((harness) =>
          h("div", { class: "row-between" },
            h("div", {}, h("span", { class: "small strong" }, harness.kind), h("div", { class: "tiny muted" }, `${harness.models.length} models reported`)),
            statusBadge(harness.status),
          ),
        ), h("a", { class: "btn btn-ghost btn-sm", href: "#/harnesses" }, "Open harness manager"))),
      )),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load agents", () => void renderAgents(root)));
  }
}

function openAgentEdit(agent: Agent, harnesses: Harness[], refresh: () => void): void {
  const harnessSelect = select(
    "harness",
    harnesses.map((harness) => ({ value: harness.kind, label: harness.kind })),
    agent.harness,
  );
  const model = input("model", { value: agent.model ?? "", placeholder: "harness default or model id" });
  const tools = input("allowed_tools", { value: agent.allowed_tools.join(",") });
  const systemPrompt = h("textarea", { class: "input textarea", name: "system_instructions", rows: 7 }, agent.system_instructions) as HTMLTextAreaElement;
  const retriesInput = input("max_retries", { type: "number", value: String(agent.max_retries), min: 0, max: 5 });
  const duration = input("max_duration_ms", { type: "number", value: String(Math.round(agent.max_duration_ms / 1000)), min: 10, max: 3600 });
  const budget = input("budget_usd", { type: "number", value: agent.budget_usd === null ? "" : String(agent.budget_usd), min: 0, step: 0.5 });
  const enabled = h("input", { type: "checkbox", checked: agent.enabled }) as HTMLInputElement;
  const errorBox = h("div", { class: "login-error hidden" });
  const models = harnesses.find((harness) => harness.kind === agent.harness)?.models ?? [];

  const instance = modal(
    `Edit ${agent.label}`,
    h("form", {
      class: "form",
      onsubmit: async (event: Event) => {
        event.preventDefault();
        errorBox.classList.add("hidden");
        try {
          await api(`/api/agents/${agent.role}`, {
            method: "PUT",
            body: {
              harness: harnessSelect.value,
              model: model.value.trim() || null,
              allowed_tools: tools.value.split(",").map((tool) => tool.trim()).filter(Boolean),
              max_duration_ms: Number(duration.value) * 1000,
              budget_usd: budget.value === "" ? null : Number(budget.value),
              max_retries: Number(retriesInput.value),
              system_instructions: systemPrompt.value,
              enabled: enabled.checked,
            },
          });
          instance.close();
          toast("Agent role updated. New tasks use this configuration.", "success");
          refresh();
        } catch (error) {
          errorBox.textContent = error instanceof Error ? error.message : "Unable to update role";
          errorBox.classList.remove("hidden");
        }
      },
    },
    errorBox,
    h("p", { class: "modal-copy" }, "Changing a role changes future task assignments only. Existing sessions keep their recorded harness and model provenance."),
    h("div", { class: "form-grid" },
      field("Harness", harnessSelect),
      field("Model", model, `${models.length} models reported by this harness`),
    ),
    disclosure("Advanced role settings", h("div", { class: "form-grid" },
      field("Allowed tools", tools), field("System instructions", systemPrompt),
      field("Max retries", retriesInput), field("Max duration (seconds)", duration),
      field("Budget (USD)", budget, "Empty means no per-task budget."),
      h("label", { class: "checkbox full" }, enabled, "Role enabled"),
    )),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Save role"),
    ),
  ),
  null,
  { wide: true },
  );
}
