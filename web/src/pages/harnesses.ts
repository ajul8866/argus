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

type Harness = {
  kind: "pi" | "claude-code";
  label: string;
  executable: string;
  version: string | null;
  status: string;
  detail: string;
  auth: { ready: boolean; detail: string };
  capabilities: Record<string, boolean>;
  config: {
    executable: string;
    provider: string | null;
    model: string | null;
    permission_mode: string;
    allowed_tools: string[];
    extra_args: string[];
  };
  models: Array<{ id: string; label: string }>;
  detected_at: string;
};

type TestResult = {
  detection: Harness;
  result: {
    status: string;
    structured: unknown;
    usage: { input_tokens: number; output_tokens: number; cost_usd: number; duration_ms: number };
    error: string | null;
    sandbox: string;
    duration_ms: number;
  } | null;
};

export async function renderHarnesses(root: HTMLElement): Promise<void> {
  root.replaceChildren(loading("Detecting harnesses"));
  try {
    const [{ harnesses }, { agents }] = await Promise.all([
      api<{ harnesses: Harness[] }>("/api/harnesses"),
      api<{ agents: Array<{ role: string; harness: string; enabled: boolean }> }>("/api/agents"),
    ]);
    const isAdmin = session.user?.role === "admin";

    const cards = harnesses.map((harness) => {
      const capabilities = Object.entries(harness.capabilities).filter(([, value]) => typeof value === "boolean");
      return h("div", { class: "panel harness-card" },
        h("div", { class: "harness-head" },
          h("div", {},
            h("div", { class: "row", style: { gap: "8px" } },
              h("span", { class: "harness-name" }, harness.label),
              statusBadge(harness.status),
            ),
            h("div", { class: "harness-sub" }, `${harness.executable}${harness.version ? `, version ${harness.version}` : ""}`),
          ),
          h("div", { class: "row" },
            isAdmin && harness.status !== "missing" ? button(
              agents.filter((agent) => ["codebase_mapper", "security_researcher", "independent_validator", "retest_auditor"].includes(agent.role)).every((agent) => agent.harness === harness.kind && agent.enabled)
                ? "Use for all audits" : "Use for audits",
              async (event) => {
                const trigger = event.currentTarget as HTMLButtonElement;
                trigger.disabled = true;
                try {
                  await api(`/api/harnesses/${harness.kind}/assign`, { method: "POST", body: {} });
                  toast(`${harness.label} selected for all audit roles.`, "success");
                  await renderHarnesses(root);
                } catch (error) { toast(error instanceof Error ? error.message : "Unable to assign runtime", "error"); }
                finally { trigger.disabled = false; }
              }, "primary", { class: "btn-sm" },
            ) : null,
            isAdmin ? button("Configure", () => openHarnessConfig(harness, () => void renderHarnesses(root)), "ghost", { class: "btn-sm" }) : null,
          ),
        ),
        h("div", { class: `callout ${harness.status === "ready" ? "good" : harness.status === "missing" ? "bad" : "warn"}` },
          h("div", { class: "small" }, harness.detail),
          h("div", { class: "tiny muted", style: { marginTop: "var(--space-2xs)" } }, harness.auth.detail),
        ),
        h("p", { class: "small muted" }, "Use for audits selects this runtime and its default model for every audit role. Validation still uses separate sessions."),
        disclosure("Technical details",
        h("div", {},
          h("div", { class: "tiny muted", style: { marginBottom: "var(--space-2xs)" } }, "Capabilities"),
          h("div", { class: "cap-grid" }, ...capabilities.map(([capability, supported]) =>
            h("div", { class: `cap ${supported ? "on" : ""}` }, capability.replaceAll("_", " ")),
          )),
        ),
        h("div", {},
          h("div", { class: "tiny muted", style: { marginBottom: "var(--space-2xs)" } }, "Configuration"),
          h("dl", { class: "kv" },
            h("dt", {}, "Provider"), h("dd", {}, harness.config.provider ?? "harness default"),
            h("dt", {}, "Model"), h("dd", { class: "mono" }, harness.config.model ?? "harness default"),
            h("dt", {}, "Permission mode"), h("dd", {}, harness.config.permission_mode),
            h("dt", {}, "Allowed tools"), h("dd", { class: "mono tiny" }, harness.config.allowed_tools.join(", ") || "none"),
          ),
        ),
        harness.models.length
          ? h("details", {},
              h("summary", { class: "tiny muted", style: { cursor: "pointer" } }, `${harness.models.length} selectable models`),
              h("div", { class: "chip-row", style: { marginTop: "8px", maxHeight: "130px", overflowY: "auto" } },
                ...harness.models.slice(0, 80).map((model) => h("span", { class: "chip mono", title: model.label }, model.id)),
              ),
            )
          : null,
          isAdmin ? button("Run connection test", async () => {
            try {
              const result = await api<TestResult>(`/api/harnesses/${harness.kind}/test`, { method: "POST", body: {} });
              showTestResult(harness, result);
            } catch (error) { toast(error instanceof Error ? error.message : "Connection test failed", "error"); }
          }, "secondary") : null,
          h("p", { class: "small muted" }, "A connection test calls the model and may use provider credits."),
        ),
      );
    });

    root.replaceChildren(
      pageHeader(
        "AI setup",
        "Choose Pi or Claude Code and a model to run your audits.",
        isAdmin ? h("a", { class: "btn btn-secondary", href: "#/agents" }, "Agent assignments") : null,
      ),
      h("div", { class: "grid grid-2" }, ...cards),

    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load harnesses", () => void renderHarnesses(root)));
  }
}

function showTestResult(harness: Harness, result: TestResult): void {
  const body = h("div", { class: "stack" },
    h("div", { class: `callout ${result.result?.status === "completed" ? "good" : "bad"}` },
      h("div", { class: "small strong" }, result.result?.status === "completed" ? "Harness executed successfully" : "Harness test did not complete"),
      h("div", { class: "tiny" }, result.result?.error ?? "Structured response received."),
    ),
    result.result
      ? h("dl", { class: "kv" },
          h("dt", {}, "Sandbox"), h("dd", {}, result.result.sandbox),
          h("dt", {}, "Model tokens"), h("dd", {}, `${result.result.usage.input_tokens} in / ${result.result.usage.output_tokens} out`),
          h("dt", {}, "Reported cost"), h("dd", {}, `$${(result.result.usage.cost_usd ?? 0).toFixed(4)}`),
          h("dt", {}, "Duration"), h("dd", {}, `${Math.round(result.result.duration_ms || result.result.usage.duration_ms)}ms`),
        )
      : null,
    result.result?.structured ? h("pre", { class: "json-block" }, JSON.stringify(result.result.structured, null, 2)) : null,
    h("div", { class: "hint" }, "This was a real harness invocation. It is not a simulated connectivity check."),
  );
  modal(`${harness.label} connection test`, body, null, { wide: true });
}

function openHarnessConfig(harness: Harness, refresh: () => void): void {
  const executable = input("executable", { value: harness.config.executable });
  const provider = input("provider", { value: harness.config.provider ?? "" });
  const model = input("model", { value: harness.config.model ?? "", placeholder: "provider/model or default" });
  provider.required = harness.kind === "pi";
  model.required = harness.kind === "pi";
  const permission = select(
    "permission_mode",
    [
      { value: "plan", label: "plan (read-only)" },
      { value: "dontAsk", label: "dontAsk" },
      { value: "acceptEdits", label: "acceptEdits (not recommended)" },
      { value: "manual", label: "manual" },
    ],
    harness.config.permission_mode,
  );
  const tools = input("allowed_tools", { value: harness.config.allowed_tools.join(",") });
  const extraArgs = input("extra_args", { value: harness.config.extra_args.join(",") });
  const errorBox = h("div", { class: "login-error hidden" });
  const instance = modal(
    `Configure ${harness.label}`,
    h("form", {
      class: "form",
      onsubmit: async (event: Event) => {
        event.preventDefault();
        errorBox.classList.add("hidden");
        try {
          await api(`/api/harnesses/${harness.kind}`, {
            method: "PUT",
            body: {
              executable: executable.value.trim(),
              provider: provider.value.trim() || null,
              model: model.value.trim() || null,
              permission_mode: permission.value,
              allowed_tools: tools.value.split(",").map((tool) => tool.trim()).filter(Boolean),
              extra_args: extraArgs.value.split(",").map((arg) => arg.trim()).filter(Boolean),
            },
          });
          instance.close();
          toast("Harness configuration saved.", "success");
          refresh();
        } catch (error) {
          errorBox.textContent = error instanceof Error ? error.message : "Unable to save harness configuration";
          errorBox.classList.remove("hidden");
        }
      },
    },
    errorBox,
    h("div", { class: "form-grid" },
      harness.kind === "pi" ? field("Provider", provider) : null,
      field("Model", model, harness.kind === "pi" ? "Model ID from your provider." : "Leave empty to use the runtime default."),
    ),
    disclosure("Advanced runtime settings", h("div", { class: "form-grid" },
      field("Executable", executable), field("Permission mode", permission),
      field("Allowed tools", tools), field("Extra arguments", extraArgs),
    )),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Save configuration"),
    ),
    ),
    null,
  );
}
