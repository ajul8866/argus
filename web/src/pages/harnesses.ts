import { api, session } from "../api.ts";
import {
  badge,
  button,
  emptyState,
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
    const { harnesses } = await api<{ harnesses: Harness[] }>("/api/harnesses");
    const isAdmin = session.user?.role === "admin";
    const isAuditor = isAdmin || session.user?.role === "auditor";

    const cards = harnesses.map((harness) => {
      const capabilities = Object.entries(harness.capabilities).filter(([, value]) => typeof value === "boolean");
      return h("div", { class: "panel harness-card" },
        h("div", { class: "harness-head" },
          h("div", {},
            h("div", { class: "row", style: { gap: "8px" } },
              h("span", { class: "harness-name" }, harness.label),
              statusBadge(harness.status),
            ),
            h("div", { class: "harness-sub" }, `${harness.executable}${harness.version ? ` · v${harness.version}` : ""}`),
          ),
          h("div", { class: "row" },
            isAuditor ? button("Check", async () => {
              try {
                const result = await api<{ harness: Harness }>(`/api/harnesses/${harness.kind}/check`, { method: "POST", body: {} });
                toast(result.harness.auth.ready ? "Harness authentication verified." : result.harness.detail, result.harness.auth.ready ? "success" : "error");
                await renderHarnesses(root);
              } catch (error) {
                toast(error instanceof Error ? error.message : "Health check failed", "error");
              }
            }, "secondary", { class: "btn-sm" }) : null,
            isAdmin ? button("Test", async () => {
              try {
                const result = await api<TestResult>(`/api/harnesses/${harness.kind}/test`, { method: "POST", body: {} });
                showTestResult(harness, result);
                await renderHarnesses(root);
              } catch (error) {
                toast(error instanceof Error ? error.message : "Connection test failed", "error");
              }
            }, "primary", { class: "btn-sm" }) : null,
            isAdmin ? button("Configure", () => openHarnessConfig(harness, () => void renderHarnesses(root)), "ghost", { class: "btn-sm" }) : null,
          ),
        ),
        h("div", { class: `callout ${harness.status === "ready" ? "good" : harness.status === "missing" ? "bad" : "warn"}` },
          h("div", { class: "small" }, harness.detail),
          h("div", { class: "tiny muted", style: { marginTop: "3px" } }, harness.auth.detail),
        ),
        h("div", {},
          h("div", { class: "tiny muted", style: { marginBottom: "5px" } }, "CAPABILITIES"),
          h("div", { class: "cap-grid" }, ...capabilities.map(([capability, supported]) =>
            h("div", { class: `cap ${supported ? "on" : ""}` }, h("span", { class: "dot" }), capability.replaceAll("_", " ")),
          )),
        ),
        h("div", {},
          h("div", { class: "tiny muted", style: { marginBottom: "5px" } }, "CONFIGURATION"),
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
      );
    });

    root.replaceChildren(
      pageHeader(
        "Harnesses",
        "Pi and Claude Code are independent execution runtimes. Argus supervises their real processes, streams events, and preserves their native capabilities.",
        isAdmin ? h("a", { class: "btn btn-secondary", href: "#/agents" }, "Agent assignments") : null,
      ),
      h("div", { class: "grid grid-2" }, ...cards),
      h("div", { style: { height: "14px" } }),
      section("Integration notes", h("div", { class: "narrative" },
        h("p", {}, "Pi runs in RPC mode over strict JSONL. Argus correlates every command by request ID, treats prompt acceptance as acceptance only, and waits for agent_settled before declaring completion."),
        h("p", {}, "Claude Code runs through the non-interactive CLI with stream-json output and JSON-schema structured output. Permission bypass flags are rejected by the platform."),
        h("p", { class: "muted small" }, "A harness health check can consume provider credits. Test connections execute a real minimal agent run. Status is persisted and never silently substituted."),
      )),
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
    h("p", { class: "modal-copy" }, "Provider credentials are separate from harness configuration. Store API keys in Settings → Credentials; this form never accepts secret values."),
    h("div", { class: "form-grid" },
      field("Executable", executable),
      field("Provider", provider, "Pi provider name; ignored by Claude Code"),
      field("Model", model, "Model ID used by this harness"),
      field("Permission mode", permission, "Bypass modes are rejected"),
      field("Allowed tools", tools, "Harness-native names; role tools must stay inside this policy cap"),
      field("Extra arguments", extraArgs, "Comma-separated safe arguments"),
    ),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Save configuration"),
    ),
    ),
    null,
  );
}
