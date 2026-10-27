import { button, field, h, input, modal, toast } from "../ui.ts";
import { createWorkerToken, revokeWorkerToken, WORKER_SCOPES, type WorkerTokenRow, listWorkerTokens } from "./worker-tokens.ts";

/**
 * Issues an audit-scoped token for the worker container. The raw value is
 * shown once; it is never retrievable again, so the dialog says so plainly.
 */
export function openWorkerToken(auditId: string): void {
  const label = input("label", { value: "worker container", required: true });
  const output = h("div", { class: "stack" });
  const list = h("div", { class: "stack" });
  const errorBox = h("div", { class: "login-error hidden", role: "alert", tabindex: "-1" });
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Issue token");

  async function refresh(): Promise<void> {
    try {
      const tokens = await listWorkerTokens();
      const scoped = tokens.filter((token: WorkerTokenRow) => token.audit_id === auditId);
      list.replaceChildren(
        scoped.length === 0
          ? h("p", { class: "small muted" }, "No worker token has been issued for this audit.")
          : h("table", { class: "table" },
              h("thead", {}, h("tr", {}, h("th", {}, "Label"), h("th", {}, "Scopes"), h("th", {}, "Created"), h("th", {}, ""))),
              h("tbody", {}, ...scoped.map((token) =>
                h("tr", {},
                  h("td", { class: "strong" }, token.label),
                  h("td", { class: "mono tiny" }, token.scopes.join(", ")),
                  h("td", { class: "small muted" }, token.created_at),
                  h("td", {}, button("Revoke", async () => {
                    await revokeWorkerToken(token.id);
                    toast("Worker token revoked.", "success");
                    await refresh();
                  }, "ghost", { class: "btn-sm" })),
                ),
              )),
            ),
      );
    } catch (error) {
      errorBox.textContent = error instanceof Error ? error.message : "Unable to list tokens";
      errorBox.classList.remove("hidden");
    }
  }

  const content = h("form", {
    class: "form",
    onsubmit: async (event: Event) => {
      event.preventDefault();
      errorBox.classList.add("hidden");
      submit.disabled = true;
      try {
        const token = await createWorkerToken(auditId, label.value.trim() || "worker container");
        output.replaceChildren(
          h("p", { class: "modal-copy" },
            "Copy this token now. Argus stores only its hash, so it cannot be shown again."),
          h("code", { class: "code", style: { userSelect: "all", wordBreak: "break-all" } }, token.raw),
        );
        await refresh();
      } catch (error) {
        errorBox.textContent = error instanceof Error ? error.message : "Unable to issue a token";
        errorBox.classList.remove("hidden");
        errorBox.focus();
      } finally {
        submit.disabled = false;
      }
    },
  },
  errorBox,
  h("p", { class: "modal-copy" },
    `A worker receives only ${WORKER_SCOPES.join(" and ")}. It can read the audit and propose candidates, but a separate run must confirm them.`),
  field("Label", label),
  h("div", { class: "form-actions" }, submit),
  output,
  h("h4", {}, "Issued for this audit"),
  list);

  modal("Worker token", content, null, { onClose: () => undefined });
  void refresh();
}
