import { api } from "../api.ts";
import { h, modal, toast } from "../ui.ts";

export async function previewReport(reportId: string, format: string, title: string): Promise<void> {
  try {
    const response = await fetch(`/api/reports/${reportId}/download`, { credentials: "same-origin" });
    if (!response.ok) throw new Error(`Preview failed with status ${response.status}`);
    const body = await response.text();
    const content =
      format === "json"
        ? body
        : format === "html"
          ? body.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "")
          : body;
    modal(
      `${title} / ${format.toUpperCase()} preview`,
      h("pre", {
        class: "json-block",
        style: { maxHeight: "65vh", whiteSpace: "pre-wrap", fontFamily: "var(--mono)", fontSize: "11px" },
      }, content.slice(0, 200_000)),
      null,
      { wide: true },
    );
  } catch (error) {
    toast(error instanceof Error ? error.message : "Unable to preview report", "error");
  }
}
