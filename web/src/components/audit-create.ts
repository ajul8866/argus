import { api } from "../api.ts";
import { button, disclosure, field, h, input, modal, select, toast } from "../ui.ts";
import { createAuditWithSnapshot, createProjectWithSnapshot } from "./audit-setup.ts";
import { chooseRepositoryFolder } from "./repository-folder-picker.ts";

type ProjectRow = {
  id: string;
  name: string;
  source_path: string;
  repository_count?: number;
};

type RepositoryRow = { id: string; commit_sha: string | null; branch: string | null; file_count: number; imported_at: string };

export async function openAuditCreate(defaultProjectId?: string): Promise<string | null> {
  let projects: ProjectRow[];
  let settings: Record<string, unknown>;
  try {
    const [registry, policy] = await Promise.all([
      api<{ projects: ProjectRow[] }>("/api/projects"),
      api<{ settings: Record<string, unknown> }>("/api/settings"),
    ]);
    projects = registry.projects;
    settings = policy.settings;
  } catch (error) {
    toast(error instanceof Error ? error.message : "Unable to load audit setup", "error");
    return null;
  }
  if (projects.length === 0) {
    await openProjectCreate();
    return null;
  }
  const writablePolicy = settings["security.allow_writable_workspace"] === true;
  const projectSelect = select("project_id", projects.map((project) => ({ value: project.id, label: project.name })), defaultProjectId ?? projects[0]!.id);
  const repositorySelect = select("repository_id", []);
  const repositoryHint = h("p", { class: "modal-copy", role: "status" });
  const numeric = (key: string, fallback: number, min: number, max: number) => input(key, {
    type: "number", value: String(Math.min(max, Math.max(min, Number(settings[`audit.${key}`] ?? fallback)))), min, max, required: true,
  });
  const maxAreas = numeric("max_areas", 4, 1, 8);
  const maxCandidates = numeric("max_candidates_per_area", 4, 1, 8);
  const maxConfirmations = numeric("max_confirmations", 12, 0, 30);
  const maxConcurrent = numeric("max_concurrent_agents", 4, 1, 12);
  const defaults = new Map([
    ["max_areas", maxAreas.value], ["max_candidates_per_area", maxCandidates.value],
    ["max_confirmations", maxConfirmations.value], ["max_concurrent_agents", maxConcurrent.value],
  ]);
  const maxCost = input("max_cost_usd", { type: "number", min: 0, step: 0.5, placeholder: "No additional limit" });
  const startNow = h("input", { type: "checkbox", name: "start_now", checked: true });
  const writableWorkspace = h("input", { type: "checkbox", name: "writable_workspace" });
  const errorBox = h("div", { class: "login-error hidden", role: "alert", tabindex: "-1" });
  const submitButton = h("button", { class: "btn btn-primary", type: "submit", disabled: true }, "Start audit");
  let loadingRepositories = false;
  let requestId = 0;
  let closed = false;

  async function loadRepositories(): Promise<void> {
    const request = ++requestId;
    loadingRepositories = true;
    submitButton.disabled = true;
    repositorySelect.replaceChildren();
    repositoryHint.textContent = "Loading project files…";
    errorBox.classList.add("hidden");
    try {
      const { repositories } = await api<{ repositories: RepositoryRow[] }>(`/api/projects/${projectSelect.value}`);
      if (closed || request !== requestId) return;
      repositorySelect.replaceChildren(...repositories.map((repository, index) => h("option", { value: repository.id },
        `${index === 0 ? "Latest: " : ""}${repository.file_count} files, ${new Date(repository.imported_at).toLocaleDateString()}${repository.commit_sha ? `, ${repository.commit_sha.slice(0, 8)}` : ""}`,
      )));
      repositoryHint.textContent = repositories.length
        ? "Uses the latest imported files. Results and reports are generated automatically."
        : "Project files will be imported automatically before the audit starts.";
      submitButton.disabled = false;
    } catch (error) {
      if (closed || request !== requestId) return;
      errorBox.textContent = error instanceof Error ? error.message : "Unable to load project files";
      errorBox.classList.remove("hidden");
      repositoryHint.textContent = "Choose the project again to retry.";
    } finally {
      if (request === requestId) loadingRepositories = false;
    }
  }
  projectSelect.addEventListener("change", () => void loadRepositories());
  startNow.addEventListener("change", () => { submitButton.textContent = startNow.checked ? "Start audit" : "Save audit for later"; });
  const content = h("form", {
    class: "form",
    onsubmit: async (event: Event) => {
      event.preventDefault();
      if (loadingRepositories || submitButton.disabled) return;
      errorBox.classList.add("hidden");
      submitButton.disabled = true;
      submitButton.textContent = "Preparing audit…";
      const overrides: Record<string, unknown> = {};
      for (const control of [maxAreas, maxCandidates, maxConfirmations, maxConcurrent]) {
        if (control.value !== defaults.get(control.name)) overrides[control.name] = Number(control.value);
      }
      if (maxCost.value.trim()) overrides.max_cost_usd = Number(maxCost.value);
      if (writablePolicy && writableWorkspace.checked) overrides.writable_workspace = true;
      try {
        const result = await createAuditWithSnapshot({
          projectId: projectSelect.value, repositoryId: repositorySelect.value || undefined,
          overrides, startNow: startNow.checked,
        });
        instance.close();
        toast(result.startError ? `Audit saved. ${result.startError}` : startNow.checked ? "Audit started." : "Audit saved for later.", result.startError ? "error" : "success");
        location.hash = `#/audits/${result.id}`;
        return result.id;
      } catch (error) {
        errorBox.textContent = error instanceof Error ? error.message : "Unable to create audit";
        errorBox.classList.remove("hidden");
        errorBox.focus();
      } finally {
        submitButton.disabled = false;
        submitButton.textContent = startNow.checked ? "Start audit" : "Save audit for later";
      }
    },
  }, errorBox,
  projects.length > 1 ? field("Project", projectSelect) : h("p", { class: "strong" }, projects[0]!.name),
  repositoryHint,
  disclosure("Advanced audit settings",
    h("div", { class: "form-grid" },
      field("Saved source snapshot", repositorySelect, "The latest import is selected automatically."),
      field("Cost limit (USD)", maxCost),
      field("Assessment areas", maxAreas), field("Candidates per area", maxCandidates),
      field("Confirmation limit", maxConfirmations), field("Concurrent agents", maxConcurrent),
      h("label", { class: "checkbox full" }, startNow, "Start immediately"),
      writablePolicy ? h("label", { class: "checkbox full" }, writableWorkspace, "Request a writable workspace (requires task approval)") : null,
    ),
  ),
  h("div", { class: "form-actions" }, button("Cancel", () => instance.close(), "secondary"), submitButton));
  const instance = modal("New audit", content, null, { onClose: () => { closed = true; } });
  void loadRepositories();
  return null;
}

export async function openProjectCreate(): Promise<void> {
  const name = input("name", { placeholder: "Payments API", required: true });
  const sourcePath = input("source_path", { placeholder: "Choose a folder on this host", required: true });
  sourcePath.id = "project-source-path";
  sourcePath.readOnly = true;
  const browse = button("Browse folders", async () => {
    const selected = await chooseRepositoryFolder(sourcePath.value || undefined);
    if (!selected) return;
    sourcePath.value = selected;
    if (!name.value.trim()) name.value = selected.split(/[\\/]/).filter(Boolean).at(-1) ?? "My project";
  }, "secondary");
  const description = input("description", { placeholder: "What this project does" });
  const include = input("scope_include", { value: "**/*" });
  const exclude = h("textarea", {
    class: "input textarea",
    name: "scope_exclude",
  }, ".git/**,node_modules/**,vendor/**,dist/**,build/**,**/*.min.js,**/*.map");
  const maxAgents = input("max_concurrent_agents", { type: "number", value: "3", min: 1, max: 12, required: true });
  const errorBox = h("div", { class: "login-error hidden", role: "alert", tabindex: "-1" });

  const parseGlobs = (value: string): string[] =>
    value
      .split(/[\n,]/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0 && !entry.startsWith("#"));

  const content = h(
    "form",
    {
      class: "form",
      onsubmit: async (event: Event) => {
        event.preventDefault();
        errorBox.classList.add("hidden");
        if (!sourcePath.value) {
          errorBox.textContent = "Choose a repository folder.";
          errorBox.classList.remove("hidden");
          browse.focus();
          return;
        }
        const submitButton = (event.currentTarget as HTMLFormElement).querySelector<HTMLButtonElement>('button[type="submit"]');
        if (submitButton) submitButton.disabled = true;
        try {
          const result = await createProjectWithSnapshot({
            name: name.value,
            source_path: sourcePath.value,
            description: description.value,
            scope_include: parseGlobs(include.value),
            scope_exclude: parseGlobs((exclude as HTMLTextAreaElement).value),
            max_concurrent_agents: Number(maxAgents.value),
          });
          instance.close();
          toast(result.importError ? `Project added. Import failed: ${result.importError}` : "Project added and files imported. Ready to audit.", result.importError ? "error" : "success");
          location.hash = `#/projects/${result.id}`;
        } catch (error) {
          errorBox.textContent = error instanceof Error ? error.message : "Unable to create project";
          errorBox.classList.remove("hidden");
          errorBox.focus();
        } finally {
          if (submitButton) submitButton.disabled = false;
        }
      },
    },
    errorBox,
    h("div", { class: "stack" },
      field("Project name", name),
      h("div", { class: "field" },
        h("label", { class: "field-label", for: sourcePath.id }, "Repository folder"),
        h("div", { class: "folder-address" }, sourcePath, browse),
      ),
    ),
    h("p", { class: "modal-copy" }, "All source files are included by default. Dependencies and build outputs are excluded."),
    disclosure("Advanced settings (optional)",
      h("div", { class: "stack" },
        field("Description", description, "Optional"),
        field("Concurrent agents", maxAgents, "Up to 3 at once by default"),
        field("Files to include", include, "Leave **/* to include all files. To limit the audit, use patterns such as src/**,api/**."),
        field("Files to exclude", exclude, "Files matching these patterns are skipped. Separate patterns with commas or new lines."),
      ),
    ),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Create project"),
    ),
  );
  const instance = modal("New project", content, null);
}

export async function importRepository(projectId: string, ref?: string): Promise<void> {
  try {
    const result = await api<{ repository: { id: string; commit_sha: string | null; file_count: number } }>(
      `/api/projects/${projectId}/import`,
      { method: "POST", body: ref ? { ref } : {} },
    );
    toast(
      `Repository imported: ${result.repository.file_count} files${result.repository.commit_sha ? ` at ${result.repository.commit_sha.slice(0, 10)}` : ""}.`,
      "success",
    );
    location.hash = `#/projects/${projectId}`;
  } catch (error) {
    toast(error instanceof Error ? error.message : "Import failed", "error");
  }
}
