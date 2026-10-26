import { api } from "../api.ts";
import { button, field, h, input, modal, select, toast } from "../ui.ts";
import { chooseRepositoryFolder } from "./repository-folder-picker.ts";

type ProjectRow = {
  id: string;
  name: string;
  source_path: string;
  repository_count?: number;
};

type RepositoryRow = { id: string; commit_sha: string | null; branch: string | null; file_count: number; imported_at: string };

export async function openAuditCreate(defaultProjectId?: string): Promise<string | null> {
  let projects: ProjectRow[] = [];
  try {
    const result = await api<{ projects: ProjectRow[] }>("/api/projects");
    projects = result.projects;
  } catch (error) {
    toast(error instanceof Error ? error.message : "Unable to load projects", "error");
    return null;
  }
  if (projects.length === 0) {
    toast("Create a project and import an authorized repository first.", "error");
    location.hash = "#/projects";
    return null;
  }
  let writablePolicy = false;
  try {
    const policy = await api<{ settings: Record<string, unknown> }>("/api/settings");
    writablePolicy = policy.settings["security.allow_writable_workspace"] === true;
  } catch {
    // Best-effort; the server rejects a writable request when the policy is off.
  }
  let repositories: RepositoryRow[] = [];
  const projectSelect = select(
    "project_id",
    projects.map((project) => ({ value: project.id, label: project.name })),
    defaultProjectId ?? projects[0]!.id,
  );
  const repositorySelect = select("repository_id", []);
  const repositoryHint = h("span", { class: "field-hint", id: "repository-hint" }, "Loading repositories…");
  repositorySelect.setAttribute("aria-describedby", "repository-hint");
  const maxAreas = input("max_areas", { type: "number", value: "3", min: 1, max: 8, required: true });
  const maxCandidates = input("max_candidates_per_area", { type: "number", value: "3", min: 1, max: 8, required: true });
  const maxConfirmations = input("max_confirmations", { type: "number", value: "6", min: 0, max: 30, required: true });
  const maxConcurrent = input("max_concurrent_agents", { type: "number", value: "3", min: 1, max: 12, required: true });
  const maxCost = input("max_cost_usd", { type: "number", min: 0, step: 0.5, placeholder: "optional" });
  const distinctHarness = h("input", { type: "checkbox", name: "distinct_harness", checked: true }) as HTMLInputElement;
  const startNow = h("input", { type: "checkbox", name: "start_now", checked: true }) as HTMLInputElement;
  const writableWorkspace = h("input", {
    type: "checkbox",
    name: "writable_workspace",
    disabled: !writablePolicy,
  }) as HTMLInputElement;
  const errorBox = h("div", { class: "login-error hidden", role: "alert", tabindex: "-1" });

  async function loadRepositories(): Promise<void> {
    repositorySelect.replaceChildren();
    repositoryHint.textContent = "Loading repositories…";
    try {
      const detail = await api<{ repositories: RepositoryRow[] }>(`/api/projects/${projectSelect.value}`);
      repositories = detail.repositories;
      for (const repository of repositories) {
        repositorySelect.appendChild(
          h(
            "option",
            { value: repository.id },
            `${repository.commit_sha ? repository.commit_sha.slice(0, 10) : "no commit"}, ${repository.file_count} files, ${new Date(repository.imported_at).toLocaleDateString()}`,
          ),
        );
      }
      repositoryHint.textContent =
        repositories.length > 0
          ? "The newest import is selected by default. Signed-out repository state is never fetched by agents."
          : "No imported repository. Import one from the project page first.";
    } catch (error) {
      repositoryHint.textContent = error instanceof Error ? error.message : "Unable to load repositories";
    }
  }
  projectSelect.addEventListener("change", () => void loadRepositories());
  await loadRepositories();

  const content = h(
    "form",
    {
      class: "form",
      onsubmit: async (event: Event) => {
        event.preventDefault();
        errorBox.classList.add("hidden");
        if (repositories.length === 0) {
          errorBox.textContent = "Import a repository before creating an audit.";
          errorBox.classList.remove("hidden");
          errorBox.focus();
          return;
        }
        const submit = event.currentTarget as HTMLFormElement;
        const submitButton = submit.querySelector('button[type="submit"]') as HTMLButtonElement | null;
        if (submitButton) submitButton.disabled = true;
        try {
          const created = await api<{ audit: { id: string } }>("/api/audits", {
            method: "POST",
            body: {
              project_id: projectSelect.value,
              repository_id: repositorySelect.value,
              overrides: {
                max_areas: Number(maxAreas.value),
                max_candidates_per_area: Number(maxCandidates.value),
                max_confirmations: Number(maxConfirmations.value),
                max_concurrent_agents: Number(maxConcurrent.value),
                max_cost_usd: maxCost.value.trim() === "" ? null : Number(maxCost.value),
                require_distinct_harness_for_retest: distinctHarness.checked,
                writable_workspace: writablePolicy && writableWorkspace.checked,
              },
            },
          });
          if (startNow.checked) {
            await api(`/api/audits/${created.audit.id}/start`, { method: "POST" });
          }
          instance.close();
          toast(startNow.checked ? "Audit created and started." : "Audit created. Start it when ready.", "success");
          location.hash = `#/audits/${created.audit.id}`;
        } catch (error) {
          errorBox.textContent = error instanceof Error ? error.message : "Unable to create audit";
          errorBox.classList.remove("hidden");
          errorBox.focus();
        } finally {
          if (submitButton) submitButton.disabled = false;
        }
      },
    },
    errorBox,
    h("div", { class: "form-grid" },
      field("Project", projectSelect),
      h("label", { class: "field" },
        h("span", { class: "field-label" }, "Repository snapshot"),
        repositorySelect,
        repositoryHint,
      ),
      field("Assessment areas", maxAreas, "1–8 coherent areas produced by the mapper"),
      field("Candidates per area", maxCandidates, "Cap per researcher session"),
      field("Confirmation cap", maxConfirmations, "Maximum candidates sent to independent confirmation"),
      field("Concurrent agents", maxConcurrent, "Effective limit is also bounded by the server setting"),
      field("Cost budget (USD)", maxCost, "Optional audit-wide ceiling; checked after each session"),
      h("label", { class: "checkbox full" }, distinctHarness, "Prefer a distinct harness for retest when configured"),
      h("label", { class: "checkbox full" }, startNow, "Start the six-phase workflow immediately"),
      h(
        "label",
        { class: "checkbox full" },
        writableWorkspace,
        writablePolicy
          ? "Request a writable workspace (every task still needs administrator approval)"
          : "Writable workspace is disabled by administrator policy",
      ),
    ),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Create audit"),
    ),
  );
  const instance = modal("New autonomous audit", content, null, { wide: false });
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
          const result = await api<{ project: { id: string } }>("/api/projects", {
            method: "POST",
            body: {
              name: name.value,
              source_path: sourcePath.value,
              description: description.value,
              scope_include: parseGlobs(include.value),
              scope_exclude: parseGlobs((exclude as HTMLTextAreaElement).value),
              max_concurrent_agents: Number(maxAgents.value),
            },
          });
          instance.close();
          toast("Project created. Import the repository snapshot next.", "success");
          location.hash = `#/projects/${result.project.id}`;
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
    h("details", { class: "form-advanced" },
      h("summary", { tabindex: "0" }, "Advanced settings (optional)"),
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
    location.hash = `#/explorer?repo=${result.repository.id}`;
  } catch (error) {
    toast(error instanceof Error ? error.message : "Import failed", "error");
  }
}
