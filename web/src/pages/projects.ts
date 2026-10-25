import { api } from "../api.ts";
import { importRepository, openAuditCreate, openProjectCreate } from "../components/audit-create.ts";
import {
  button,
  emptyState,
  errorState,
  field,
  formatDate,
  h,
  input,
  loading,
  modal,
  pageHeader,
  section,
  statusBadge,
  timeAgo,
  timelineEntry,
  toast,
} from "../ui.ts";

type Project = {
  id: string;
  name: string;
  description: string;
  source_path: string;
  scope_include: string[];
  scope_exclude: string[];
  authorized_by: string;
  authorization_ref: string;
  status: string;
  created_at: string;
  updated_at: string;
  repository_count?: number;
  audit_count?: number;
  last_audit_at?: string | null;
};

type Repository = {
  id: string;
  path: string;
  commit_sha: string | null;
  branch: string | null;
  file_count: number;
  total_bytes: number;
  imported_at: string;
};

type Audit = {
  id: string;
  status: string;
  current_phase: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export async function renderProjects(root: HTMLElement): Promise<void> {
  root.replaceChildren(loading("Loading projects"));
  try {
    const { projects } = await api<{ projects: Project[] }>("/api/projects");
    const content = projects.length
      ? h(
          "div",
          { class: "table-wrap" },
          h(
            "table",
            {},
            h("thead", {}, h("tr", {},
              h("th", {}, "Project"),
              h("th", {}, "Authorization"),
              h("th", {}, "Snapshots"),
              h("th", {}, "Audits"),
              h("th", {}, "Last audit"),
              h("th", {}, ""),
            )),
            h("tbody", {}, ...projects.map((project) =>
              h("tr", {},
                h("td", { "data-label": "Project" },
                  h("a", { class: "table-title", href: `#/projects/${project.id}` }, project.name),
                  h("div", { class: "table-sub mono" }, project.source_path),
                ),
                h("td", { "data-label": "Authorization" },
                  h("div", { class: "small" }, project.authorized_by),
                  h("div", { class: "table-sub" }, project.authorization_ref),
                ),
                h("td", { "data-label": "Snapshots" }, String(project.repository_count ?? 0)),
                h("td", { "data-label": "Audits" }, String(project.audit_count ?? 0)),
                h("td", { "data-label": "Last audit", class: "small muted" }, project.last_audit_at ? timeAgo(project.last_audit_at) : "—"),
                h("td", { "data-label": "Actions" },
                  h("div", { class: "table-actions" },
                    h("a", { class: "btn btn-sm btn-secondary", href: `#/projects/${project.id}` }, "Open"),
                    button("Import", async () => {
                      await importRepository(project.id);
                    }, "ghost", { class: "btn-sm" }),
                  ),
                ),
              ),
            )),
          ),
        )
      : emptyState(
          "No authorized projects",
          "Register an authorized source repository path, import a snapshot, and then run the six-phase audit.",
          button("Create project", () => void openProjectCreate(), "primary"),
        );

    root.replaceChildren(
      pageHeader("Projects", "Authorized repositories, scope boundaries, snapshots, and audit history.", button("New project", () => void openProjectCreate(), "primary")),
      h("div", { class: "stack" },
        section("Project registry", content, h("span", { class: "tiny muted" }, `${projects.length} project${projects.length === 1 ? "" : "s"}`)),
        h("div", { class: "grid grid-2" },
          section("Source control", h("div", { class: "narrative" },
            h("p", {}, "Argus imports a snapshot of the repository worktree or a specific git ref. Agents only receive a read-only copy of files inside the configured include scope."),
            h("p", { class: "muted small" }, "Authorization evidence is required and is carried into every generated report."),
            h("div", { class: "callout" },
              h("div", { class: "strong small" }, "Scope is enforced by the platform"),
              h("p", { class: "tiny muted", style: { margin: "var(--space-2xs) 0 0" } }, "Files outside the scope are not copied into agent workspaces and cannot be read through the explorer or evidence API."),
            ),
          )),
          section("Recommended workflow", h("div", { class: "timeline" },
            ...[
              ["Register the engagement", "Record the authorization owner and reference."],
              ["Import a snapshot", "Pin a commit or worktree state; the inventory is hashed."],
              ["Assign harnesses", "Pi and Claude Code can serve different roles."],
              ["Run the six phases", "Mapping, discovery, confirmation, findings, retest, reports."],
              ["Review and export", "Inspect provenance, evidence, and limitations."],
            ].map(([title, detail], index) =>
              timelineEntry("on",
                h("div", { class: "small strong" }, `${index + 1}. ${title}`),
                h("div", { class: "tiny muted" }, detail),
              ),
            ),
          )),
        ),
      ),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load projects", () => void renderProjects(root)));
  }
}

export async function renderProjectDetail(root: HTMLElement, projectId: string): Promise<void> {
  root.replaceChildren(loading("Loading project"));
  try {
    const detail = await api<{ project: Project; repositories: Repository[]; audits: Audit[] }>(`/api/projects/${projectId}`);
    const project = detail.project;

    const repositories = detail.repositories.length
      ? h(
          "div",
          { class: "table-wrap" },
          h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Snapshot"), h("th", {}, "Commit"), h("th", {}, "Files"), h("th", {}, "Imported"), h("th", {}, ""))),
            h("tbody", {}, ...detail.repositories.map((repository) =>
              h("tr", {},
                h("td", { "data-label": "Snapshot" }, h("span", { class: "mono small" }, repository.id.slice(0, 8)), h("div", { class: "table-sub" }, repository.path)),
                h("td", { "data-label": "Commit", class: "mono small" }, repository.commit_sha?.slice(0, 12) ?? "no git"),
                h("td", { "data-label": "Files" }, String(repository.file_count)),
                h("td", { "data-label": "Imported", class: "small muted" }, formatDate(repository.imported_at)),
                h("td", { "data-label": "Actions" },
                  h("div", { class: "table-actions" },
                    h("a", { class: "btn btn-sm btn-secondary", href: `#/explorer?repo=${repository.id}` }, "Explore"),
                  ),
                ),
              ),
            )),
          ),
        )
      : emptyState("No repository snapshot", "Import a snapshot to build the inventory and start an audit.", button("Import snapshot", () => void openImport(project.id), "primary"));

    const audits = detail.audits.length
      ? h(
          "div",
          { class: "table-wrap" },
          h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Audit"), h("th", {}, "Status"), h("th", {}, "Phase"), h("th", {}, "Created"), h("th", {}, ""))),
            h("tbody", {}, ...detail.audits.map((audit) =>
              h("tr", {},
                h("td", { "data-label": "Audit", class: "mono small" }, audit.id.slice(0, 8)),
                h("td", { "data-label": "Status" }, statusBadge(audit.status)),
                h("td", { "data-label": "Phase", class: "small" }, `Phase ${audit.current_phase}`),
                h("td", { "data-label": "Created", class: "small muted" }, formatDate(audit.created_at)),
                h("td", { "data-label": "Actions" }, h("div", { class: "table-actions" }, h("a", { class: "btn btn-sm btn-secondary", href: `#/audits/${audit.id}` }, "Open"))),
              ),
            )),
          ),
        )
      : emptyState("No audits", "Create the first six-phase audit for the newest snapshot.", button("New audit", () => void openAuditCreate(project.id), "primary"));

    root.replaceChildren(
      pageHeader(
        project.name,
        project.description || "Authorized project and assessment history.",
        h("div", { class: "row" },
          button("Import snapshot", () => void openImport(project.id), "secondary"),
          button("New audit", () => void openAuditCreate(project.id), "primary"),
        ),
      ),
      h("div", { class: "grid grid-main" },
        h("div", { class: "stack" },
          section("Repository snapshots", repositories),
          section("Audit history", audits),
        ),
        h("div", { class: "stack" },
          section("Authorization", h("dl", { class: "kv" },
            h("dt", {}, "Authorized by"), h("dd", {}, project.authorized_by),
            h("dt", {}, "Reference"), h("dd", {}, project.authorization_ref),
            h("dt", {}, "Source path"), h("dd", { class: "mono" }, project.source_path),
            h("dt", {}, "Status"), h("dd", {}, statusBadge(project.status)),
            h("dt", {}, "Created"), h("dd", {}, formatDate(project.created_at)),
          )),
          section("Scope", h("div", { class: "stack" },
            h("div", {},
              h("div", { class: "tiny muted" }, "Include"),
              h("div", { class: "chip-row" }, ...project.scope_include.map((glob) => h("span", { class: "chip on mono" }, glob))),
            ),
            h("div", {},
              h("div", { class: "tiny muted" }, "Exclude"),
              h("div", { class: "chip-row" }, ...project.scope_exclude.map((glob) => h("span", { class: "chip mono" }, glob))),
            ),
          )),
        ),
      ),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load project", () => void renderProjectDetail(root, projectId)));
  }
}

function openImport(projectId: string): void {
  const ref = input("ref", { placeholder: "optional git ref, e.g. main or v1.4.2" });
  const instance = modal(
    "Import repository snapshot",
    h("form", {
      class: "form",
      onsubmit: async (event: Event) => {
        event.preventDefault();
        instance.close();
        toast("Importing snapshot…", "info");
        await importRepository(projectId, ref.value.trim() || undefined);
      },
    },
    h("p", { class: "modal-copy" }, "Argus inventories only in-scope files. An optional git ref is archived into an immutable snapshot under the Argus data directory."),
    field("Git ref", ref, "Leave empty to import the current worktree state"),
    h("div", { class: "form-actions" },
      button("Cancel", () => instance.close(), "secondary"),
      h("button", { class: "btn btn-primary", type: "submit" }, "Import"),
    ),
    ),
    null,
  );
}
