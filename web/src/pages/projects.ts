import { api, session } from "../api.ts";
import { importRepository, openAuditCreate, openProjectCreate } from "../components/audit-create.ts";
import {
  button,
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
  statusBadge,
  timeAgo,
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
    const canManage = session.user?.role === "admin" || session.user?.role === "auditor";
    const content = projects.length
      ? h(
          "div",
          { class: "table-wrap" },
          h(
            "table",
            {},
            h("thead", {}, h("tr", {},
              h("th", {}, "Project"),
              h("th", { class: "col-optional" }, "Snapshots"),
              h("th", { class: "col-optional" }, "Audits"),
              h("th", { class: "col-optional" }, "Last audit"),
              h("th", {}, ""),
            )),
            h("tbody", {}, ...projects.map((project) =>
              h("tr", {},
                h("td", {},
                  h("a", { class: "table-title", href: `#/projects/${project.id}` }, project.name),
                  h("div", { class: "table-sub mono" }, project.source_path),
                  h("div", { class: "phone-only tiny muted" }, `${project.repository_count ?? 0} snapshots, ${project.audit_count ?? 0} audits`),
                ),
                h("td", { class: "col-optional" }, String(project.repository_count ?? 0)),
                h("td", { class: "col-optional" }, String(project.audit_count ?? 0)),
                h("td", { class: "small muted col-optional" }, project.last_audit_at ? timeAgo(project.last_audit_at) : "—"),
                h("td", {},
                  h("div", { class: "table-actions" },
                    h("a", { class: "btn btn-sm btn-secondary", href: `#/projects/${project.id}` }, "Open"),
                    canManage ? button("Import", async () => {
                      await importRepository(project.id);
                    }, "ghost", { class: "btn-sm" }) : null,
                  ),
                ),
              ),
            )),
          ),
        )
      : emptyState(
          "No projects yet",
          "Choose a repository folder. Argus imports its files automatically.",
          canManage ? button("Create project", () => void openProjectCreate(), "primary") : null,
        );

    root.replaceChildren(
      pageHeader("Projects", "Your repositories, snapshots, and audit history.", canManage ? button("New project", () => void openProjectCreate(), "primary") : null),
      h("div", { class: "stack" },
        section("Project registry", content, h("span", { class: "tiny muted" }, `${projects.length} project${projects.length === 1 ? "" : "s"}`)),
        disclosure("About source snapshots", h("div", { class: "grid grid-2" },
          section("Source control", h("div", { class: "narrative" },
            h("p", {}, "Argus imports a snapshot of the repository worktree or a specific git ref. Agents only receive a read-only copy of files inside the configured include scope."),
            h("div", { class: "callout" },
              h("div", { class: "strong small" }, "Scope is enforced by the platform"),
              h("p", { class: "tiny muted", style: { margin: "4px 0 0" } }, "Files outside the scope are not copied into agent workspaces and cannot be read through the explorer or evidence API."),
            ),
          )),
          section("Recommended workflow", h("div", { class: "timeline" },
            ...[
              ["Add a project", "Enter a name and the repository folder."],
              ["Files are imported", "Argus saves a source snapshot automatically."],
              ["Connect an AI runtime", "Use AI setup once to choose Pi or Claude Code."],
              ["Run the six phases", "Mapping, discovery, confirmation, findings, retest, reports."],
              ["Review and export", "Inspect provenance, evidence, and limitations."],
            ].map(([title, detail], index) =>
              h("div", { class: "timeline-item on" },
                h("span", { class: "timeline-dot" }),
                h("div", { class: "small strong" }, `${index + 1}. ${title}`),
                h("div", { class: "tiny muted" }, detail),
              ),
            ),
          )),
        )),
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
    const canManage = session.user?.role === "admin" || session.user?.role === "auditor";

    const repositories = detail.repositories.length
      ? h(
          "div",
          { class: "table-wrap" },
          h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Snapshot"), h("th", {}, "Commit"), h("th", {}, "Files"), h("th", {}, "Imported"), h("th", {}, ""))),
            h("tbody", {}, ...detail.repositories.map((repository) =>
              h("tr", {},
                h("td", {}, h("span", { class: "mono small" }, repository.id.slice(0, 8)), h("div", { class: "table-sub" }, repository.path)),
                h("td", { class: "mono small" }, repository.commit_sha?.slice(0, 12) ?? "no git"),
                h("td", {}, String(repository.file_count)),
                h("td", { class: "small muted" }, formatDate(repository.imported_at)),
                h("td", {},
                  h("div", { class: "table-actions" },
                    h("a", { class: "btn btn-sm btn-secondary", href: `#/explorer?repo=${repository.id}` }, "Explore"),
                  ),
                ),
              ),
            )),
          ),
        )
      : emptyState("No files imported yet", "Start an audit to import the project files automatically.");

    const audits = detail.audits.length
      ? h(
          "div",
          { class: "table-wrap" },
          h("table", {},
            h("thead", {}, h("tr", {}, h("th", {}, "Audit"), h("th", {}, "Status"), h("th", {}, "Phase"), h("th", {}, "Created"), h("th", {}, ""))),
            h("tbody", {}, ...detail.audits.map((audit) =>
              h("tr", {},
                h("td", { class: "mono small" }, audit.id.slice(0, 8)),
                h("td", {}, statusBadge(audit.status)),
                h("td", { class: "small" }, `Phase ${audit.current_phase}`),
                h("td", { class: "small muted" }, formatDate(audit.created_at)),
                h("td", {}, h("div", { class: "table-actions" }, h("a", { class: "btn btn-sm btn-secondary", href: `#/audits/${audit.id}` }, "Open"))),
              ),
            )),
          ),
        )
      : emptyState("No audits", "Create the first six-phase audit for the newest snapshot.", canManage ? button("New audit", () => void openAuditCreate(project.id), "primary") : null);

    root.replaceChildren(
      pageHeader(
        project.name,
        project.description || "Repository snapshots and audit history.",
        h("div", { class: "row" },
          canManage ? button("Refresh files", () => void importRepository(project.id), "secondary") : null,
          canManage ? button("New audit", () => void openAuditCreate(project.id), "primary") : null,
        ),
      ),
      h("div", { class: "grid grid-main" },
        h("div", { class: "stack" },
          section("Repository snapshots", repositories),
          section("Audit history", audits),
        ),
        h("div", { class: "stack" },
          section("Project details", h("dl", { class: "kv" },
            project.authorized_by ? h("dt", {}, "Authorized by") : null,
            project.authorized_by ? h("dd", {}, project.authorized_by) : null,
            project.authorization_ref ? h("dt", {}, "Reference") : null,
            project.authorization_ref ? h("dd", {}, project.authorization_ref) : null,
            h("dt", {}, "Source path"), h("dd", { class: "mono" }, project.source_path),
            h("dt", {}, "Status"), h("dd", {}, statusBadge(project.status)),
            h("dt", {}, "Created"), h("dd", {}, formatDate(project.created_at)),
          )),
          disclosure("Source scope and versions",
            canManage ? button("Import a specific git ref", () => void openImport(project.id), "secondary") : null,
            section("Scope", h("div", { class: "stack" },
            h("div", {},
              h("div", { class: "tiny muted" }, "Include"),
              h("div", { class: "chip-row" }, ...project.scope_include.map((glob) => h("span", { class: "chip on mono" }, glob))),
            ),
            h("div", {},
              h("div", { class: "tiny muted" }, "Exclude"),
              h("div", { class: "chip-row" }, ...project.scope_exclude.map((glob) => h("span", { class: "chip mono" }, glob))),
            ),
          ))),
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
