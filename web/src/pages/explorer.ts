import { api } from "../api.ts";
import { openAuditCreate } from "../components/audit-create.ts";
import {
  badge,
  button,
  emptyState,
  fill,
  errorState,
  field,
  formatDate,
  h,
  input,
  loading,
  pageHeader,
  section,
  select,
  statusBadge,
  toast,
} from "../ui.ts";

type RepositoryList = {
  repositories: Array<{
    id: string;
    project_id: string;
    project_name: string;
    commit_sha: string | null;
    branch: string | null;
    file_count: number;
    total_bytes: number;
    imported_at: string;
  }>;
};

type RepoFile = { path: string; size: number; lines: number; language: string };
type Endpoint = { method: string; path: string; file: string; line: number };
type AuthBoundary = { kind: string; detail: string; file: string; line: number };

type RepoDetail = {
  repository: {
    id: string;
    project_id: string;
    path: string;
    commit_sha: string | null;
    branch: string | null;
    file_count: number;
    total_bytes: number;
    imported_at: string;
    inventory_summary: string;
    inventory: {
      files: RepoFile[];
      languages: Record<string, number>;
      frameworks: string[];
      endpoints: Endpoint[];
      auth_boundaries: AuthBoundary[];
      dependency_graph: Array<{ from: string; to: string }>;
      entrypoints: string[];
      truncated: boolean;
    };
  };
  project: { id: string; name: string; source_path: string };
  map: {
    summary?: string;
    modules?: Array<{ name: string; path: string; purpose: string }>;
    areas?: Array<{ id: string; title: string; rationale: string; files: string[]; security_focus: string[] }>;
    critical_paths?: Array<{ name: string; description: string; files: string[] }>;
    coverage_notes?: string[];
    limitations?: string[];
  } | null;
};

type Coverage = { area_id: string; title: string; status: string; files: string[]; notes: string | null };

export async function renderExplorer(root: HTMLElement, params: URLSearchParams): Promise<void> {
  root.replaceChildren(loading("Loading repositories"));
  try {
    const { repositories } = await api<RepositoryList>("/api/repositories");
    if (repositories.length === 0) {
      root.replaceChildren(
        pageHeader("Codebase explorer", "Read-only repository inspection, architecture maps, and coverage.", null),
        emptyState("No repository snapshots", "Create a project and import an authorized repository first.", h("a", { class: "btn btn-primary", href: "#/projects" }, "Open projects")),
      );
      return;
    }
    let selected = params.get("repo") ?? repositories[0]!.id;
    if (!repositories.some((repository) => repository.id === selected)) selected = repositories[0]!.id;
    const repositoryDetail = await api<RepoDetail>(`/api/repositories/${selected}`);
    const repo = repositoryDetail.repository;
    let activeTab = params.get("tab") ?? "source";
    let currentPath = params.get("path") ?? "";
    let currentFile: { path: string; content: string; size: number; truncated: boolean; binary: boolean; lines: number } | null = null;
    let coverage: Coverage[] = [];
    let coverageLoaded = false;

    const repositorySelect = select(
      "repository",
      repositories.map((repository) => ({
        value: repository.id,
        label: `${repository.project_name}, ${repository.commit_sha?.slice(0, 8) ?? "worktree"}, ${repository.file_count} files`,
      })),
      selected,
    );
    repositorySelect.addEventListener("change", () => {
      location.hash = `#/explorer?repo=${repositorySelect.value}`;
    });

    if (currentPath) {
      try {
        currentFile = await api(`/api/repositories/${selected}/file?path=${encodeURIComponent(currentPath)}`);
      } catch (error) {
        toast(error instanceof Error ? error.message : "Unable to load file", "error");
      }
    }

    async function loadCoverage(): Promise<Coverage[]> {
      if (coverageLoaded) return coverage;
      coverageLoaded = true;
      try {
        const projectDetail = await api<{ audits: Array<{ id: string }> }>(`/api/projects/${repo.project_id}`);
        const latest = projectDetail.audits[0];
        if (latest) {
          const audit = await api<{ coverage: Coverage[] }>(`/api/audits/${latest.id}`);
          coverage = audit.coverage;
        }
      } catch {
        coverage = [];
      }
      return coverage;
    }

    const header = pageHeader(
      "Codebase explorer",
      "Inspect the exact scoped snapshot agents receive. Files outside the authorization scope are unreachable here.",
      h("div", { class: "row" },
        repositorySelect,
        h("a", { class: "btn btn-secondary", href: `#/projects/${repo.project_id}` }, "Project"),
        button("New audit", () => void openAuditCreate(repo.project_id), "primary"),
      ),
    );

    const tabs = h("div", { class: "tabs" },
      ...[["source", "Source"], ["architecture", "Architecture"], ["coverage", "Coverage"]].map(([key, label]) =>
        h("button", {
          class: `tab ${activeTab === key ? "active" : ""}`,
          onclick: () => {
            location.hash = `#/explorer?repo=${selected}&tab=${key}${currentPath ? `&path=${encodeURIComponent(currentPath)}` : ""}`;
          },
        }, label!),
      ),
    );

    let content: HTMLElement;
    if (activeTab === "architecture") {
      content = architectureTab(repositoryDetail);
    } else if (activeTab === "coverage") {
      content = h("div", { class: "stack" }, h("div", { class: "loading-state" }, h("span", { class: "spinner" }), "Loading coverage"));
      void loadCoverage().then((rows) => content.replaceChildren(coverageTab(rows)));
    } else {
      content = sourceTab(repo, currentPath, currentFile, (path) => {
        location.hash = `#/explorer?repo=${selected}&tab=source&path=${encodeURIComponent(path)}`;
      });
    }

    root.replaceChildren(header, h("div", { class: "panel" }, tabs, content));
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to load explorer", () => void renderExplorer(root, params)));
  }
}

function sourceTab(
  repo: RepoDetail["repository"],
  currentPath: string,
  file: { path: string; content: string; size: number; truncated: boolean; binary: boolean; lines: number } | null,
  onSelect: (path: string) => void,
): HTMLElement {
  const files = repo.inventory.files;
  const search = input("search", { placeholder: "Filter files…" });
  const treeHost = h("div", { class: "stack", style: { maxHeight: "620px", overflowY: "auto" } });
  const renderTree = (filter: string) => {
    if (filter.trim()) {
      const matches = files.filter((entry) => entry.path.toLowerCase().includes(filter.toLowerCase())).slice(0, 120);
      treeHost.replaceChildren(
        ...matches.map((entry) =>
          h("button", {
            class: `tree-file ${entry.path === currentPath ? "active" : ""}`,
            onclick: () => onSelect(entry.path),
          },
            h("span", { class: "truncate" }, entry.path),
            h("span", { class: "tiny muted nowrap" }, `${entry.lines} L`),
          ),
        ),
      );
      return;
    }
    const prefix = currentPath ? currentPath.split("/").slice(0, -1).join("/") : "";
    const entries = new Map<string, { path: string; type: "file" | "directory"; lines?: number }>();
    for (const entry of files) {
      if (prefix && !entry.path.startsWith(`${prefix}/`)) continue;
      const relative = prefix ? entry.path.slice(prefix.length + 1) : entry.path;
      const [first, ...rest] = relative.split("/");
      if (!first) continue;
      const child = prefix ? `${prefix}/${first}` : first;
      if (rest.length > 0) entries.set(child, { path: child, type: "directory" });
      else entries.set(child, { path: child, type: "file", lines: entry.lines });
    }
    const list = [...entries.values()].sort((a, b) => (a.type === b.type ? a.path.localeCompare(b.path) : a.type === "directory" ? -1 : 1));
    treeHost.replaceChildren();
    fill(treeHost, [
      prefix
        ? h("button", { class: "tree-file", onclick: () => onSelect(prefix.split("/").slice(0, -1).join("/")) }, "↑ Parent directory")
        : null,
      ...list.slice(0, 200).map((entry) =>
        h("button", {
          class: `tree-file ${entry.path === currentPath ? "active" : ""}`,
          onclick: () => onSelect(entry.path),
        },
          h("span", { class: "truncate" }, entry.path.split("/").pop()),
          entry.type === "file" ? h("span", { class: "tiny muted nowrap" }, `${entry.lines} L`) : null,
        ),
      ),
    ]);
  };
  search.addEventListener("input", () => renderTree(search.value));
  renderTree("");

  const fileBody = file
    ? file.binary
      ? emptyState("Binary file", "Argus does not render binary files in the explorer.")
      : file.content.length > 0
        ? h("div", { class: "code-view" },
            h("pre", { class: "code-lines" }, file.content.split("\n").map((_, index) => String(index + 1)).join("\n")),
            h("pre", { class: "code-body" }, file.content),
          )
        : emptyState("Empty file", "The file has no text content.")
    : h("div", { class: "explorer-placeholder" },
        h("div", { class: "empty-mark" }, "⌘"),
        h("h3", {}, "Select a file"),
        h("p", {}, "Browse the isolated snapshot that agent sessions inspect. File contents are read directly from the authorized repository within the imported scope."),
      );

  return h("div", { class: "explorer-grid" },
    h("aside", { class: "explorer-tree" },
      search,
      h("div", { class: "tiny muted" }, `${repo.inventory.files.length} files, ${(repo.total_bytes / 1024).toFixed(1)} KiB`),
      treeHost,
    ),
    h("div", { class: "explorer-main" },
      file
        ? h("div", { class: "row-between", style: { marginBottom: "10px" } },
            h("div", {},
              h("div", { class: "mono small" }, file.path),
              h("div", { class: "tiny muted" }, `${file.lines} lines, ${file.size} bytes${file.truncated ? ", preview truncated" : ""}`),
            ),
            badge(file.truncated ? "preview" : "read-only", file.truncated ? "warn" : "neutral"),
          )
        : null,
      fileBody,
    ),
  );
}

function architectureTab(detail: RepoDetail): HTMLElement {
  const repo = detail.repository;
  const map = detail.map;
  return h("div", { class: "stack" },
    h("div", { class: "grid grid-3" },
      h("div", { class: "metric" }, h("div", { class: "metric-label" }, "Files"), h("div", { class: "metric-value" }, String(repo.inventory.files.length))),
      h("div", { class: "metric" }, h("div", { class: "metric-label" }, "Endpoints"), h("div", { class: "metric-value" }, String(repo.inventory.endpoints.length))),
      h("div", { class: "metric" }, h("div", { class: "metric-label" }, "Dependency edges"), h("div", { class: "metric-value" }, String(repo.inventory.dependency_graph.length))),
    ),
    map?.summary ? h("div", { class: "callout" }, map.summary) : h("div", { class: "callout warn" }, "No completed Phase 1 map for this snapshot yet."),
    h("div", { class: "grid grid-2" },
      h("div", {},
        h("div", { class: "section-title" }, "Languages and frameworks"),
        h("div", { class: "chip-row" }, ...Object.entries(repo.inventory.languages).map(([language, count]) => h("span", { class: "chip on mono" }, `${language} ${count}`))),
        h("div", { class: "chip-row", style: { marginTop: "6px" } }, ...repo.inventory.frameworks.map((framework) => h("span", { class: "chip" }, framework))),
        h("div", { class: "section-title" }, "Entrypoints"),
        h("div", { class: "stack" }, ...(repo.inventory.entrypoints.length ? repo.inventory.entrypoints : ["No conventional entrypoints detected"]).map((entry) => h("div", { class: "mono tiny" }, entry))),
      ),
      h("div", {},
        h("div", { class: "section-title" }, "Modules"),
        map?.modules?.length
          ? h("div", { class: "table-wrap" }, h("table", { class: "small-table" },
              h("thead", {}, h("tr", {}, h("th", {}, "Module"), h("th", {}, "Path"), h("th", {}, "Purpose"))),
              h("tbody", {}, ...map.modules.slice(0, 40).map((module) =>
                h("tr", {}, h("td", { class: "small strong" }, module.name), h("td", { class: "mono tiny" }, module.path), h("td", { class: "small muted" }, module.purpose)),
              )),
            ))
          : h("p", { class: "muted small" }, "Modules appear after Phase 1 completes."),
        h("div", { class: "section-title" }, "Assessment areas"),
        map?.areas?.length
          ? h("div", { class: "stack" }, ...map.areas.map((area) =>
              h("div", { class: "callout" },
                h("div", { class: "row", style: { justifyContent: "space-between" } }, h("span", { class: "small strong" }, area.title), h("span", { class: "chip mono" }, area.id)),
                h("div", { class: "tiny muted" }, `${area.files.length} files, ${area.security_focus.join(", ")}`),
              ),
            ))
          : h("p", { class: "muted small" }, "Areas appear after Phase 1 completes."),
      ),
    ),
    h("div", { class: "section-title" }, "Endpoint inventory"),
    repo.inventory.endpoints.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "small-table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Method"), h("th", {}, "Path"), h("th", {}, "Location"))),
          h("tbody", {}, ...repo.inventory.endpoints.slice(0, 120).map((endpoint) =>
            h("tr", {}, h("td", { class: "mono" }, endpoint.method), h("td", { class: "mono" }, endpoint.path), h("td", { class: "mono tiny" }, `${endpoint.file}:${endpoint.line}`)),
          )),
        ))
      : h("p", { class: "muted small" }, "No endpoint patterns detected."),
    h("div", { class: "section-title" }, "Import dependency graph (sample)"),
    repo.inventory.dependency_graph.length
      ? h("div", { class: "table-wrap", style: { maxHeight: "280px" } }, h("table", { class: "small-table" },
          h("thead", {}, h("tr", {}, h("th", {}, "From"), h("th", {}, "To"))),
          h("tbody", {}, ...repo.inventory.dependency_graph.slice(0, 80).map((edge) =>
            h("tr", {}, h("td", { class: "mono tiny" }, edge.from), h("td", { class: "mono tiny" }, edge.to)),
          )),
        ))
      : h("p", { class: "muted small" }, "No internal import edges detected."),
    h("div", { class: "section-title" }, "Authentication and authorization signals"),
    repo.inventory.auth_boundaries.length
      ? h("div", { class: "stack" }, ...repo.inventory.auth_boundaries.slice(0, 50).map((boundary) =>
          h("div", { class: "row-between small" },
            h("div", {}, h("span", { class: "strong" }, boundary.kind), h("span", { class: "muted" }, `, ${boundary.detail}`)),
            h("span", { class: "mono tiny muted" }, `${boundary.file}:${boundary.line}`),
          ),
        ))
      : h("p", { class: "muted small" }, "No authentication boundary signals detected."),
    map?.limitations?.length ? h("div", { class: "callout warn" }, h("div", { class: "small" }, "Map limitations"), h("div", { class: "small" }, map.limitations.join(", "))) : null,
  );
}

function coverageTab(rows: Coverage[]): HTMLElement {
  if (rows.length === 0) return emptyState("No coverage yet", "Coverage appears after the mapper creates assessment areas in a completed audit.");
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Area"), h("th", {}, "Status"), h("th", {}, "Files"), h("th", {}, "Notes"))),
      h("tbody", {}, ...rows.map((row) =>
        h("tr", {},
          h("td", {}, h("div", { class: "table-title" }, row.title), h("div", { class: "table-sub mono" }, row.area_id)),
          h("td", {}, statusBadge(row.status)),
          h("td", { class: "mono small" }, String(row.files.length)),
          h("td", { class: "small muted" }, row.notes ?? "—"),
        ),
      )),
    ),
  );
}
