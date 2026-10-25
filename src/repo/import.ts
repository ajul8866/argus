import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { runCommand } from "../harness/process.ts";
import { badRequest, now, parseJson, toJson, uid } from "../util.ts";
import { DEFAULT_EXCLUDES, buildInventory, gitInfo } from "./inventory.ts";
import { assertAuthorizedRoot, createWorkspace, removeOutOfScope, removeSymlinks } from "./workspace.ts";

export async function importRepository(
  deps: { config: Config; store: Store },
  project: { id: string; source_path: string; scope_include: string; scope_exclude: string },
  ref: string | null,
  importedBy: string,
): Promise<{
  id: string;
  project_id: string;
  path: string;
  commit_sha: string | null;
  branch: string | null;
  file_count: number;
  total_bytes: number;
  imported_at: string;
}> {
  const sourceRoot = await assertAuthorizedRoot(project.source_path, deps.config.allowedRoots);
  const git = await gitInfo(sourceRoot);
  const scope = {
    include: parseJson<string[]>(project.scope_include, ["**/*"]),
    exclude: [...new Set([...DEFAULT_EXCLUDES, ...parseJson<string[]>(project.scope_exclude, [])])],
  };
  let importRoot = sourceRoot;
  let commit = git.commit;
  let branch = git.branch;
  const snapshotBase = join(
    deps.config.dataDir,
    "repos",
    project.id,
    `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
  );
  if (ref) {
    if (!git.commit) throw badRequest("Git refs require a git repository");
    if (!/^[A-Za-z0-9][A-Za-z0-9._/@^~:-]{0,199}$/.test(ref)) {
      throw badRequest("Invalid git ref");
    }
    const resolved = await runCommand(
      ["git", "-C", sourceRoot, "rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`],
      { timeoutMs: 20_000 },
    );
    if (resolved.code !== 0) throw badRequest(`Unknown git ref: ${ref}`);
    const commitSha = resolved.stdout.trim();
    if (!/^[0-9a-f]{40}$/.test(commitSha) && !/^[0-9a-f]{64}$/.test(commitSha)) {
      throw badRequest("Git did not resolve the ref to a commit");
    }
    commit = commitSha;
    await mkdir(snapshotBase, { recursive: true, mode: 0o700 });
    const archived = await runCommand(
      ["sh", "-c", 'git -C "$1" archive --format=tar "$2" | tar -xf - -C "$3"', "argus", sourceRoot, commitSha, snapshotBase],
      { timeoutMs: 180_000 },
    );
    if (archived.code !== 0) {
      throw badRequest(`Failed to archive ${ref}: ${archived.stderr.slice(0, 500)}`);
    }
    // Archive extracts the whole commit, including files rejected by the import
    // scope. Remove symlinks first, then drop the remaining out-of-scope files
    // so a later read with a wider project scope cannot recover them.
    await removeSymlinks(snapshotBase);
    await removeOutOfScope(snapshotBase, scope);
    importRoot = snapshotBase;
    branch = ref;
  } else {
    // Snapshot the current worktree so later edits cannot silently change the
    // code that evidence quotes and findings refer to.
    const sourceInventory = await buildInventory(sourceRoot, {
      scope,
      maxFiles: 6_000,
      maxFileBytes: 512_000,
    });
    if (sourceInventory.files.length === 0) throw badRequest("No in-scope files were found in the repository");
    await mkdir(snapshotBase, { recursive: true, mode: 0o700 });
    await createWorkspace(sourceRoot, sourceInventory, scope, snapshotBase, {
      project_id: project.id,
      source_root: sourceRoot,
      commit,
      imported_by: importedBy,
    });
    importRoot = snapshotBase;
  }
  const inventory = await buildInventory(importRoot, {
    scope,
    maxFiles: 6_000,
    maxFileBytes: 512_000,
  });
  if (inventory.files.length === 0) throw badRequest("No in-scope files were found in the repository");
  const id = uid();
  deps.store.run(
    `INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id,
    project.id,
    importRoot,
    commit,
    branch,
    toJson(inventory.languages),
    toJson(inventory.frameworks),
    toJson(inventory),
    toJson({
      endpoints: inventory.endpoints,
      auth_boundaries: inventory.auth_boundaries,
      dependency_graph: inventory.dependency_graph,
      entrypoints: inventory.entrypoints,
    }),
    inventory.files.length,
    inventory.total_bytes,
    now(),
  );
  const stored = deps.store.get<{
    id: string;
    project_id: string;
    path: string;
    commit_sha: string | null;
    branch: string | null;
    file_count: number;
    total_bytes: number;
    imported_at: string;
  }>("SELECT * FROM repositories WHERE id = ?", id)!;
  return { ...stored, file_count: inventory.files.length };
}
