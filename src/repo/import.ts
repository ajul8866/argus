import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { runCommand } from "../harness/process.ts";
import { badRequest, now, parseJson, toJson, uid } from "../util.ts";
import { DEFAULT_EXCLUDES, buildInventory, gitInfo } from "./inventory.ts";
import { assertAuthorizedRoot, createWorkspace } from "./workspace.ts";

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
  const sourceRoot = await assertAuthorizedRoot(project.source_path, deps.config.allowedRoots, deps.config.dataDir);
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
  let staging: string | null = null;
  try {
    if (ref) {
      if (!git.commit) throw badRequest("Git refs require a git repository");
      if (!/^[A-Za-z0-9][A-Za-z0-9._/@^~:-]{0,199}$/.test(ref)) {
        throw badRequest("Invalid git ref");
      }
      const resolved = await runCommand(
        ["git", "-C", sourceRoot, "rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`],
        {
          timeoutMs: 20_000,
          env: {
            PATH: process.env.PATH ?? "/usr/bin:/bin",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
          },
        },
      );
      if (resolved.code !== 0) throw badRequest(`Unknown git ref: ${ref}`);
      commit = resolved.stdout.trim();
      staging = await mkdtemp(join(deps.config.dataDir, "repo-import-"));
      const archivePath = join(staging, "snapshot.tar");
      const extractedRoot = join(staging, "source");
      await mkdir(extractedRoot, { mode: 0o700 });
      // Archive with every repository-local command-bearing configuration
      // entry overridden, so a filter/tar/fsmonitor driver shipped inside the
      // audited repository cannot execute during `git archive`.
      const gitDir = await runCommand(
        ["git", "-C", sourceRoot, "rev-parse", "--absolute-git-dir"],
        { timeoutMs: 20_000 },
      );
      if (gitDir.code !== 0) throw badRequest("Failed to locate the git directory");
      const localConfig = await runCommand(
        ["git", "--git-dir", gitDir.stdout.trim(), "config", "--local", "--name-only", "--list"],
        { timeoutMs: 20_000 },
      );
      const dangerousKey =
        /^(filter\..*\.(smudge|clean|process)|tar\..*\.command|diff\..*\.(textconv|command)|core\.(fsmonitor|hookspath|pager|editor|sshcommand|alternaterefscommand|gitproxy)|credential\..*\.helper|uploadpack\..*\.(uploadpack|receivepack)|gpg\..*\.program)$/i;
      const overrides = localConfig.stdout
        .split("\n")
        .map((line) => line.trim())
        .filter((key) => key && dangerousKey.test(key))
        .flatMap((key) => ["-c", `${key}=`]);
      const archived = await runCommand(
        [
          "git",
          ...overrides,
          "-c",
          "core.fsmonitor=",
          "-c",
          `core.hooksPath=${join(staging, "nohooks")}`,
          "-c",
          "core.pager=cat",
          "-C",
          sourceRoot,
          "archive",
          "--format=tar",
          "--output",
          archivePath,
          commit,
        ],
        {
          timeoutMs: 180_000,
          env: {
            PATH: process.env.PATH ?? "/usr/bin:/bin",
            HOME: staging,
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_ATTR_NOSYSTEM: "1",
          },
        },
      );
      if (archived.code !== 0 || archived.timedOut) {
        throw badRequest(`Failed to archive ${ref}: ${archived.stderr.slice(0, 500)}`);
      }
      const extracted = await runCommand(["tar", "-xf", archivePath, "-C", extractedRoot], { timeoutMs: 180_000 });
      if (extracted.code !== 0 || extracted.timedOut) {
        throw badRequest(`Failed to extract ${ref}: ${extracted.stderr.slice(0, 500)}`);
      }
      importRoot = extractedRoot;
      branch = ref;
    }
    // Snapshot the current worktree so later edits cannot silently change the
    // code that evidence quotes and findings refer to.
    const sourceInventory = await buildInventory(importRoot, {
      scope,
      maxFiles: 6_000,
      maxFileBytes: 512_000,
    });
    if (sourceInventory.files.length === 0) throw badRequest("No in-scope files were found in the repository");
    await mkdir(snapshotBase, { recursive: true, mode: 0o700 });
    await createWorkspace(importRoot, sourceInventory, scope, snapshotBase, {
      project_id: project.id,
      source_root: sourceRoot,
      commit,
      imported_by: importedBy,
    });
    importRoot = snapshotBase;
  } catch (error) {
    await rm(snapshotBase, { recursive: true, force: true });
    throw error;
  } finally {
    if (staging) await rm(staging, { recursive: true, force: true });
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
