import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { runCommand } from "../harness/process.ts";
import { AppError, badRequest, now, parseJson, toJson, uid } from "../util.ts";
import { DEFAULT_EXCLUDES, buildInventory, gitArgv, gitInfo } from "./inventory.ts";
import {
  GIT_DIRECTORY_ERROR,
  GIT_METADATA_ERROR,
  assertAuthorizedRoot,
  createWorkspace,
  openAuthorizedGitDirectory,
  openWorktreeGit,
  type PinnedGitDir,
} from "./workspace.ts";

function gitEnv(): Record<string, string> {
  return { PATH: process.env.PATH ?? "/usr/bin:/bin" };
}

function pinnedGitDirFlag(): string {
  if (existsSync("/proc/self/fd")) return "--git-dir=/proc/self/fd/3";
  if (existsSync("/dev/fd")) return "--git-dir=/dev/fd/3";
  throw new AppError(400, "invalid_repository", GIT_METADATA_ERROR);
}

// Git reads this descriptor, not the path. Replacing `.git` with a symlink
// after the open does not change the inode git archives. GIT_COMMON_DIR is the
// same descriptor, so a commondir file written after the metadata check cannot
// redirect object reads.
export async function runPinnedGit(
  git: PinnedGitDir,
  args: string[],
  timeoutMs: number,
): Promise<{ code: number; stdout: string; stderr: string; timedOut: boolean }> {
  const flag = pinnedGitDirFlag();
  // `--no-replace-objects` and the config overrides are the same flags `gitInfo`
  // uses. `git archive` and `git status` open core.excludesFile and
  // core.attributesFile while reading config; `rev-parse` does not. A fifo at
  // either path blocks the archive for the full timeout unless the command
  // forces both settings. GIT_NO_LAZY_FETCH stops a promisor remote from
  // downloading the object being archived.
  return runCommand(gitArgv([flag, ...args]), {
    timeoutMs,
    env: {
      ...gitEnv(),
      GIT_COMMON_DIR: flag.slice("--git-dir=".length),
      GIT_NO_LAZY_FETCH: "1",
    },
    extraFd: git.fd,
  });
}

async function pinnedGitInfo(git: PinnedGitDir): Promise<{ commit: string | null; branch: string | null }> {
  const commit = await runPinnedGit(git, ["rev-parse", "HEAD"], 20_000);
  const branch = await runPinnedGit(git, ["rev-parse", "--abbrev-ref", "HEAD"], 20_000);
  return {
    commit: commit.code === 0 ? commit.stdout.trim() || null : null,
    branch: branch.code === 0 ? branch.stdout.trim() || null : null,
  };
}

function archiveTreeish(commit: string, gitPath: string, sourceRoot: string): string {
  if (!/^[0-9a-f]{7,64}$/i.test(commit) || basename(gitPath) !== ".git") {
    throw new AppError(400, "invalid_repository", GIT_DIRECTORY_ERROR);
  }
  const prefix = relative(dirname(gitPath), sourceRoot).replaceAll("\\", "/");
  if (prefix === "") return commit;
  const parts = prefix.split("/");
  if (
    prefix.startsWith("../") ||
    prefix === ".." ||
    prefix.startsWith("/") ||
    prefix.includes(":") ||
    prefix.includes("\0") ||
    parts.includes("..") ||
    parts.includes(".") ||
    parts.some((part) => part.length === 0)
  ) {
    throw new AppError(400, "invalid_repository", GIT_DIRECTORY_ERROR);
  }
  return `${commit}:${prefix}`;
}

async function discoverGitDirectory(sourceRoot: string, allowedRoots: string[]): Promise<PinnedGitDir | null> {
  const discovered = await runCommand(
    ["git", "-C", sourceRoot, "rev-parse", "--absolute-git-dir"],
    { timeoutMs: 20_000, env: gitEnv() },
  );
  if (discovered.code !== 0 || discovered.timedOut) return null;
  const printed = discovered.stdout.trim();
  if (!printed || printed.includes("\0") || printed.includes("\n")) {
    throw new AppError(400, "invalid_repository", GIT_DIRECTORY_ERROR);
  }
  return openAuthorizedGitDirectory(printed.startsWith("/") ? printed : resolve(sourceRoot, printed), allowedRoots);
}

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
  const localGit = await openWorktreeGit(sourceRoot, deps.config.allowedRoots);
  let pinnedGit: PinnedGitDir | null = localGit.kind === "pinned" ? localGit.git : null;
  const scope = {
    include: parseJson<string[]>(project.scope_include, ["**/*"]),
    exclude: [...new Set([...DEFAULT_EXCLUDES, ...parseJson<string[]>(project.scope_exclude, [])])],
  };
  let importRoot = sourceRoot;
  let commit: string | null = null;
  let branch: string | null = null;
  const snapshotBase = join(
    deps.config.dataDir,
    "repos",
    project.id,
    `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
  );
  let staging: string | null = null;
  try {
    if (localGit.kind === "pinned" && pinnedGit) {
      const git = await pinnedGitInfo(pinnedGit);
      commit = git.commit;
      branch = git.branch;
    } else if (localGit.kind === "missing" && !ref) {
      const git = await gitInfo(sourceRoot);
      commit = git.commit;
      branch = git.branch;
    }
    if (ref) {
      if (localGit.kind === "unsafe") throw new AppError(400, "invalid_repository", GIT_METADATA_ERROR);
      if (!/^[A-Za-z0-9][A-Za-z0-9._/@^~:-]{0,199}$/.test(ref)) {
        throw badRequest("Invalid git ref");
      }
      if (!pinnedGit) pinnedGit = await discoverGitDirectory(sourceRoot, deps.config.allowedRoots);
      if (!pinnedGit) throw badRequest("Git refs require a git repository");
      const resolved = await runPinnedGit(
        pinnedGit,
        ["rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`],
        20_000,
      );
      if (resolved.code !== 0 || resolved.timedOut) throw badRequest(`Unknown git ref: ${ref}`);
      commit = resolved.stdout.trim();
      staging = await mkdtemp(join(deps.config.dataDir, "repo-import-"));
      const archivePath = join(staging, "snapshot.tar");
      const extractedRoot = join(staging, "source");
      await mkdir(extractedRoot, { mode: 0o700 });
      const archived = await runPinnedGit(
        pinnedGit,
        ["archive", "--format=tar", "--output", archivePath, archiveTreeish(commit, pinnedGit.path, sourceRoot)],
        180_000,
      );
      if (archived.code !== 0 || archived.timedOut) {
        throw badRequest(`Failed to archive ${ref}: ${archived.stderr.slice(0, 500)}`);
      }
      const extracted = await runCommand(["tar", "-xf", archivePath, "-C", extractedRoot], {
        timeoutMs: 180_000,
        env: gitEnv(),
      });
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
    await pinnedGit?.close().catch(() => undefined);
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
