import { lstat, mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { runCommand } from "../harness/process.ts";
import { AppError, badRequest, now, parseJson, toJson, uid } from "../util.ts";
import { DEFAULT_EXCLUDES, buildInventory, gitInfo } from "./inventory.ts";
import { assertAuthorizedRoot, canonicalDirectory, createWorkspace } from "./workspace.ts";

const GIT_METADATA_ERROR = "Git metadata must stay inside the repository";

function gitCommandEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value !== "string" || key.startsWith("GIT_")) continue;
    env[key] = value;
  }
  if (!env.PATH) env.PATH = "/usr/bin:/bin";
  return env;
}

function pathInside(candidate: string, root: string): boolean {
  const normalizedRoot = root.endsWith("/") ? root : `${root}/`;
  return candidate === root || candidate.startsWith(normalizedRoot);
}

// `git rev-parse --git-common-dir` prints an absolute path, or a path relative
// to the source directory. A quoted or multi-line path is not used.
function resolveReportedGitPath(sourceRoot: string, printed: string): string {
  const trimmed = printed.trim();
  if (!trimmed || trimmed.includes("\0") || trimmed.includes("\n") || trimmed.startsWith("\"")) {
    throw invalidGitMetadata();
  }
  return trimmed.startsWith("/") ? trimmed : join(sourceRoot, trimmed);
}

function invalidGitMetadata(): AppError {
  return new AppError(400, "invalid_repository", GIT_METADATA_ERROR);
}

// A fifo here would block the following git command. A symlink would name a
// different file than the one inside this directory.
async function assertRegularGitEntry(path: string): Promise<void> {
  let info;
  try {
    info = await lstat(path);
  } catch {
    return;
  }
  if (info.isSymbolicLink() || !info.isFile()) throw invalidGitMetadata();
}

// A pipe or symlink named .git would block or escape before git runs. A gitfile
// is a regular file; ref imports reject it separately so worktree snapshots can
// still copy the selected files.
async function assertLocalGitReadable(sourceRoot: string): Promise<void> {
  const gitPath = join(sourceRoot, ".git");
  let info;
  try {
    info = await lstat(gitPath);
  } catch {
    return;
  }
  if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) throw invalidGitMetadata();
  if (!info.isDirectory()) return;
  await assertRegularGitEntry(join(gitPath, "HEAD"));
  await assertRegularGitEntry(join(gitPath, "config"));
}

// Alternate object databases and symlinked packs live outside the repository
// even when .git itself is a real directory. git archive would copy those bytes.
async function assertContainedObjectStore(gitDir: string): Promise<void> {
  const objectsPath = join(gitDir, "objects");
  let rootInfo;
  try {
    rootInfo = await lstat(objectsPath);
  } catch {
    throw invalidGitMetadata();
  }
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) throw invalidGitMetadata();
  const pending = [objectsPath];
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) break;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      throw invalidGitMetadata();
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile())) throw invalidGitMetadata();
      if (entry.isDirectory()) {
        pending.push(join(current, entry.name));
        continue;
      }
      if (entry.name === "alternates" && current === join(objectsPath, "info")) throw invalidGitMetadata();
    }
  }
}

// Git walks parent directories and follows a .git file or symlink. Archive only
// when that discovered metadata is the work tree containing this source path,
// and the object store does not point at another repository. subpath is the
// directory to archive when the source sits below the work tree root.
async function prepareRefArchive(sourceRoot: string): Promise<{ toplevel: string; subpath: string | null }> {
  const gitPath = join(sourceRoot, ".git");
  let localGit;
  try {
    localGit = await lstat(gitPath);
  } catch {
    localGit = null;
  }
  if (localGit && (localGit.isSymbolicLink() || !localGit.isDirectory())) throw invalidGitMetadata();
  const env = gitCommandEnv();
  const gitDirResult = await runCommand(
    ["git", "-C", sourceRoot, "rev-parse", "--absolute-git-dir"],
    { env, timeoutMs: 20_000 },
  );
  const topResult = await runCommand(
    ["git", "-C", sourceRoot, "rev-parse", "--show-toplevel"],
    { env, timeoutMs: 20_000 },
  );
  if (
    gitDirResult.code !== 0 ||
    gitDirResult.timedOut ||
    topResult.code !== 0 ||
    topResult.timedOut
  ) {
    throw badRequest("Git refs require a git repository");
  }
  let pinnedGit: string;
  let pinnedTop: string;
  try {
    pinnedGit = await canonicalDirectory(gitDirResult.stdout.trim());
    pinnedTop = await canonicalDirectory(topResult.stdout.trim());
  } catch {
    throw invalidGitMetadata();
  }
  if (!pathInside(sourceRoot, pinnedTop) || !pathInside(pinnedGit, pinnedTop)) throw invalidGitMetadata();
  // A commondir file leaves this git directory inside the work tree while
  // archive reads objects from another repository. The common directory Git
  // will use has to be the git directory checked above.
  const commonResult = await runCommand(
    ["git", "-C", sourceRoot, "rev-parse", "--git-common-dir"],
    { env, timeoutMs: 20_000 },
  );
  if (commonResult.code !== 0 || commonResult.timedOut) throw invalidGitMetadata();
  let pinnedCommon: string;
  try {
    pinnedCommon = await canonicalDirectory(resolveReportedGitPath(sourceRoot, commonResult.stdout));
  } catch {
    throw invalidGitMetadata();
  }
  if (pinnedCommon !== pinnedGit) throw invalidGitMetadata();
  await assertContainedObjectStore(pinnedGit);
  const relativePath = relative(pinnedTop, sourceRoot);
  if (!relativePath) return { toplevel: pinnedTop, subpath: null };
  if (
    relativePath.startsWith("..") ||
    relativePath.startsWith("/") ||
    relativePath.includes("\0")
  ) {
    throw invalidGitMetadata();
  }
  return { toplevel: pinnedTop, subpath: relativePath.split(sep).join("/") };
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
  if (ref && !/^[A-Za-z0-9][A-Za-z0-9._/@^~:-]{0,199}$/.test(ref)) {
    throw badRequest("Invalid git ref");
  }
  await assertLocalGitReadable(sourceRoot);
  const refArchive = ref ? await prepareRefArchive(sourceRoot) : null;
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
      const env = gitCommandEnv();
      const resolved = await runCommand(
        ["git", "-C", sourceRoot, "rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`],
        { env, timeoutMs: 20_000 },
      );
      if (resolved.code !== 0 || resolved.timedOut) throw badRequest(`Unknown git ref: ${ref}`);
      commit = resolved.stdout.trim();
      const treeish = refArchive?.subpath ? `${commit}:${refArchive.subpath}` : commit;
      staging = await mkdtemp(join(deps.config.dataDir, "repo-import-"));
      const archivePath = join(staging, "snapshot.tar");
      const extractedRoot = join(staging, "source");
      await mkdir(extractedRoot, { mode: 0o700 });
      const archived = await runCommand(
        ["git", "-C", refArchive?.toplevel ?? sourceRoot, "archive", "--format=tar", "--output", archivePath, treeish],
        { env, timeoutMs: 180_000 },
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
