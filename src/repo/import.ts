import { lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { runCommand } from "../harness/process.ts";
import { badRequest, isInside, now, parseJson, toJson, uid } from "../util.ts";
import {
  DEFAULT_EXCLUDES,
  buildInventory,
  gitInfoForDirectory,
  preparePrivateGitDirectory,
  resolveGitCommonDirectory,
  resolveGitDirectory,
} from "./inventory.ts";
import { assertAuthorizedRoot, createWorkspace } from "./workspace.ts";

const GIT_ESCAPE = "The repository's git directory is outside the authorized repository";

function privateGitEnvironment(staging: string, objectDirectory: string | null): Record<string, string> {
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: staging,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_ATTR_NOSYSTEM: "1",
    ...(objectDirectory ? { GIT_OBJECT_DIRECTORY: objectDirectory } : {}),
  };
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
  const sourceRoot = await assertAuthorizedRoot(project.source_path, deps.config.allowedRoots, deps.config.dataDir);
  // `assertAuthorizedRoot` validates the directory the auditor nominated, but
  // git performs its own repository discovery and follows a `.git` file's
  // `gitdir:` pointer. Canonicalize the directory git would actually use and
  // require it to stay inside the authorized repository root, so a hand-off
  // directory cannot redirect the import at another repository on the host.
  const gitDirectory = await resolveGitDirectory(sourceRoot);
  const hasGitEntry = await lstat(join(sourceRoot, ".git")).then(
    () => true,
    () => false,
  );
  const gitDirectoryInsideRoot = gitDirectory !== null && isInside(sourceRoot, gitDirectory);
  if (hasGitEntry && gitDirectory === null) {
    throw badRequest("Failed to locate the git directory");
  }
  if (hasGitEntry && !gitDirectoryInsideRoot) {
    throw badRequest(GIT_ESCAPE);
  }
  // Worktree-style layouts redirect the object store through a `commondir`
  // file, so require that indirection to stay inside the authorized root too.
  const gitCommonDirectory = gitDirectoryInsideRoot && gitDirectory
    ? await resolveGitCommonDirectory(gitDirectory)
    : null;
  if (gitDirectoryInsideRoot && (!gitCommonDirectory || !isInside(sourceRoot, gitCommonDirectory))) {
    throw badRequest(GIT_ESCAPE);
  }
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
    if (gitDirectoryInsideRoot && gitDirectory && gitCommonDirectory) {
      staging = await mkdtemp(join(deps.config.dataDir, "repo-import-"));
      // Every git command below reads a private metadata directory with a
      // whitelisted config and no `commondir`; it can neither follow a
      // rewritten pointer nor read command-bearing configuration supplied by
      // the audited repository.
      const privateGit = await preparePrivateGitDirectory(
        { gitDirectory, commonDirectory: gitCommonDirectory },
        { sourceRoot, staging, includeObjects: ref !== null },
      );
      if (ref) {
        if (!/^[A-Za-z0-9][A-Za-z0-9._/@^~:-]{0,199}$/.test(ref)) {
          throw badRequest("Invalid git ref");
        }
        const resolved = await runCommand(
          [
            "git",
            `--git-dir=${privateGit.gitDirectory}`,
            "rev-parse",
            "--verify",
            "--end-of-options",
            `${ref}^{commit}`,
          ],
          { timeoutMs: 20_000, env: privateGitEnvironment(staging, privateGit.objectDirectory) },
        );
        if (resolved.code !== 0) throw badRequest(`Unknown git ref: ${ref}`);
        commit = resolved.stdout.trim();
        branch = ref;
        const archivePath = join(staging, "snapshot.tar");
        const extractedRoot = join(staging, "source");
        await mkdir(extractedRoot, { mode: 0o700 });
        const archived = await runCommand(
          [
            "git",
            `--git-dir=${privateGit.gitDirectory}`,
            "-c",
            "core.fsmonitor=",
            "-c",
            `core.hooksPath=${join(staging, "nohooks")}`,
            "-c",
            "core.pager=cat",
            "archive",
            "--format=tar",
            "--output",
            archivePath,
            commit,
          ],
          { timeoutMs: 180_000, env: privateGitEnvironment(staging, privateGit.objectDirectory) },
        );
        if (archived.code !== 0 || archived.timedOut) {
          throw badRequest(`Failed to archive ${ref}: ${archived.stderr.slice(0, 500)}`);
        }
        const extracted = await runCommand(["tar", "-xf", archivePath, "-C", extractedRoot], { timeoutMs: 180_000 });
        if (extracted.code !== 0 || extracted.timedOut) {
          throw badRequest(`Failed to extract ${ref}: ${extracted.stderr.slice(0, 500)}`);
        }
        importRoot = extractedRoot;
      } else {
        const info = await gitInfoForDirectory(privateGit.gitDirectory);
        commit = info.commit;
        branch = info.branch;
      }
    } else if (ref) {
      if (gitDirectory) throw badRequest(GIT_ESCAPE);
      throw badRequest("Git refs require a git repository");
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
