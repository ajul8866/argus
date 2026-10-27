import { constants } from "node:fs";
import { lstat, mkdir, mkdtemp, open, readdir, readlink, rm } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { runCommand } from "../harness/process.ts";
import { AppError, badRequest, now, parseJson, toJson, uid } from "../util.ts";
import { DEFAULT_EXCLUDES, buildInventory, gitArgv, gitInfo } from "./inventory.ts";
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

async function assertRealGitDirectory(path: string): Promise<void> {
  let info;
  try {
    info = await lstat(path);
  } catch {
    return;
  }
  if (info.isSymbolicLink() || !info.isDirectory()) throw invalidGitMetadata();
}

const GIT_CONFIG_MAX_BYTES = 1_048_576;

// HEAD and loose refs are tiny text files. A larger file is not a ref Git can
// use, and reading it could block or pull in an unrelated payload.
async function readSmallGitText(
  path: string,
  maxBytes = 4_096,
  options?: { requireUtf8?: boolean },
): Promise<string | null> {
  const noFollow = constants.O_NOFOLLOW;
  const nonBlock = constants.O_NONBLOCK;
  if (typeof noFollow !== "number" || typeof nonBlock !== "number" || noFollow === 0 || nonBlock === 0) {
    throw invalidGitMetadata();
  }
  let info;
  try {
    info = await lstat(path);
  } catch {
    return null;
  }
  if (info.isSymbolicLink() || !info.isFile()) throw invalidGitMetadata();
  if (!Number.isSafeInteger(info.size) || info.size < 0 || info.size > maxBytes) throw invalidGitMetadata();
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | noFollow | nonBlock);
  } catch {
    throw invalidGitMetadata();
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== info.size) throw invalidGitMetadata();
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < opened.size) {
      const { bytesRead } = await handle.read(buffer, offset, opened.size - offset, offset);
      if (bytesRead === 0) throw invalidGitMetadata();
      offset += bytesRead;
    }
    const text = buffer.toString("utf8");
    // Git uses the raw bytes of a gitfile or commondir. A replacement character
    // would name a different directory than the one Git opens.
    if (options?.requireUtf8 && !Buffer.from(text, "utf8").equals(buffer)) throw invalidGitMetadata();
    return text;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

function gitRefParts(refName: string): string[] {
  const parts = refName.split("/");
  if (
    !refName ||
    refName.startsWith("/") ||
    refName.includes("\\") ||
    refName.includes("\0") ||
    parts.some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    throw invalidGitMetadata();
  }
  return parts;
}

// Follow a symref chain without opening a pipe or a symlink. Git opens the
// same path while resolving HEAD, and a fifo there waits until another process
// connects a writer.
async function assertLooseRef(gitDir: string, refName: string, depth: number): Promise<void> {
  if (depth > 8) throw invalidGitMetadata();
  const parts = gitRefParts(refName);
  let current = gitDir;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (!part) throw invalidGitMetadata();
    current = join(current, part);
    let entry;
    try {
      entry = await lstat(current);
    } catch {
      return;
    }
    if (entry.isSymbolicLink()) throw invalidGitMetadata();
    const last = index === parts.length - 1;
    if (!last) {
      if (!entry.isDirectory()) throw invalidGitMetadata();
      continue;
    }
    if (!entry.isFile()) throw invalidGitMetadata();
  }
  const text = await readSmallGitText(current);
  const line = text?.split("\n", 1)[0] ?? "";
  if (!line.startsWith("ref:")) return;
  await assertLooseRef(gitDir, line.slice("ref:".length).trim(), depth + 1);
}

// Git opens include.path while parsing config, before a command-line -c
// override exists. Section headers are recognized wherever the parser is
// between values, including after another header on the same line. A comment
// or a value that merely contains the word does not start a section.
function isGitSpace(char: string): boolean {
  return char === " " || char === "\t" || char === "\r" || char === "\f" || char === "\v";
}

function isGitAlpha(char: string): boolean {
  return (char >= "A" && char <= "Z") || (char >= "a" && char <= "z");
}

function isGitKeyChar(char: string): boolean {
  return char === "-" || (char >= "0" && char <= "9") || isGitAlpha(char);
}

function gitConfigIncludesFile(text: string): boolean {
  const source = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let index = 0;
  let sawEof = false;
  let comment = false;
  const read = (): string => {
    if (sawEof) return "\n";
    if (index >= source.length) {
      sawEof = true;
      return "\n";
    }
    const char = source[index] ?? "";
    index += 1;
    if (char === "\r" && source[index] === "\n") {
      index += 1;
      return "\n";
    }
    return char;
  };
  const skipExtended = (first: string): boolean => {
    let current = first;
    do {
      if (current === "\n" || sawEof) return false;
      current = read();
    } while (isGitSpace(current));
    if (current !== "\"") return false;
    while (true) {
      current = read();
      if (current === "\n" || sawEof) return false;
      if (current === "\"") break;
      if (current === "\\") {
        current = read();
        if (current === "\n" || sawEof) return false;
      }
    }
    return read() === "]";
  };
  const skipEntry = (first: string): boolean => {
    let current = first;
    while (isGitKeyChar(current)) current = read();
    while (current === " " || current === "\t") current = read();
    if (current === "\n") return true;
    if (current !== "=") return false;
    let quote = false;
    let inComment = false;
    while (true) {
      current = read();
      if (current === "\n") return !quote;
      if (inComment) continue;
      if (!quote && isGitSpace(current)) continue;
      if (!quote && (current === "#" || current === ";")) {
        inComment = true;
        continue;
      }
      if (current === "\\") {
        read();
        if (sawEof) return !quote;
        continue;
      }
      if (current === "\"") quote = !quote;
    }
  };

  while (!sawEof) {
    const current = read();
    if (current === "\n") {
      if (sawEof) return false;
      comment = false;
      continue;
    }
    if (comment) continue;
    if (isGitSpace(current)) continue;
    if (current === "#" || current === ";") {
      comment = true;
      continue;
    }
    if (current === "[") {
      let name = "";
      let closed = false;
      while (!closed) {
        const next = read();
        if (next === "]") {
          if (name === "include" || name === "includeif") return true;
          closed = true;
          break;
        }
        if (isGitSpace(next) || next === "\n") {
          if (name === "include" || name === "includeif") return true;
          if (next === "\n" || sawEof || !skipExtended(next)) return false;
          closed = true;
          break;
        }
        if (sawEof || (!isGitKeyChar(next) && next !== ".")) return false;
        name += next.toLowerCase();
      }
      continue;
    }
    if (!isGitAlpha(current) || !skipEntry(current)) return false;
  }
  return false;
}

async function assertConfigHasNoInclude(path: string): Promise<void> {
  const text = await readSmallGitText(path, GIT_CONFIG_MAX_BYTES);
  if (text && gitConfigIncludesFile(text)) throw invalidGitMetadata();
}

// Git strips only trailing CR and LF from a gitfile or commondir. Spaces and
// embedded newlines stay in the path. ".." is applied after symlinks are
// followed; see resolveGitDirectoryPath.
function gitPointerTarget(gitDir: string, text: string): string {
  let end = text.length;
  while (end > 0 && (text[end - 1] === "\n" || text[end - 1] === "\r")) end -= 1;
  const raw = text.slice(0, end);
  if (!raw || raw.includes("\0")) throw invalidGitMetadata();
  return raw.startsWith("/") ? raw : `${gitDir}/${raw}`;
}

const MAX_GIT_SYMLINKS = 32;

function stripLastPathComponent(path: string): string {
  const offset = path.startsWith("/") ? 1 : 0;
  let length = path.length;
  while (offset < length && path[length - 1] !== "/") length -= 1;
  while (offset < length && path[length - 1] === "/") length -= 1;
  return path.slice(0, length);
}

// Git follows each symlink and only then applies "..". The runtime realpath
// cancels ".." against the symlink's name first, so it can return a different
// directory from the one Git opens. A final symlink is rejected: Git would
// follow it, and refusing it fails closed before that open.
async function resolveGitDirectoryPath(target: string): Promise<string> {
  if (!target.startsWith("/")) throw invalidGitMetadata();
  let resolved = "/";
  let remaining = target.slice(1);
  let symlinks = 0;
  while (remaining.length > 0) {
    let start = 0;
    while (start < remaining.length && remaining[start] === "/") start += 1;
    let end = start;
    while (end < remaining.length && remaining[end] !== "/") end += 1;
    const component = remaining.slice(start, end);
    remaining = remaining.slice(end);
    if (!component || component === ".") continue;
    if (component === "..") {
      resolved = stripLastPathComponent(resolved);
      continue;
    }
    if (!resolved.endsWith("/")) resolved += "/";
    resolved += component;
    let info;
    try {
      info = await lstat(resolved);
    } catch {
      throw invalidGitMetadata();
    }
    if (!info.isSymbolicLink()) continue;
    const pending = remaining.replace(/^\/+/, "");
    if (!pending) throw invalidGitMetadata();
    symlinks += 1;
    if (symlinks > MAX_GIT_SYMLINKS) throw invalidGitMetadata();
    let linkBytes: Buffer;
    try {
      const linked = await readlink(resolved, { encoding: "buffer" });
      if (!Buffer.isBuffer(linked)) throw invalidGitMetadata();
      linkBytes = linked;
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw invalidGitMetadata();
    }
    const link = linkBytes.toString("utf8");
    if (!link || link.includes("\0") || !Buffer.from(link, "utf8").equals(linkBytes)) throw invalidGitMetadata();
    resolved = stripLastPathComponent(resolved);
    remaining = link.startsWith("/") ? `${link.slice(1)}/${pending}` : `${link}/${pending}`;
    if (link.startsWith("/")) resolved = "/";
  }
  return resolved;
}

async function resolveExistingGitDirectory(target: string): Promise<string | null> {
  const resolved = await resolveGitDirectoryPath(target);
  let info;
  try {
    info = await lstat(resolved);
  } catch {
    throw invalidGitMetadata();
  }
  if (info.isSymbolicLink() || !info.isDirectory()) throw invalidGitMetadata();
  return resolved;
}

// `git rev-parse --verify <ref>` opens the loose ref for that name even when
// HEAD points somewhere else. `worktrees/<name>/HEAD` and a pseudoref such as
// FETCH_HEAD are opened by that name too. A pipe at the final path blocks the
// open. A symlink is followed. An fsmonitor socket is not a ref, so a socket
// is left in place; a pipe, device, or symlink is not.
const PSEUDO_REF_NAME = /^[A-Z_-]+$/;

async function assertPlainGitTree(directory: string): Promise<void> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    throw invalidGitMetadata();
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      await assertPlainGitTree(join(directory, entry.name));
      continue;
    }
    if (entry.isFile() || entry.isSocket()) continue;
    throw invalidGitMetadata();
  }
}

async function assertPlainGitTreeIfPresent(directory: string): Promise<void> {
  let info;
  try {
    info = await lstat(directory);
  } catch {
    return;
  }
  if (info.isSymbolicLink() || !info.isDirectory()) throw invalidGitMetadata();
  await assertPlainGitTree(directory);
}

async function assertPlainPseudoRefs(gitDir: string): Promise<void> {
  let entries;
  try {
    entries = await readdir(gitDir, { withFileTypes: true });
  } catch {
    throw invalidGitMetadata();
  }
  for (const entry of entries) {
    if (!PSEUDO_REF_NAME.test(entry.name)) continue;
    if (entry.isSymbolicLink() || !entry.isFile()) throw invalidGitMetadata();
  }
}

// commondir is a path relative to this git directory, or an absolute path.
// Git reads config and exclude files from that other directory before the
// later equality check can reject it.
async function linkedGitDirectory(gitDir: string): Promise<string | null> {
  const text = await readSmallGitText(join(gitDir, "commondir"), 4_096, { requireUtf8: true });
  if (text === null) return null;
  return resolveExistingGitDirectory(gitPointerTarget(gitDir, text));
}

async function assertGitDirectoryMetadata(gitDir: string, seen = new Set<string>()): Promise<void> {
  let identity;
  try {
    identity = await lstat(gitDir);
  } catch {
    throw invalidGitMetadata();
  }
  if (identity.isSymbolicLink() || !identity.isDirectory()) throw invalidGitMetadata();
  const mark = `${identity.dev}:${identity.ino}`;
  if (seen.has(mark)) return;
  seen.add(mark);
  await assertRegularGitEntry(join(gitDir, "config"));
  await assertRegularGitEntry(join(gitDir, "config.worktree"));
  await assertRegularGitEntry(join(gitDir, "commondir"));
  await assertRegularGitEntry(join(gitDir, "packed-refs"));
  await assertRegularGitEntry(join(gitDir, "shallow"));
  await assertRealGitDirectory(join(gitDir, "info"));
  await assertRegularGitEntry(join(gitDir, "info", "exclude"));
  await assertRegularGitEntry(join(gitDir, "info", "attributes"));
  await assertRegularGitEntry(join(gitDir, "info", "grafts"));
  await assertRegularGitEntry(join(gitDir, "info", "sparse-checkout"));
  await assertRealGitDirectory(join(gitDir, "refs"));
  await assertConfigHasNoInclude(join(gitDir, "config"));
  await assertConfigHasNoInclude(join(gitDir, "config.worktree"));
  await assertPlainPseudoRefs(gitDir);
  await assertPlainGitTreeIfPresent(join(gitDir, "refs"));
  await assertPlainGitTreeIfPresent(join(gitDir, "worktrees"));
  const head = await readSmallGitText(join(gitDir, "HEAD"));
  const headLine = head?.split("\n", 1)[0] ?? "";
  if (headLine.startsWith("ref:")) await assertLooseRef(gitDir, headLine.slice("ref:".length).trim(), 0);
  const common = await linkedGitDirectory(gitDir);
  if (common) await assertGitDirectoryMetadata(common, seen);
}

// A gitfile is "gitdir: <path>". The path is relative to the file's directory.
// Git follows it and then opens metadata in that directory.
async function assertGitFileTarget(gitFilePath: string): Promise<void> {
  const text = await readSmallGitText(gitFilePath, 4_096, { requireUtf8: true });
  if (text === null || !text.startsWith("gitdir: ")) return;
  const resolved = await resolveExistingGitDirectory(gitPointerTarget(dirname(gitFilePath), text.slice("gitdir: ".length)));
  if (resolved) await assertGitDirectoryMetadata(resolved);
}

// A pipe or symlink named .git would block or escape before git runs. A gitfile
// is a regular file; ref imports reject it separately so worktree snapshots can
// still copy the selected files. The directory a gitfile names, including one
// found by walking parents, is checked before Git starts.
async function assertLocalGitReadable(sourceRoot: string): Promise<void> {
  let current = sourceRoot;
  while (true) {
    const gitPath = join(current, ".git");
    let info;
    try {
      info = await lstat(gitPath);
    } catch {
      const parent = dirname(current);
      if (parent === current) return;
      current = parent;
      continue;
    }
    if (info.isDirectory()) {
      await assertGitDirectoryMetadata(gitPath);
      return;
    }
    if (!info.isFile()) throw invalidGitMetadata();
    await assertGitFileTarget(gitPath);
    return;
  }
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
    gitArgv(["-C", sourceRoot, "rev-parse", "--absolute-git-dir"]),
    { env, timeoutMs: 20_000 },
  );
  const topResult = await runCommand(
    gitArgv(["-C", sourceRoot, "rev-parse", "--show-toplevel"]),
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
    gitArgv(["-C", sourceRoot, "rev-parse", "--git-common-dir"]),
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
        gitArgv(["-C", sourceRoot, "rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`]),
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
        gitArgv(["-C", refArchive?.toplevel ?? sourceRoot, "archive", "--format=tar", "--output", archivePath, treeish]),
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
