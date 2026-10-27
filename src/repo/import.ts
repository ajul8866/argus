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
// same path while resolving HEAD and while resolving the requested revision,
// and a fifo there waits until another process connects a writer.
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
  const text = await readSmallGitText(current, 4_096, { requireUtf8: true });
  const target = looseSymrefTarget(text ?? "");
  if (!target) return;
  await assertLooseRef(gitDir, target, depth + 1);
}

// "name~3" and "name^2" select an ancestor. Git opens the loose ref for the
// prefix, not for the suffix. A "~" or "^" earlier in the name is part of the
// ref. The requested ref cannot contain "{"; the verifier appends "^{commit}".
function ancestorPrefix(name: string): string | null {
  let index = name.length - 1;
  while (index >= 0) {
    const char = name[index] ?? "";
    if (char < "0" || char > "9") break;
    index -= 1;
  }
  if (index < 0) return null;
  const mark = name[index];
  if (mark !== "~" && mark !== "^") return null;
  return name.slice(0, index);
}

function ancestorBase(name: string): string {
  let current = name;
  while (current.length > 0) {
    const ancestor = ancestorPrefix(current);
    if (ancestor === null) break;
    current = ancestor;
  }
  return current;
}

const COMMIT_PEEL = "^{commit}";

// rev-parse --verify receives "<ref>^{commit}". A ":" path and a ".." or "..."
// range are parsed before the loose ref is opened, so the dwim name is not the
// raw request. A range opens each side when the left side resolves; both sides
// are checked so a pipe on the right cannot block that resolution.
function revisionBeforePath(name: string): string {
  const peeled = name.endsWith(COMMIT_PEEL) ? name.slice(0, -COMMIT_PEEL.length) : name;
  const colon = peeled.indexOf(":");
  const selected = colon === -1 ? peeled : peeled.slice(0, colon);
  return ancestorBase(selected);
}

function revisionProbeNames(ref: string): string[] {
  const spec = `${ref}${COMMIT_PEEL}`;
  const names: string[] = [];
  const add = (raw: string): void => {
    const name = revisionBeforePath(raw);
    if (!name || names.includes(name)) return;
    names.push(name);
  };
  const dot = spec.indexOf("..");
  if (dot === -1) {
    add(spec);
    return names;
  }
  let end = spec.slice(dot + 2);
  if (end.startsWith(".")) end = end.slice(1);
  add(spec.slice(0, dot));
  add(end);
  return names;
}

// A directory is a dwim miss, not a pipe. A file or fifo in the middle of a
// longer probe cannot be opened as a directory, so that one probe stops.
// A symlink can be followed into a pipe, and the final file can be a symref
// to a pipe outside refs/.
async function assertProbedRef(gitDir: string, refName: string): Promise<void> {
  if (!refName) return;
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
      if (!entry.isDirectory()) return;
      continue;
    }
    if (entry.isDirectory()) return;
    if (!entry.isFile()) throw invalidGitMetadata();
  }
  await assertLooseRef(gitDir, refName, 0);
}

// repo_dwim_ref tries these six shapes and, when ambiguous-ref warnings are
// on, opens every one of them. A pipe at refs/tags/<name> blocks verification
// of the branch <name> before Git reaches refs/heads/<name>.
async function assertRequestedRevision(gitDir: string, ref: string): Promise<void> {
  for (const name of revisionProbeNames(ref)) {
    const probes = [
      name,
      `refs/${name}`,
      `refs/tags/${name}`,
      `refs/heads/${name}`,
      `refs/remotes/${name}`,
      `refs/remotes/${name}/HEAD`,
    ];
    for (const probe of probes) await assertProbedRef(gitDir, probe);
  }
}

// Git walks these abbreviations from the most specific rule. Strict mode
// keeps going when an earlier short name is ambiguous, and the later name
// opens a different set of loose paths.
function gitShortRefNames(fullRef: string): string[] {
  const rules = [
    ["refs/remotes/", "/HEAD"],
    ["refs/remotes/", ""],
    ["refs/heads/", ""],
    ["refs/tags/", ""],
    ["refs/", ""],
  ] as const;
  const names: string[] = [];
  for (const [prefix, suffix] of rules) {
    if (!fullRef.startsWith(prefix)) continue;
    if (suffix) {
      if (!fullRef.endsWith(suffix)) continue;
      const shortName = fullRef.slice(prefix.length, fullRef.length - suffix.length);
      if (!shortName || shortName.endsWith("/")) continue;
      names.push(shortName);
      continue;
    }
    const shortName = fullRef.slice(prefix.length);
    if (shortName) names.push(shortName);
  }
  return names;
}

// Git reads at most five files while resolving one symref chain. The fifth
// file is the resolved name when it is not another symref.
const SYMREF_READ_LIMIT = 5;

type SymrefFollow = { name: string; depth: number };

// C isspace(), not String.trim(). Git keeps a trailing Unicode space in the
// symref target and opens that path.
function isGitRefSpace(char: string): boolean {
  return char === " " || char === "\t" || char === "\n" || char === "\r" || char === "\f" || char === "\v";
}

function looseSymrefTarget(text: string): string | null {
  let end = text.length;
  while (end > 0 && isGitRefSpace(text[end - 1] ?? "")) end -= 1;
  const body = text.slice(0, end);
  if (!body.startsWith("ref:")) return null;
  let index = "ref:".length;
  while (index < body.length && isGitRefSpace(body[index] ?? "")) index += 1;
  const target = body.slice(index);
  // Git skips every isspace byte after "ref:", so the target can start on a
  // later line. An interior break is not a ref Git can resolve.
  if (target.includes("\n") || target.includes("\r")) return null;
  return target ? target : null;
}

// Pseudorefs and refs/bisect, refs/worktree, and refs/rewritten live in the
// worktree git directory. Every other ref is read from the common directory.
function isCurrentWorktreeRef(name: string): boolean {
  if (
    name.startsWith("refs/bisect/") ||
    name.startsWith("refs/worktree/") ||
    name.startsWith("refs/rewritten/")
  ) {
    return true;
  }
  if (!name) return false;
  for (const char of name) {
    if (char >= "A" && char <= "Z") continue;
    if (char === "-" || char === "_") continue;
    return false;
async function looseRefLine(gitDir: string, refName: string): Promise<string | null> {
  const parts = gitRefParts(refName);
  let path = gitDir;
  for (const part of parts) path = join(path, part);
  const text = await readSmallGitText(path);
  return text?.split("\n", 1)[0] ?? null;
}

// Pseudorefs and the per-worktree ref namespaces live beside HEAD. Shared
// refs such as branches and tags live in the common directory.
function isWorktreePrivateRef(refName: string): boolean {
  if (refName.startsWith("refs/bisect/") || refName.startsWith("refs/worktree/") || refName.startsWith("refs/rewritten/")) {
    return true;
  }
  if (!refName || refName.includes("/")) return false;
  for (const char of refName) {
    const upper = char >= "A" && char <= "Z";
    if (!upper && char !== "-" && char !== "_") return false;
  }
  return true;
}

// Git reads `main-worktree/<ref>` from the common directory only when `<ref>`
// is a pseudoref or a per-worktree namespace. Any other remainder is a literal
// shared ref, so the prefix stays part of that path.
function mainWorktreeBareRef(refName: string): string | null {
  const prefix = "main-worktree/";
  if (!refName.startsWith(prefix)) return null;
  const bare = refName.slice(prefix.length);
  return isCurrentWorktreeRef(bare) ? bare : null;
}

// Read one loose ref without following a symref. A pipe or symlink is rejected.
// The caller passes the git directory Git uses for this hop. A main-worktree
// prefix on a pseudoref or per-worktree ref names the file in that directory.
async function readLooseRefLine(gitDir: string, refName: string): Promise<string | null> {
  const parts = gitRefParts(mainWorktreeBareRef(refName) ?? refName);
  let current = gitDir;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (!part) throw invalidGitMetadata();
    current = join(current, part);
    let entry;
    try {
      entry = await lstat(current);
    } catch {
      return null;
    }
    if (entry.isSymbolicLink()) throw invalidGitMetadata();
    const last = index === parts.length - 1;
    if (!last) {
      if (!entry.isDirectory()) throw invalidGitMetadata();
      continue;
    }
    if (!entry.isFile()) throw invalidGitMetadata();
  }
  const text = await readSmallGitText(current, 4_096, { requireUtf8: true });
  return text ?? "";
}

// `--abbrev-ref HEAD` shortens the ref the symref chain resolves to and opens
// that name's loose-ref candidates. A linked worktree reads shared refs from
// its common directory, so a same-named file in the worktree git directory
// must not end the chain.
async function addSymrefAbbreviations(
  gitDir: string,
  names: Set<string>,
  follow: readonly SymrefFollow[],
  sharedRefsElsewhere: boolean,
// Git keeps only HEAD and a few namespaces in a linked worktree's own
// directory; every other ref is read from the common directory, so a
// same-named file in the worktree directory is a decoy Git never opens.
function isPerWorktreeRef(refName: string): boolean {
  return refName === "HEAD"
    || refName.startsWith("refs/bisect/")
    || refName.startsWith("refs/worktree/")
    || refName.startsWith("refs/rewritten/");
}

async function addSymrefAbbreviations(
  gitDir: string,
  common: string | null,
  names: Set<string>,
  follow: readonly SymrefFollow[],
): Promise<SymrefFollow[]> {
  const carry: SymrefFollow[] = [];
  const pending = [...follow];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const item = pending.pop();
    if (!item || visited.has(item.name)) continue;
    visited.add(item.name);
    const store = common && !isPerWorktreeRef(item.name) ? common : gitDir;
    const line = await readLooseRefLine(store, item.name);
    if (line === null) {
      carry.push(item);
      continue;
    }
    const target = looseSymrefTarget(line);
    if (!target) continue;
    if (item.depth >= SYMREF_READ_LIMIT - 1) continue;
    names.add(target);
    for (const shortName of gitShortRefNames(target)) names.add(shortName);
    pending.push({ name: target, depth: item.depth + 1 });
  }
  return carry;
}

// Every import runs `rev-parse HEAD` and `--abbrev-ref HEAD` before the
// requested revision is verified. Those commands open the same six candidates
// for HEAD and for each branch named by the HEAD symref chain. A linked
// worktree stores shared refs in the common directory. A same-named file in
// the worktree git directory is not the file Git opens.
// `main-worktree/HEAD` and `main-worktree/refs/bisect/...` name the main
// worktree's private refs. Git reads them from the common directory under
// the bare name, not from a `main-worktree` directory.
function mainWorktreeRefName(refName: string): string | null {
  const prefix = "main-worktree/";
  if (!refName.startsWith(prefix)) return null;
  const bare = refName.slice(prefix.length);
  return isWorktreePrivateRef(bare) ? bare : null;
}

// `--abbrev-ref HEAD` follows the symref chain and shortens the final ref.
// A linked worktree stores shared refs in the common directory. The next hop
// of a private ref is still the file next to HEAD.
async function finalHeadRef(headDir: string, refRoot: string): Promise<string | null> {
  const head = await readSmallGitText(join(headDir, "HEAD"));
  let line = head?.split("\n", 1)[0] ?? "";
  let full: string | null = null;
  const seen = new Set<string>();
  for (let depth = 0; line.startsWith("ref:"); depth += 1) {
    if (depth > 8) throw invalidGitMetadata();
    const target = line.slice("ref:".length).trim();
    if (!target || seen.has(target)) throw invalidGitMetadata();
    seen.add(target);
    full = target;
    const bare = mainWorktreeRefName(target);
    const next = await looseRefLine(bare ? refRoot : isWorktreePrivateRef(target) ? headDir : refRoot, bare ?? target);
    if (next === null) break;
    line = next;
  }
  return full;
}

// Every import runs `rev-parse HEAD` and `--abbrev-ref HEAD` before the
// requested revision is verified. Those commands open the six candidates for
// HEAD and for every abbreviation of the final branch. A linked worktree
// stores the branch refs in the common directory, so that directory is probed too.
async function assertGitLookups(
  gitDir: string,
  ref: string | null,
  inherited: readonly string[] = [],
  seen = new Set<string>(),
  follow: readonly SymrefFollow[] = [{ name: "HEAD", depth: 0 }],
): Promise<void> {
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
  const names = new Set<string>(["HEAD", ...inherited]);
  if (ref) {
    const base = revisionRefName(ref);
    if (base) names.add(base);
  }
  // Git reads commondir once, from the git directory the command started in.
  // A commondir inside the common directory is not a link Git follows, and the
  // shared refs on the chain are read there in place.
  const common = isStartedGitDirectory ? await linkedGitDirectory(gitDir) : null;
  const sharedRefsElsewhere = common !== null && await distinctGitDirectory(gitDir, common);
  const carry = await addSymrefAbbreviations(gitDir, names, follow, sharedRefsElsewhere);
  for (const name of names) await assertRequestedRevision(gitDir, name);
  if (common) await assertGitLookups(common, ref, [...names], seen, [{ name: "HEAD", depth: 0 }, ...carry], false);
}

async function distinctGitDirectory(left: string, right: string): Promise<boolean> {
  try {
    const [here, there] = await Promise.all([lstat(left), lstat(right)]);
    return here.dev !== there.dev || here.ino !== there.ino;
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw invalidGitMetadata();
  }
  const common = await linkedGitDirectory(gitDir);
  const finalRef = await finalHeadRef(gitDir, common ?? gitDir);
  if (finalRef) {
    names.add(finalRef);
    for (const shortName of gitShortRefNames(finalRef)) names.add(shortName);
  }
  for (const name of names) await assertRequestedRevision(gitDir, name);
  if (common) await assertGitLookups(common, ref, [...names], seen);
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
  const head = await readSmallGitText(join(gitDir, "HEAD"), 4_096, { requireUtf8: true });
  const headTarget = looseSymrefTarget(head ?? "");
  if (headTarget) await assertLooseRef(gitDir, headTarget, 0);
  const common = await linkedGitDirectory(gitDir);
  if (common) await assertGitDirectoryMetadata(common, seen);
}

// A gitfile is "gitdir: <path>". The path is relative to the file's directory.
// Git follows it and then opens metadata in that directory.
async function assertGitFileTarget(gitFilePath: string): Promise<string | null> {
  const text = await readSmallGitText(gitFilePath, 4_096, { requireUtf8: true });
  if (text === null || !text.startsWith("gitdir: ")) return null;
  const resolved = await resolveExistingGitDirectory(gitPointerTarget(dirname(gitFilePath), text.slice("gitdir: ".length)));
  if (resolved) await assertGitDirectoryMetadata(resolved);
  return resolved;
}

// A pipe or symlink named .git would block or escape before git runs. A gitfile
// is a regular file; ref imports reject it separately so worktree snapshots can
// still copy the selected files. The directory a gitfile names, including one
// found by walking parents, is checked before Git starts.
async function assertLocalGitReadable(sourceRoot: string): Promise<string | null> {
  let current = sourceRoot;
  while (true) {
    const gitPath = join(current, ".git");
    let info;
    try {
      info = await lstat(gitPath);
    } catch {
      const parent = dirname(current);
      if (parent === current) return null;
      current = parent;
      continue;
    }
    if (info.isDirectory()) {
      await assertGitDirectoryMetadata(gitPath);
      return gitPath;
    }
    if (!info.isFile()) throw invalidGitMetadata();
    return assertGitFileTarget(gitPath);
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
  const gitDirectory = await assertLocalGitReadable(sourceRoot);
  if (gitDirectory) await assertGitLookups(gitDirectory, ref);
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
