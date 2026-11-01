import { cp, lstat, mkdir, readdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { extname, join, relative, resolve } from "node:path";
import { badRequest, createScopeMatcher, isInside, normalizePath, sha256, toJson, truncate } from "../util.ts";
import type { Scope } from "../util.ts";

export const DEFAULT_EXCLUDES = [
  ".git/**",
  "node_modules/**",
  "vendor/**",
  "dist/**",
  "build/**",
  "out/**",
  "coverage/**",
  "target/**",
  ".next/**",
  ".nuxt/**",
  "**/node_modules/**",
  "**/vendor/**",
  "**/dist/**",
  "**/build/**",
  "**/out/**",
  "**/coverage/**",
  "**/target/**",
  "**/.next/**",
  "**/.nuxt/**",
  "**/*.min.js",
  "**/*.map",
  "**/*.lock",
  "**/*.svg",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.ico",
  "**/*.pdf",
  "**/*.zip",
  "**/*.gz",
  "**/*.woff*",
  "**/*.ttf",
  "**/*.so",
  "**/*.dll",
  "**/*.exe",
  "**/*.bin",
  "**/.env",
  "**/.env.*",
];

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".js": "JavaScript",
  ".mjs": "JavaScript",
  ".cjs": "JavaScript",
  ".jsx": "JavaScript",
  ".ts": "TypeScript",
  ".mts": "TypeScript",
  ".cts": "TypeScript",
  ".tsx": "TypeScript",
  ".go": "Go",
  ".py": "Python",
  ".rb": "Ruby",
  ".php": "PHP",
  ".java": "Java",
  ".kt": "Kotlin",
  ".kts": "Kotlin",
  ".scala": "Scala",
  ".cs": "C#",
  ".fs": "F#",
  ".c": "C",
  ".h": "C",
  ".cc": "C++",
  ".cpp": "C++",
  ".hpp": "C++",
  ".rs": "Rust",
  ".swift": "Swift",
  ".m": "Objective-C",
  ".sql": "SQL",
  ".md": "Markdown",
  ".txt": "Text",
  ".sh": "Shell",
  ".bash": "Shell",
  ".ps1": "PowerShell",
  ".vue": "Vue",
  ".svelte": "Svelte",
  ".html": "HTML",
  ".htm": "HTML",
  ".css": "CSS",
  ".scss": "CSS",
  ".yml": "YAML",
  ".yaml": "YAML",
  ".json": "JSON",
  ".toml": "TOML",
  ".xml": "XML",
  ".tf": "HCL",
  ".proto": "Protobuf",
};

const TEXT_EXTENSIONS = new Set(Object.keys(LANGUAGE_BY_EXT).filter((ext) => ext !== ".sql"));

export type RepoFile = {
  path: string;
  size: number;
  lines: number;
  language: string;
  sha256: string;
};

export type Endpoint = {
  method: string;
  path: string;
  file: string;
  line: number;
};

export type AuthBoundary = {
  kind: string;
  file: string;
  line: number;
  detail: string;
};

export type DependencyEdge = { from: string; to: string };

export type Inventory = {
  files: RepoFile[];
  skipped: Array<{ path: string; reason: string }>;
  languages: Record<string, number>;
  frameworks: string[];
  endpoints: Endpoint[];
  auth_boundaries: AuthBoundary[];
  dependency_graph: DependencyEdge[];
  entrypoints: string[];
  total_bytes: number;
  truncated: boolean;
};

export function languageFor(path: string): string {
  return LANGUAGE_BY_EXT[extname(path).toLowerCase()] ?? "Other";
}

export function isTextFile(path: string): boolean {
  return TEXT_EXTENSIONS.has(extname(path).toLowerCase());
}

export function clampText(value: unknown, max = 4000): string {
  return truncate(typeof value === "string" ? value : "", max);
}

const GIT_ESCAPE = "The repository's git directory is outside the authorized repository";

const GIT_ENV = (): Record<string, string> => ({
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});

async function runGit(path: string, args: string[]): Promise<string | null> {
  try {
    const proc = Bun.spawn(["git", ...args], {
      cwd: path,
      stdout: "pipe",
      stderr: "ignore",
      env: GIT_ENV(),
    });
    const [output, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
    return code === 0 ? output.trim() : null;
  } catch {
    return null;
  }
}

async function lstatOrNull(path: string) {
  try {
    return await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw badRequest(GIT_ESCAPE);
  }
}

/**
 * Git follows symlinks and special files inside the git directory when it
 * opens refs, packs, and loose objects. Reject the whole tree instead of
 * trusting the resolved directory path alone.
 */
async function assertSafeTree(directory: string): Promise<void> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    throw badRequest(GIT_ESCAPE);
  }
  for (const entry of entries) {
    const absolute = join(directory, entry.name);
    const stats = await lstatOrNull(absolute);
    if (!stats || stats.isSymbolicLink()) throw badRequest(GIT_ESCAPE);
    if (stats.isDirectory()) {
      await assertSafeTree(absolute);
    } else if (!stats.isFile()) {
      throw badRequest(GIT_ESCAPE);
    }
  }
}

/**
 * Resolve the git directory git would use for `path` and canonicalize it.
 * Git honours a `.git` file containing a `gitdir:` pointer, so callers must
 * contain the result before trusting it: a hand-off directory inside an
 * authorized root can otherwise redirect git at any repository on the host.
 */
export async function resolveGitDirectory(path: string): Promise<string | null> {
  const output = await runGit(path, ["rev-parse", "--absolute-git-dir"]);
  if (!output) return null;
  try {
    return await realpath(output);
  } catch {
    return null;
  }
}

/**
 * Worktree-style git directories redirect object and ref lookup through a
 * `commondir` file. Canonicalize that indirection too, because a git directory
 * that passes the root check can still point its object store elsewhere. A
 * normal repository has no `commondir` file and is its own common directory.
 */
export async function resolveGitCommonDirectory(gitDirectory: string): Promise<string | null> {
  let stats;
  try {
    stats = await lstat(join(gitDirectory, "commondir"));
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? gitDirectory : null;
  }
  if (!stats.isFile()) return null;
  let content: string;
  try {
    content = await readFile(join(gitDirectory, "commondir"), "utf8");
  } catch {
    return null;
  }
  try {
    const target = content.trim();
    return await realpath(target ? resolve(gitDirectory, target) : gitDirectory);
  } catch {
    return null;
  }
}

async function gitConfigValue(commonDirectory: string, key: string): Promise<string | null> {
  const value = await runGit(commonDirectory, [
    `--git-dir=${commonDirectory}`,
    "config",
    "--local",
    "--no-includes",
    "--get",
    key,
  ]);
  return value || null;
}

async function assertSafeGitMetadata(gitDirectory: string, commonDirectory: string): Promise<void> {
  const head = await lstatOrNull(join(gitDirectory, "HEAD"));
  if (!head || !head.isFile()) throw badRequest(GIT_ESCAPE);
  for (const name of ["commondir", "shallow"]) {
    const stats = await lstatOrNull(join(gitDirectory, name));
    if (stats && !stats.isFile()) throw badRequest(GIT_ESCAPE);
  }
  for (const name of ["packed-refs", "config"]) {
    const stats = await lstatOrNull(join(commonDirectory, name));
    if (stats && !stats.isFile()) throw badRequest(GIT_ESCAPE);
  }
  for (const name of ["refs", "reftable"]) {
    const stats = await lstatOrNull(join(commonDirectory, name));
    if (!stats) continue;
    if (!stats.isDirectory()) throw badRequest(GIT_ESCAPE);
    await assertSafeTree(join(commonDirectory, name));
  }
}

async function assertSafeObjectStore(objectDirectory: string, sourceRoot: string): Promise<string> {
  const stats = await lstatOrNull(objectDirectory);
  if (!stats || !stats.isDirectory()) throw badRequest(GIT_ESCAPE);
  await assertSafeTree(objectDirectory);
  // An alternates file names another object store that git would read from.
  for (const name of ["alternates", "http-alternates"]) {
    if (await lstatOrNull(join(objectDirectory, "info", name))) throw badRequest(GIT_ESCAPE);
  }
  const resolved = await realpath(objectDirectory).catch(() => null);
  if (!resolved || !isInside(sourceRoot, resolved)) throw badRequest(GIT_ESCAPE);
  return resolved;
}

/**
 * Build a private, self-contained git metadata directory for import. The
 * audited repository keeps ownership of its object store, refs, and config,
 * so git must never read them through paths the auditor can rewrite after
 * validation (a `commondir` swap) or through symlinks inside them.
 */
export async function preparePrivateGitDirectory(
  layout: { gitDirectory: string; commonDirectory: string },
  options: { sourceRoot: string; staging: string; includeObjects: boolean },
): Promise<{ gitDirectory: string; objectDirectory: string | null }> {
  await assertSafeGitMetadata(layout.gitDirectory, layout.commonDirectory);
  const objectDirectory = options.includeObjects
    ? await assertSafeObjectStore(join(layout.commonDirectory, "objects"), options.sourceRoot)
    : null;
  // Copy only the repository format details import needs. No audited config,
  // include.path, or config.worktree entry reaches the later git commands.
  const formatVersion = await gitConfigValue(layout.commonDirectory, "core.repositoryformatversion");
  const objectFormat = (await gitConfigValue(layout.commonDirectory, "extensions.objectformat"))?.toLowerCase() ?? null;
  const refStorage = (await gitConfigValue(layout.commonDirectory, "extensions.refstorage"))?.toLowerCase() ?? null;
  if (formatVersion !== null && !/^[01]$/.test(formatVersion)) throw badRequest(GIT_ESCAPE);
  if (objectFormat !== null && objectFormat !== "sha1" && objectFormat !== "sha256") throw badRequest(GIT_ESCAPE);
  if (refStorage !== null && refStorage !== "files" && refStorage !== "reftable") throw badRequest(GIT_ESCAPE);
  const version = formatVersion === "1" || objectFormat === "sha256" || refStorage === "reftable" ? 1 : 0;

  const privateDirectory = join(options.staging, "gitdir");
  await mkdir(privateDirectory, { recursive: true, mode: 0o700 });
  await mkdir(join(privateDirectory, "objects"), { mode: 0o700 });
  await cp(join(layout.gitDirectory, "HEAD"), join(privateDirectory, "HEAD"), { force: true });
  for (const name of ["refs", "packed-refs", "reftable"]) {
    const source = join(layout.commonDirectory, name);
    const stats = await lstatOrNull(source);
    if (!stats) continue;
    if (stats.isDirectory()) {
      await cp(source, join(privateDirectory, name), { recursive: true, force: true, dereference: false });
    } else if (stats.isFile()) {
      await cp(source, join(privateDirectory, name), { force: true, dereference: false });
    } else {
      throw badRequest(GIT_ESCAPE);
    }
  }
  // The staging directory is private (0700); reject any symlink that appeared
  // in the audited tree while it was being copied into it.
  await assertSafeTree(privateDirectory);
  const extensions: string[] = [];
  if (objectFormat === "sha256") extensions.push("\tobjectformat = sha256");
  if (refStorage === "reftable") extensions.push("\trefstorage = reftable");
  const config = ["[core]", `\trepositoryformatversion = ${version}`];
  if (extensions.length > 0) config.push("[extensions]", ...extensions);
  await writeFile(join(privateDirectory, "config"), `${config.join("\n")}\n`, { mode: 0o600 });
  return { gitDirectory: privateDirectory, objectDirectory };
}

export async function gitInfoForDirectory(
  privateGitDirectory: string,
): Promise<{ commit: string | null; branch: string | null }> {
  const run = (args: string[]): Promise<string | null> =>
    runGit(privateGitDirectory, [`--git-dir=${privateGitDirectory}`, ...args]);
  const [commit, branch] = await Promise.all([
    run(["rev-parse", "HEAD"]),
    run(["rev-parse", "--abbrev-ref", "HEAD"]),
  ]);
  return { commit: commit || null, branch: branch || null };
}

export async function gitInfo(
  path: string,
  gitDirectory?: string | null,
): Promise<{ commit: string | null; branch: string | null }> {
  let root: string;
  try {
    root = await realpath(path);
  } catch {
    return { commit: null, branch: null };
  }
  const resolvedGitDirectory = gitDirectory === undefined ? await resolveGitDirectory(path) : gitDirectory;
  // Only report repository metadata when git stays inside the audited root.
  // Otherwise a `.git` pointer (or a parent repository found by discovery)
  // would attribute an unrelated commit to this worktree import. The worktree
  // `commondir` indirection must stay inside that root too.
  if (resolvedGitDirectory === null || !isInside(root, resolvedGitDirectory)) {
    return { commit: null, branch: null };
  }
  const commonDirectory = await resolveGitCommonDirectory(resolvedGitDirectory);
  if (commonDirectory === null || !isInside(root, commonDirectory)) {
    return { commit: null, branch: null };
  }
  return gitInfoForDirectory(resolvedGitDirectory);
}

export type InventoryOptions = {
  scope: Scope;
  maxFiles: number;
  maxFileBytes: number;
};

export async function buildInventory(root: string, options: InventoryOptions): Promise<Inventory> {
  const scopeMatcher = createScopeMatcher(options.scope);
  const files: RepoFile[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];
  const languages: Record<string, number> = {};
  let totalBytes = 0;
  let truncated = false;

  const visit = async (directory: string): Promise<void> => {
    if (files.length >= options.maxFiles) {
      truncated = true;
      return;
    }
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name === ".git") continue;
      const absolute = join(directory, entry.name);
      const rel = normalizePath(relative(root, absolute));
      if (entry.isSymbolicLink()) {
        skipped.push({ path: rel, reason: "symlink" });
        continue;
      }
      if (entry.isDirectory()) {
        const directoryExcluded = scopeMatcher.excludes(`${rel}/argus-probe`);
        if (!directoryExcluded) await visit(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      if (rel === "ARGUS_SCOPE.json") continue;
      if (!scopeMatcher.matches(rel)) continue;
      if (files.length >= options.maxFiles) {
        truncated = true;
        break;
      }
      const stats = await stat(absolute);
      if (stats.size > options.maxFileBytes) {
        skipped.push({ path: rel, reason: `larger than ${options.maxFileBytes} bytes` });
        continue;
      }
      let content: Buffer;
      try {
        content = Buffer.from(await readFile(absolute));
      } catch {
        skipped.push({ path: rel, reason: "unreadable" });
        continue;
      }
      const language = languageFor(rel);
      const text = isTextFile(rel) ? content.toString("utf8") : "";
      const lineCount = text ? text.split("\n").length : 0;
      files.push({
        path: rel,
        size: stats.size,
        lines: lineCount,
        language,
        sha256: sha256(content),
      });
      languages[language] = (languages[language] ?? 0) + 1;
      totalBytes += stats.size;
    }
  };

  await visit(root);
  const textByPath = new Map<string, string>();
  for (const file of files) {
    if (!isTextFile(file.path)) continue;
    try {
      textByPath.set(file.path, await readFile(join(root, file.path), "utf8"));
    } catch {
      // File changed between listing and read; the hash in the inventory is authoritative.
    }
  }

  return {
    files,
    skipped,
    languages,
    frameworks: detectFrameworks(textByPath),
    endpoints: extractEndpoints(textByPath),
    auth_boundaries: extractAuthBoundaries(textByPath),
    dependency_graph: extractDependencyGraph(textByPath),
    entrypoints: detectEntrypoints(files),
    total_bytes: totalBytes,
    truncated,
  };
}

function detectFrameworks(textByPath: Map<string, string>): string[] {
  const found = new Set<string>();
  const addFrom = (path: string, checks: Array<[string, string]>) => {
    const text = textByPath.get(path);
    if (!text) return;
    for (const [needle, label] of checks) {
      if (text.includes(needle)) found.add(label);
    }
  };
  addFrom("package.json", [
    ["\"express\"", "Express"],
    ["\"fastify\"", "Fastify"],
    ["\"koa\"", "Koa"],
    ["\"@nestjs/core\"", "NestJS"],
    ["\"next\"", "Next.js"],
    ["\"react\"", "React"],
    ["\"vue\"", "Vue"],
    ["\"@angular/core\"", "Angular"],
    ["\"@prisma/client\"", "Prisma"],
    ["\"sequelize\"", "Sequelize"],
    ["\"typeorm\"", "TypeORM"],
    ["\"knex\"", "Knex"],
    ["\"graphql\"", "GraphQL"],
    ["\"jsonwebtoken\"", "JWT"],
    ["\"passport\"", "Passport"],
  ]);
  addFrom("go.mod", [
    ["gin-gonic/gin", "Gin"],
    ["gorilla/mux", "gorilla/mux"],
    ["labstack/echo", "Echo"],
    ["gofiber/fiber", "Fiber"],
    ["gorm.io/gorm", "GORM"],
    ["database/sql", "Go database/sql"],
  ]);
  addFrom("requirements.txt", [
    ["Django", "Django"],
    ["Flask", "Flask"],
    ["fastapi", "FastAPI"],
    ["SQLAlchemy", "SQLAlchemy"],
  ]);
  addFrom("pyproject.toml", [
    ["django", "Django"],
    ["flask", "Flask"],
    ["fastapi", "FastAPI"],
    ["sqlalchemy", "SQLAlchemy"],
  ]);
  addFrom("composer.json", [
    ["laravel/framework", "Laravel"],
    ["symfony/", "Symfony"],
  ]);
  addFrom("Gemfile", [
    ["rails", "Ruby on Rails"],
    ["sinatra", "Sinatra"],
  ]);
  addFrom("pom.xml", [
    ["spring-boot", "Spring Boot"],
    ["springframework", "Spring"],
  ]);
  return [...found].sort();
}

function lineNumber(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function extractEndpoints(textByPath: Map<string, string>): Endpoint[] {
  const results: Endpoint[] = [];
  const seen = new Set<string>();
  const patterns: Array<{ language: RegExp; method: number; path: number }> = [
    {
      language: /(?:app|router|server|api)\.(get|post|put|patch|delete|all|use)\(\s*["'`]([^"'`]+)["'`]/gi,
      method: 1,
      path: 2,
    },
    {
      language: /@(?:app|router|bp|blueprint)\.(get|post|put|patch|delete|route)\(\s*["']([^"']+)["']/gi,
      method: 1,
      path: 2,
    },
    {
      language: /\.(HandleFunc|Handle)\(\s*"([^"]+)"/g,
      method: 1,
      path: 2,
    },
    {
      language: /@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g,
      method: 1,
      path: 2,
    },
    {
      language: /Route::(get|post|put|patch|delete|any)\(\s*["']([^"']+)["']/gi,
      method: 1,
      path: 2,
    },
  ];
  for (const [file, text] of textByPath) {
    if (text.length > 900_000) continue;
    for (const pattern of patterns) {
      pattern.language.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.language.exec(text)) !== null) {
        let method = match[pattern.method]?.toUpperCase() ?? "ROUTE";
        if (method === "HANDLE" || method === "HANDLEFUNC" || method === "REQUESTMAPPING") method = "ANY";
        if (method === "ROUTE") method = "GET";
        const route = match[pattern.path] ?? "";
        if (!route.startsWith("/")) continue;
        const key = `${method} ${route} ${file}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push({ method, path: route, file, line: lineNumber(text, match.index) });
        if (results.length >= 500) return results;
      }
    }
  }
  return results;
}

function extractAuthBoundaries(textByPath: Map<string, string>): AuthBoundary[] {
  const boundaries: AuthBoundary[] = [];
  const patterns: Array<{ regex: RegExp; kind: string; detail: string }> = [
    { regex: /\b(authenticate|authorize|requireAuth|isAuthenticated|ensureLoggedIn)\b/g, kind: "middleware", detail: "Authentication middleware reference" },
    { regex: /\b(jwt\.verify|jsonwebtoken|verifyToken|decodeToken)\b/g, kind: "token", detail: "JWT verification" },
    { regex: /\b(passport\.|strategies?\b|OAuth2?|SAML)\b/g, kind: "identity", detail: "Identity provider integration" },
    { regex: /\b(hasRole|hasPermission|can\(|@PreAuthorize|@Secured|authorize\()/g, kind: "authorization", detail: "Authorization check" },
    { regex: /\b(session\[|req\.session|cookies?\.|getSession)\b/g, kind: "session", detail: "Session state access" },
    { regex: /\b(tenant_id|tenantId|org_id|organizationId|owner_id|userId\s*[!=]==?\s*)/g, kind: "tenancy", detail: "Tenant or ownership boundary reference" },
  ];
  for (const [file, text] of textByPath) {
    if (text.length > 600_000) continue;
    if (!/auth|login|session|permission|role|tenant|user/i.test(text)) continue;
    for (const pattern of patterns) {
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(text);
      if (!match) continue;
      boundaries.push({ kind: pattern.kind, file, line: lineNumber(text, match.index), detail: pattern.detail });
      if (boundaries.length >= 250) return boundaries;
    }
  }
  return boundaries;
}

function extractDependencyGraph(textByPath: Map<string, string>): DependencyEdge[] {
  const edges: DependencyEdge[] = [];
  const seen = new Set<string>();
  const known = new Set(textByPath.keys());
  const stemIndex = new Map<string, string>();
  for (const path of known) {
    const stem = path.replace(/\.(js|mjs|cjs|jsx|ts|mts|cts|tsx|py|go|rb|php|java|kt|cs|rs)$/, "");
    stemIndex.set(stem, path);
    stemIndex.set(`${stem}/index`, path);
  }
  const resolveImport = (from: string, specifier: string): string | null => {
    if (specifier.startsWith(".")) {
      const base = normalizePath(join(from, "..", specifier));
      const clean = base.replace(/\.[a-z]+$/, "");
      return stemIndex.get(base) ?? stemIndex.get(clean) ?? null;
    }
    if (specifier.includes("/") && known.has(specifier)) return specifier;
    return null;
  };
  for (const [file, text] of textByPath) {
    if (text.length > 500_000) continue;
    const imports = new Set<string>();
    let match: RegExpExecArray | null;
    const jsFrom = /\bfrom\s+["']([^"']+)["']/g;
    while ((match = jsFrom.exec(text)) !== null) imports.add(match[1]!);
    const jsRequire = /\brequire\(\s*["']([^"']+)["']\s*\)/g;
    while ((match = jsRequire.exec(text)) !== null) imports.add(match[1]!);
    const py = /^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/gm;
    while ((match = py.exec(text)) !== null) imports.add((match[1] ?? match[2] ?? "").replaceAll(".", "/"));
    for (const specifier of imports) {
      const target = resolveImport(file, specifier);
      if (!target || target === file) continue;
      const key = `${file}->${target}`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({ from: file, to: target });
      if (edges.length >= 4000) return edges;
    }
  }
  return edges;
}

function detectEntrypoints(files: RepoFile[]): string[] {
  const names = new Set([
    "main.go",
    "server.ts",
    "server.js",
    "app.ts",
    "app.js",
    "index.ts",
    "index.js",
    "main.py",
    "app.py",
    "manage.py",
    "main.rb",
    "index.php",
    "Program.cs",
    "main.rs",
  ]);
  return files
    .filter((file) => names.has(file.path.split("/").pop() ?? ""))
    .slice(0, 40)
    .map((file) => file.path);
}

export function inventorySummary(inventory: Inventory): string {
  const languageList = Object.entries(inventory.languages)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([language, count]) => `${language} (${count})`)
    .join(", ");
  return [
    `${inventory.files.length} files, ${(inventory.total_bytes / 1024).toFixed(1)} KiB`,
    languageList ? `languages: ${languageList}` : "no recognized languages",
    inventory.frameworks.length ? `frameworks: ${inventory.frameworks.join(", ")}` : "no framework detected",
    `${inventory.endpoints.length} endpoints, ${inventory.auth_boundaries.length} auth boundary signals`,
  ].join("; ");
}

export function inventoryForAgent(inventory: Inventory): string {
  const files = inventory.files
    .slice(0, 400)
    .map((file) => `${file.path} (${file.language}, ${file.lines} lines)`)
    .join("\n");
  return toJson({
    summary: inventorySummary(inventory),
    languages: inventory.languages,
    frameworks: inventory.frameworks,
    entrypoints: inventory.entrypoints,
    endpoints: inventory.endpoints.slice(0, 200),
    auth_boundaries: inventory.auth_boundaries.slice(0, 100),
    files: files || "(no files)",
    truncated: inventory.truncated || inventory.files.length > 400,
  });
}
