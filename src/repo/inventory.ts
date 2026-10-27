import { readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { runCommand } from "../harness/process.ts";
import { createScopeMatcher, normalizePath, sha256, toJson, truncate } from "../util.ts";
import type { Scope } from "../util.ts";
import { canonicalDirectory, readCappedRegularFile } from "./workspace.ts";

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
  ".env",
  ".env.*",
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

// Repository config can point core.excludesFile and core.attributesFile at a
// fifo. Git opens that path from every command that reads the config. Force
// both settings at the command line so the fifo is never opened.
// --no-replace-objects keeps refs/replace from substituting another object for
// the commit being archived. Without it, archive can store different bytes
// than that commit while rev-parse still prints the original commit id.
const GIT_CONFIG_OVERRIDES = ["-c", "core.excludesFile=/dev/null", "-c", "core.attributesFile=/dev/null"] as const;

export function gitArgv(args: readonly string[]): string[] {
  return ["git", "--no-replace-objects", ...GIT_CONFIG_OVERRIDES, ...args];
}

export async function gitInfo(path: string): Promise<{ commit: string | null; branch: string | null }> {
  const run = async (args: string[]): Promise<string | null> => {
    try {
      const result = await runCommand(gitArgv(args), {
        cwd: path,
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
        timeoutMs: 15_000,
      });
      if (result.timedOut || result.code !== 0) return null;
      return result.stdout.trim() || null;
    } catch {
      return null;
    }
  };
  const [commit, branch] = await Promise.all([
    run(["rev-parse", "HEAD"]),
    run(["rev-parse", "--abbrev-ref", "HEAD"]),
  ]);
  return { commit: commit || null, branch: branch || null };
}

export type InventoryOptions = {
  scope: Scope;
  maxFiles: number;
  maxFileBytes: number;
};

export async function buildInventory(root: string, options: InventoryOptions): Promise<Inventory> {
  const scopeMatcher = createScopeMatcher(options.scope);
  const rootReal = await canonicalDirectory(root);
  const files: RepoFile[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];
  const languages: Record<string, number> = {};
  const textByPath = new Map<string, string>();
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
      const rel = normalizePath(relative(rootReal, absolute));
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
      let opened: { size: number; bytes: Buffer; truncated: boolean };
      try {
        opened = await readCappedRegularFile(absolute, options.maxFileBytes, {
          root: rootReal,
          relativePath: rel,
        });
      } catch {
        skipped.push({ path: rel, reason: "unreadable" });
        continue;
      }
      if (opened.truncated) {
        skipped.push({ path: rel, reason: `larger than ${options.maxFileBytes} bytes` });
        continue;
      }
      const content = opened.bytes;
      const language = languageFor(rel);
      const text = isTextFile(rel) ? content.toString("utf8") : "";
      const lineCount = text ? text.split("\n").length : 0;
      files.push({
        path: rel,
        size: opened.size,
        lines: lineCount,
        language,
        sha256: sha256(content),
      });
      if (text) textByPath.set(rel, text);
      languages[language] = (languages[language] ?? 0) + 1;
      totalBytes += opened.size;
    }
  };

  await visit(rootReal);

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
