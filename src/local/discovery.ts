import { readFile, readdir, realpath, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { sha256 } from "../util.ts";
import type { McpConnection } from "./types.ts";

export type DiscoveredResource = {
  id: string; kind: "skill" | "mcp"; name: string; description: string;
  path: string; sources: string[]; fingerprint: string;
  metadata: Record<string, unknown>; connection?: McpConnection;
};
export type DiscoveryOptions = { home: string; projectRoot: string; env: Record<string, string | undefined> };
export type ScanResult = { resources: DiscoveredResource[]; roots: string[]; errors: Array<{ source: string; message: string }> };

const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const idFor = (kind: string, path: string) => sha256(`${kind}:${path}`).slice(0, 24);

function parseMcpToml(text: string): unknown {
  try { return Bun.TOML.parse(text); } catch {
    // Bun 1.3 rejects valid digit-leading bare table keys in unrelated settings.
    // Read only the MCP tables when the complete client config hits that parser limitation.
    let collecting = false;
    const lines: string[] = [];
    for (const line of text.split(/\r?\n/)) {
      if (/^\s*\[/.test(line)) collecting = /^\s*\[\s*mcp_servers(?:\.|\s*\])/.test(line);
      if (collecting) lines.push(line.replace(/^(\s*\[\s*mcp_servers\.)([0-9][A-Za-z0-9_-]*)(?=[.\]])/, '$1"$2"'));
    }
    if (lines.length === 0) throw new Error("Invalid TOML");
    return Bun.TOML.parse(lines.join("\n"));
  }
}

export async function readSmallFile(path: string, maxBytes = 256_000): Promise<string> {
  const info = await stat(path);
  if (!info.isFile() || info.size > maxBytes) throw new Error("Not a regular file or exceeds the file size limit");
  const bytes = await readFile(path);
  if (bytes.length > maxBytes || bytes.includes(0)) throw new Error("File is too large or contains binary data");
  return bytes.toString("utf8");
}

function frontmatter(content: string, key: string): string {
  const match = content.match(/^\uFEFF?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!match) return "";
  const lines = match[1]!.split(/\r?\n/);
  const index = lines.findIndex((line) => line.startsWith(`${key}:`));
  if (index < 0) return "";
  let value = lines[index]!.slice(key.length + 1).trim();
  if (/^[>|][-+]?\s*$/.test(value)) {
    const block: string[] = [];
    for (const line of lines.slice(index + 1)) {
      if (/^\S/.test(line)) break;
      block.push(line.trim());
    }
    value = block.join(" ").trim();
  }
  return value.replace(/^(['"])([\s\S]*)\1$/, "$2").slice(0, key === "name" ? 200 : 4_000);
}

function normalizedJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(normalizedJson).join(",")}]`;
  if (record(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${normalizedJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
}

function connection(raw: Record<string, unknown>, env: DiscoveryOptions["env"]): McpConnection {
  const expand = (value: unknown): string => {
    if (typeof value !== "string" || value.includes("\0")) throw new Error("Configuration contains an invalid string");
    if (value.startsWith("!")) throw new Error("Command substitutions in configuration are not supported");
    return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-)([^}]*))?\}/g, (_match, key: string, operator: string | undefined, fallback: string | undefined) => {
      const selected = env[key];
      if (selected !== undefined && (operator !== ":-" || selected !== "")) return selected;
      if (operator) return fallback ?? "";
      throw new Error(`Missing environment variable: ${key}`);
    });
  };
  const strings = (value: unknown): Record<string, string> => {
    if (value === undefined) return {};
    if (!record(value)) throw new Error("Expected a configuration object");
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, expand(item)]));
  };
  if (typeof raw.url === "string") {
    const type = raw.type === "sse" ? "sse" : "http";
    if (raw.type && !["http", "sse", "streamable-http"].includes(String(raw.type))) throw new Error("Unsupported MCP transport");
    const url = new URL(expand(raw.url));
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("MCP URL must use HTTP(S) without embedded credentials");
    const headers = { ...strings(raw.headers), ...strings(raw.http_headers) };
    if (record(raw.env_http_headers)) {
      for (const [header, key] of Object.entries(raw.env_http_headers)) {
        if (typeof key !== "string" || !env[key]) throw new Error(`Missing environment variable: ${typeof key === "string" ? key : "invalid name"}`);
        headers[header] = env[key]!;
      }
    }
    if (typeof raw.bearer_token_env_var === "string") {
      const token = env[raw.bearer_token_env_var];
      if (!token) throw new Error(`Missing environment variable: ${raw.bearer_token_env_var}`);
      headers.Authorization = `Bearer ${token}`;
    }
    if (raw.oauth || raw.auth || raw.headersHelper) throw new Error("This server requires native authentication configuration; token/header configuration is supported");
    return { type, url: url.toString(), headers };
  }
  if (raw.type && raw.type !== "stdio") throw new Error("Unsupported MCP transport");
  if (typeof raw.command !== "string" || !raw.command.trim()) throw new Error("MCP command or URL is missing");
  if (raw.args !== undefined && !Array.isArray(raw.args)) throw new Error("MCP args must be an array");
  const serverEnv = strings(raw.env);
  if (Array.isArray(raw.env_vars)) {
    for (const key of raw.env_vars) {
      if (typeof key !== "string" || env[key] === undefined) throw new Error("Missing inherited MCP environment variable");
      serverEnv[key] = env[key]!;
    }
  }
  if (raw.cwd !== undefined) throw new Error("A fixed server cwd cannot be used inside an audit workspace");
  return { type: "stdio", command: expand(raw.command), args: (raw.args ?? []).map(expand), env: serverEnv };
}

export async function discoverLocal(options: DiscoveryOptions): Promise<ScanResult> {
  const result: ScanResult = { resources: [], roots: [], errors: [] };
  const skillPaths = [
    ".agents/skills", ".codex/skills", ".claude/skills", ".pi/agent/skills", ".config/opencode/skills", ".codex/plugins/cache",
  ].map((path) => join(options.home, path));
  skillPaths.push(...[".agents/skills", ".codex/skills", ".claude/skills", ".pi/skills", "skills"].map((path) => join(options.projectRoot, path)));
  const visited = new Set<string>();
  const skillsByContent = new Map<string, DiscoveredResource>();
  let directories = 0;
  const walk = async (path: string, depth: number, source: string): Promise<void> => {
    if (depth > 9 || directories >= 5_000) return;
    let canonical: string;
    try { canonical = await realpath(path); } catch { return; }
    if (visited.has(canonical)) {
      const existing = result.resources.find((item) => item.kind === "skill" && dirname(item.path) === canonical);
      if (existing && !existing.sources.includes(source)) existing.sources.push(source);
      return;
    }
    visited.add(canonical);
    directories += 1;
    let entries;
    try { entries = await readdir(canonical, { withFileTypes: true }); } catch {
      result.errors.push({ source: path, message: "Skill directory could not be read" });
      return;
    }
    const skillFile = entries.find((entry) => entry.name === "SKILL.md" && entry.isFile());
    if (skillFile) {
      const file = join(canonical, "SKILL.md");
      try {
        const content = await readSmallFile(file);
        const name = frontmatter(content, "name") || canonical.split("/").at(-1)!;
        const fingerprint = sha256(content);
        const duplicate = skillsByContent.get(`${name}:${fingerprint}`);
        if (duplicate) { if (!duplicate.sources.includes(source)) duplicate.sources.push(source); }
        else {
          const resource: DiscoveredResource = { id: idFor("skill", file), kind: "skill", name,
            description: frontmatter(content, "description"), path: file, sources: [source], fingerprint, metadata: { error: null } };
          skillsByContent.set(`${name}:${fingerprint}`, resource);
          result.resources.push(resource);
        }
      } catch {
        const error = "SKILL.md could not be read as a text file under 256 KB";
        result.errors.push({ source: file, message: error });
        result.resources.push({ id: idFor("skill", file), kind: "skill", name: canonical.split("/").at(-1)!,
          description: "", path: file, sources: [source], fingerprint: sha256(`unreadable:${file}`), metadata: { error } });
      }
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (!["node_modules", ".git", "references", "assets", "scripts"].includes(entry.name) &&
          (!skillFile || entry.name === "skills") && (entry.isDirectory() || entry.isSymbolicLink())) {
        await walk(join(canonical, entry.name), depth + 1, source);
      }
    }
  };
  for (const root of [...new Set(skillPaths)]) { result.roots.push(root); await walk(root, 0, root); }
  if (directories >= 5_000) result.errors.push({ source: "skills", message: "Directory scan limit reached (5000)" });

  const serversByConfig = new Map<string, DiscoveredResource>();
  const addServers = (value: unknown, source: string) => {
    if (!record(value)) return;
    for (const [name, raw] of Object.entries(value).slice(0, 250)) {
      if (!record(raw)) { result.errors.push({ source, message: `Server ${name.slice(0, 100)} has an invalid definition` }); continue; }
      let config: McpConnection | undefined;
      let error: string | null = null;
      try { config = connection(raw, options.env); } catch (caught) { error = caught instanceof Error ? caught.message : "Invalid MCP configuration"; }
      const transport = config?.type ?? (raw.command ? "stdio" : raw.url ? raw.type === "sse" ? "sse" : "http" : "unsupported");
      let endpoint = transport === "stdio" ? (typeof raw.command === "string" ? raw.command.split(/\s/)[0]!.slice(0, 300) : "") : "";
      if (typeof raw.url === "string") {
        try { const url = new URL(raw.url); endpoint = url.origin; } catch { endpoint = "Invalid URL"; }
      }
      const fingerprint = sha256(normalizedJson({ config: config ?? raw, enabled: raw.enabled !== false }));
      const duplicate = serversByConfig.get(`${name}:${fingerprint}`);
      if (duplicate) { duplicate.sources.push(source); continue; }
      const resource: DiscoveredResource = { id: idFor("mcp", `${source}:${name}`), kind: "mcp", name: name.slice(0, 200),
        description: typeof raw.description === "string" ? raw.description.slice(0, 2_000) : "",
        path: source, sources: [source], fingerprint,
        metadata: { transport, endpoint, source_enabled: raw.enabled !== false, error }, connection: config };
      serversByConfig.set(`${name}:${fingerprint}`, resource);
      result.resources.push(resource);
    }
  };
  const configs = [
    join(options.home, ".pi/agent/mcp.json"), join(options.home, ".claude.json"),
    join(options.home, ".claude/mcp.json"), join(options.home, ".config/claude/claude_desktop_config.json"),
    join(options.home, ".codex/config.toml"), join(options.projectRoot, ".mcp.json"),
    join(options.projectRoot, ".pi/mcp.json"), join(options.projectRoot, ".codex/config.toml"),
  ];
  for (const path of [...new Set(configs)]) {
    result.roots.push(path);
    let text: string;
    try { text = await readSmallFile(path, 2_000_000); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") result.errors.push({ source: path, message: "MCP config is unreadable or exceeds 2 MB" });
      continue;
    }
    try {
      const parsed: unknown = path.endsWith(".toml") ? parseMcpToml(text) : JSON.parse(text);
      if (!record(parsed)) throw new Error("Invalid configuration root");
      addServers(parsed.mcpServers ?? parsed.mcp_servers, path);
      if (record(parsed.projects)) {
        for (const [projectPath, value] of Object.entries(parsed.projects)) {
          const root = resolve(projectPath);
          if (record(value) && (options.projectRoot === root || options.projectRoot.startsWith(`${root}/`))) {
            addServers(value.mcpServers, `${path}#${root}`);
          }
        }
      }
    } catch { result.errors.push({ source: path, message: `Invalid ${path.endsWith(".toml") ? "TOML" : "JSON"} MCP configuration` }); }
  }
  return result;
}
