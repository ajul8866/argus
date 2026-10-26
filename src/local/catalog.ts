import { readdir, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import type { Store } from "../db/index.ts";
import { AppError, badRequest, now, parseJson, safeJoin, toJson } from "../util.ts";
import { discoverLocal, readSmallFile, type DiscoveryOptions } from "./discovery.ts";
import { mcpServerKey, type CatalogView, type LocalMcp, type LocalSkill, type McpConnection, type ResourceCall, type ResourceKind, type ResourceStats, type ResourceUsageContext, type SessionResources } from "./types.ts";

type ResourceRow = {
  id: string; kind: ResourceKind; name: string; description: string; path: string;
  sources: string; metadata: string; present: number; enabled: number; roles: string; mcp_ids: string;
};
const emptyStats = (): ResourceStats => ({ total_calls: 0, tasks_covered: 0, last_call: null });
const privateFile = (path: string): boolean => path.split(/[\\/]/).some((part) =>
  /^\.env(?:\.|$)/i.test(part) ||
  /^(?:\.npmrc|\.netrc|\.pypirc|\.git-credentials)$/i.test(part) ||
  /^(?:auth|credentials|secrets)(?:\.(?:json|ya?ml|toml|ini|conf))?$/i.test(part) ||
  /^id_(?:rsa|dsa|ecdsa|ed25519)$/i.test(part) ||
  /\.(?:pem|key|p12|pfx)$/i.test(part)
);

export class LocalCatalog {
  private readonly options: DiscoveryOptions;
  private readonly refreshMs: number;
  private connections = new Map<string, McpConnection>();
  private scan: CatalogView["scan"] = { scanned_at: null, roots: [], errors: [] };
  private refreshedAt = 0;
  private refreshing: Promise<CatalogView> | null = null;

  constructor(private readonly store: Store, options: Partial<DiscoveryOptions> & { refreshMs?: number } = {}) {
    this.options = {
      home: resolve(options.home ?? homedir()),
      projectRoot: resolve(options.projectRoot ?? join(import.meta.dir, "../..")),
      env: options.env ?? process.env,
    };
    this.refreshMs = options.refreshMs ?? 15_000;
  }

  async refresh(force = false): Promise<CatalogView> {
    if (this.refreshing) return this.refreshing;
    if (!force && this.scan.scanned_at && Date.now() - this.refreshedAt < this.refreshMs) return this.list();
    const operation = this.scanLocal();
    this.refreshing = operation;
    try { return await operation; } finally { this.refreshing = null; }
  }

  private async scanLocal(): Promise<CatalogView> {
    const result = await discoverLocal(this.options);
    const timestamp = now();
    const connections = new Map<string, McpConnection>();
    this.store.transaction(() => {
      this.store.run("UPDATE local_resources SET present = 0");
      for (const item of result.resources) {
        this.store.run(
          `INSERT INTO local_resources (id, kind, name, description, path, sources, metadata, fingerprint, present, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
           ON CONFLICT(id) DO UPDATE SET name = excluded.name, description = excluded.description,
             path = excluded.path, sources = excluded.sources, metadata = excluded.metadata,
             fingerprint = excluded.fingerprint, present = 1, last_seen_at = excluded.last_seen_at`,
          item.id, item.kind, item.name, item.description, item.path, toJson(item.sources), toJson(item.metadata), item.fingerprint, timestamp,
        );
        if (item.connection) connections.set(item.id, item.connection);
      }
    });
    this.connections = connections;
    this.scan = { scanned_at: timestamp, roots: result.roots, errors: result.errors };
    this.refreshedAt = Date.now();
    return this.list();
  }

  list(): CatalogView {
    const statistics = new Map(this.store.all<ResourceStats & { resource_kind: ResourceKind; resource_id: string }>(
      `SELECT resource_kind, resource_id, COUNT(*) AS total_calls, COUNT(DISTINCT task_id) AS tasks_covered,
              MAX(created_at) AS last_call FROM local_resource_usage GROUP BY resource_kind, resource_id`,
    ).map((row) => [`${row.resource_kind}:${row.resource_id}`, row]));
    const skills: LocalSkill[] = [];
    const servers: LocalMcp[] = [];
    for (const row of this.store.all<ResourceRow>("SELECT * FROM local_resources ORDER BY name COLLATE NOCASE, id")) {
      const metadata = parseJson<Record<string, unknown>>(row.metadata, {});
      const counts = statistics.get(`${row.kind}:${row.id}`) ?? emptyStats();
      const stats = { total_calls: counts.total_calls, tasks_covered: counts.tasks_covered, last_call: counts.last_call };
      const base = { id: row.id, name: row.name, description: row.description, sources: parseJson<string[]>(row.sources, []),
        present: Boolean(row.present), enabled: Boolean(row.enabled), error: typeof metadata.error === "string" ? metadata.error : null, stats };
      if (row.kind === "skill") {
        skills.push({ ...base, path: row.path, roles: parseJson<string[]>(row.roles, []), mcp_ids: parseJson<string[]>(row.mcp_ids, []) });
      } else {
        servers.push({ ...base, transport: String(metadata.transport ?? "unsupported") as LocalMcp["transport"],
          endpoint: String(metadata.endpoint ?? ""), source_enabled: metadata.source_enabled !== false });
      }
    }
    const roles = this.store.all<{ role: string; label: string; enabled: number }>("SELECT role, label, enabled FROM agent_defs ORDER BY rowid")
      .map((role) => ({ ...role, enabled: Boolean(role.enabled) }));
    return { skills, servers, roles, scan: this.scan };
  }

  private resource(id: string, kind: ResourceKind): ResourceRow {
    const row = this.store.get<ResourceRow>("SELECT * FROM local_resources WHERE id = ? AND kind = ?", id, kind);
    if (!row) throw new AppError(404, "resource_not_found", "Local resource not found");
    return row;
  }

  setSkillAccess(id: string, input: { enabled: boolean; roles: string[]; mcp_ids: string[] }): LocalSkill {
    this.resource(id, "skill");
    if (typeof input.enabled !== "boolean" || !Array.isArray(input.roles) || !Array.isArray(input.mcp_ids) ||
        [...input.roles, ...input.mcp_ids].some((entry) => typeof entry !== "string")) throw badRequest("Invalid skill access configuration");
    if (input.roles.length > 20 || input.mcp_ids.length > 100) throw badRequest("Too many role or MCP assignments");
    const roles = [...new Set(input.roles)];
    const servers = [...new Set(input.mcp_ids)];
    for (const role of roles) {
      if (!this.store.get("SELECT role FROM agent_defs WHERE role = ?", role)) throw badRequest(`Unknown agent role: ${role.slice(0, 100)}`);
    }
    for (const server of servers) this.resource(server, "mcp");
    this.store.run("UPDATE local_resources SET enabled = ?, roles = ?, mcp_ids = ? WHERE id = ?", input.enabled ? 1 : 0, toJson(roles), toJson(servers), id);
    return this.list().skills.find((skill) => skill.id === id)!;
  }

  setServerEnabled(id: string, enabled: boolean): LocalMcp {
    this.resource(id, "mcp");
    if (typeof enabled !== "boolean") throw badRequest("enabled must be a boolean");
    this.store.run("UPDATE local_resources SET enabled = ? WHERE id = ?", enabled ? 1 : 0, id);
    return this.list().servers.find((server) => server.id === id)!;
  }

  private async skillRoot(id: string): Promise<string> {
    const row = this.resource(id, "skill");
    if (!row.present) throw new AppError(409, "skill_missing", "This skill is no longer present locally");
    const canonical = await realpath(row.path);
    if (canonical !== row.path) throw new AppError(403, "skill_path_changed", "The discovered skill path changed; rescan before reading");
    return dirname(canonical);
  }

  async readSkillFile(id: string, path: string): Promise<{ path: string; content: string }> {
    if (privateFile(path)) throw new AppError(403, "private_skill_file", "Credential files are excluded from skill resources");
    const root = await this.skillRoot(id);
    const target = safeJoin(root, path);
    const canonical = await realpath(target);
    if (canonical !== target || !canonical.startsWith(`${root}/`)) throw new AppError(403, "skill_file_outside_root", "Skill files must remain inside the discovered directory without symlinks");
    return { path: relative(root, canonical), content: await readSmallFile(canonical) };
  }

  async skillDetail(id: string): Promise<{ skill: LocalSkill; files: string[] }> {
    const root = await this.skillRoot(id);
    const files: string[] = [];
    const walk = async (directory: string, depth: number): Promise<void> => {
      if (depth > 8 || files.length >= 512) return;
      const entries = await readdir(directory, { withFileTypes: true });
      for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
        if (files.length >= 512) break;
        if (["node_modules", ".git"].includes(entry.name) || privateFile(entry.name) || entry.isSymbolicLink()) continue;
        const path = join(directory, entry.name);
        if (entry.isDirectory()) await walk(path, depth + 1);
        else if (entry.isFile() && (await stat(path)).size <= 256_000) files.push(relative(root, path));
      }
    };
    await walk(root, 0);
    const skill = this.list().skills.find((item) => item.id === id)!;
    return { skill, files: files.sort((a, b) => a === "SKILL.md" ? -1 : b === "SKILL.md" ? 1 : a.localeCompare(b)) };
  }

  async resourcesForRole(role: string): Promise<SessionResources> {
    const view = await this.refresh();
    const selected = view.skills.filter((skill) => skill.present && skill.enabled && skill.roles.includes(role));
    if (selected.length > 16) throw new AppError(409, "skill_limit", "At most 16 skills may be assigned to one role");
    const skills: SessionResources["skills"] = [];
    let promptBytes = 0;
    for (const skill of selected) {
      const main = await this.readSkillFile(skill.id, "SKILL.md");
      promptBytes += Buffer.byteLength(main.content);
      if (promptBytes > 160_000) throw new AppError(409, "skill_context_limit", "Assigned skill instructions exceed the 160 KB session limit");
      const detail = await this.skillDetail(skill.id);
      const files: Array<{ path: string; content: string }> = [];
      let bytes = 0;
      for (const path of detail.files) {
        try {
          const file = path === "SKILL.md" ? main : await this.readSkillFile(skill.id, path);
          bytes += Buffer.byteLength(file.content);
          if (bytes > 2_000_000) throw new AppError(409, "skill_resource_limit", "Skill text resources exceed the 2 MB snapshot limit");
          files.push(file);
        } catch (error) {
          if (error instanceof AppError || path === "SKILL.md") throw error;
          // Non-text attachments are shown in the file list but excluded from text snapshots.
        }
      }
      skills.push({ id: skill.id, name: skill.name, content: main.content, files });
    }
    const linked = new Set(selected.flatMap((skill) => skill.mcp_ids));
    const servers: SessionResources["servers"] = [];
    for (const server of view.servers) {
      if (!linked.has(server.id) || !server.present || !server.enabled || !server.source_enabled) continue;
      const connection = this.connections.get(server.id);
      if (server.error || !connection) throw new AppError(409, "mcp_unavailable", `Linked MCP server ${server.name} is unavailable: ${server.error ?? "configuration missing"}`);
      servers.push({ id: server.id, name: server.name, key: mcpServerKey(server.id), connection: structuredClone(connection) });
    }
    return { skills, servers };
  }

  private record(kind: ResourceKind, id: string, event: "load" | "tool", context: ResourceUsageContext, callId: string, toolName: string | null): void {
    this.store.run(
      `INSERT OR IGNORE INTO local_resource_usage
       (resource_kind, resource_id, event, audit_id, task_id, session_id, role, harness, tool_name, call_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      kind, id, event, context.auditId, context.taskId, context.sessionId, context.role, context.harness, toolName, callId, now(),
    );
  }

  recordLoads(resources: SessionResources, context: ResourceUsageContext): void {
    for (const skill of resources.skills) this.record("skill", skill.id, "load", context, context.sessionId, null);
  }

  recordTool(resources: SessionResources, context: ResourceUsageContext, toolName: string, callId: string): void {
    const server = resources.servers.find((item) => toolName.startsWith(`mcp__${item.key}__`));
    if (server && callId) this.record("mcp", server.id, "tool", context, callId, toolName.slice(`mcp__${server.key}__`.length));
  }

  usage(kind: ResourceKind, id: string): { stats: ResourceStats; recent: ResourceCall[] } {
    this.resource(id, kind);
    const stats = this.store.get<ResourceStats>(
      "SELECT COUNT(*) AS total_calls, COUNT(DISTINCT task_id) AS tasks_covered, MAX(created_at) AS last_call FROM local_resource_usage WHERE resource_kind = ? AND resource_id = ?", kind, id,
    ) ?? emptyStats();
    const recent = this.store.all<ResourceCall>(
      "SELECT id, event, role, harness, audit_id, task_id, session_id, tool_name, created_at FROM local_resource_usage WHERE resource_kind = ? AND resource_id = ? ORDER BY id DESC LIMIT 20", kind, id,
    );
    return { stats, recent };
  }
}
