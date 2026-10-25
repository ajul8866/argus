export type ResourceKind = "skill" | "mcp";
export type ResourceStats = { total_calls: number; tasks_covered: number; last_call: string | null };
export type LocalSkill = {
  id: string; name: string; description: string; path: string; sources: string[];
  present: boolean; enabled: boolean; roles: string[]; mcp_ids: string[];
  error: string | null; stats: ResourceStats;
};
export type LocalMcp = {
  id: string; name: string; description: string; sources: string[];
  transport: "stdio" | "http" | "sse" | "unsupported"; endpoint: string;
  present: boolean; enabled: boolean; source_enabled: boolean;
  error: string | null; stats: ResourceStats;
};
export type CatalogView = {
  skills: LocalSkill[]; servers: LocalMcp[];
  roles: Array<{ role: string; label: string; enabled: boolean }>;
  scan: { scanned_at: string | null; roots: string[]; errors: Array<{ source: string; message: string }> };
};
export type McpConnection = {
  type: "stdio" | "http" | "sse";
  command?: string; args?: string[]; env?: Record<string, string>;
  url?: string; headers?: Record<string, string>;
};
export type SessionResources = {
  skills: Array<{ id: string; name: string; content: string; files: Array<{ path: string; content: string }> }>;
  servers: Array<{ id: string; name: string; key: string; connection: McpConnection }>;
};
export type ResourceUsageContext = { auditId: string; taskId: string; sessionId: string; role: string; harness: string };
export type ResourceCall = { id: number; event: string; role: string; harness: string; audit_id: string; task_id: string; session_id: string; tool_name: string | null; created_at: string };

export function mcpServerKey(id: string): string {
  return `argus_${id}`;
}
