export type AdapterConfig = { baseUrl: string; token: string };
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

type ToolDefinition = {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
};

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "health",
    description: "Check Argus health and version.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "list_audits",
    description: "List recent audits, optionally filtered by project.",
    inputSchema: {
      type: "object",
      properties: { project_id: { type: "string" } },
    },
  },
  {
    name: "get_audit",
    description: "Read one audit with tasks, findings, coverage, and sessions.",
    inputSchema: { type: "object", properties: { audit_id: { type: "string" } }, required: ["audit_id"] },
  },
  {
    name: "get_coverage",
    description: "Read asset coverage for one audit.",
    inputSchema: { type: "object", properties: { audit_id: { type: "string" } }, required: ["audit_id"] },
  },
  {
    name: "list_findings",
    description: "List findings, optionally filtered by audit or status.",
    inputSchema: {
      type: "object",
      properties: { audit_id: { type: "string" }, status: { type: "string" } },
    },
  },
  {
    name: "get_finding",
    description: "Read one finding with its evidence.",
    inputSchema: { type: "object", properties: { finding_id: { type: "string" } }, required: ["finding_id"] },
  },
  {
    name: "launch_audit",
    description: "Create and start a static, dynamic, or hybrid audit. Requires the matching launch scope.",
    inputSchema: {
      type: "object",
      properties: {
        project_id: { type: "string" },
        mode: { type: "string", enum: ["static", "dynamic", "hybrid"] },
        repository_id: { type: "string" },
        target_id: { type: "string" },
        overrides: { type: "object" },
      },
      required: ["project_id"],
    },
  },
  {
    name: "create_task",
    description: "Create a task inside an existing audit. Dynamic task kinds also require audit:launch_dynamic.",
    inputSchema: {
      type: "object",
      properties: {
        audit_id: { type: "string" },
        kind: { type: "string" },
        payload: { type: "object" },
        agent_role: { type: "string" },
        phase: { type: "number" },
      },
      required: ["audit_id", "kind"],
    },
  },
  {
    name: "get_exploration",
    description: "Read assets, exploration nodes, edges, anchors, and asset coverage for one audit.",
    inputSchema: { type: "object", properties: { audit_id: { type: "string" } }, required: ["audit_id"] },
  },
  {
    name: "propose_candidate",
    description:
      "Propose a dynamic candidate with a PoC manifest. The broker replays it only when a separate run confirms it. Requires audit:propose_candidate.",
    inputSchema: {
      type: "object",
      properties: {
        audit_id: { type: "string" },
        asset_id: { type: "string" },
        title: { type: "string" },
        category: { type: "string" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        manifest: { type: "object" },
        script: { type: "string" },
        proposed_by: { type: "string" },
        impact: { type: "string" },
        remediation: { type: "string" },
        intent_node_id: { type: "string" },
        source: { type: "object" },
      },
      required: ["audit_id", "asset_id", "title", "category", "severity", "manifest", "script"],
    },
  },
  {
    name: "confirm_candidate",
    description:
      "Confirm a proposed dynamic candidate by replaying its PoC through the broker. Requires audit:confirm_candidate and a different proposer.",
    inputSchema: {
      type: "object",
      properties: { candidate_id: { type: "string" }, confirmed_by: { type: "string" } },
      required: ["candidate_id"],
    },
  },
  {
    name: "control_task",
    description: "Cancel or retry a task.",
    inputSchema: {
      type: "object",
      properties: {
        task_id: { type: "string" },
        action: { type: "string", enum: ["cancel", "retry"] },
      },
      required: ["task_id", "action"],
    },
  },
];

function stringArg(args: Record<string, unknown>, key: string, required = true): string {
  const value = args[key];
  if (value === undefined && !required) return "";
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${key} is required`);
  return value.trim();
}

export async function callTool(
  name: string,
  args: Record<string, unknown>,
  config: AdapterConfig,
  fetchImpl: FetchLike = fetch,
): Promise<unknown> {
  if (!config.token || !config.token.startsWith("argus_")) {
    throw new Error("ARGUS_API_TOKEN is required and must be an Argus token");
  }
  const base = config.baseUrl.replace(/\/+$/, "");
  const request = async (path: string, init: RequestInit = {}): Promise<unknown> => {
    const headers = new Headers(init.headers);
    headers.set("authorization", `Bearer ${config.token}`);
    if (init.body !== undefined) headers.set("content-type", "application/json");
    const response = await fetchImpl(`${base}${path}`, { ...init, headers });
    const text = await response.text();
    const body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    if (!response.ok) {
      const error = body.error as { code?: string; message?: string } | undefined;
      throw new Error(error?.message ?? error?.code ?? `Argus API returned ${response.status}`);
    }
    return body;
  };

  switch (name) {
    case "health":
      return request("/api/health");
    case "list_audits": {
      const projectId = stringArg(args, "project_id", false);
      return request(`/api/audits${projectId ? `?project_id=${encodeURIComponent(projectId)}` : ""}`);
    }
    case "get_audit":
      return request(`/api/audits/${encodeURIComponent(stringArg(args, "audit_id"))}`);
    case "get_coverage": {
      const body = (await request(`/api/audits/${encodeURIComponent(stringArg(args, "audit_id"))}`)) as {
        coverage?: unknown;
      };
      return body.coverage ?? [];
    }
    case "list_findings": {
      const params = new URLSearchParams();
      const auditId = stringArg(args, "audit_id", false);
      const status = stringArg(args, "status", false);
      if (auditId) params.set("audit_id", auditId);
      if (status) params.set("status", status);
      const query = params.toString();
      return request(`/api/findings${query ? `?${query}` : ""}`);
    }
    case "get_finding":
      return request(`/api/findings/${encodeURIComponent(stringArg(args, "finding_id"))}`);
    case "launch_audit": {
      const mode = typeof args.mode === "string" ? args.mode : "static";
      if (!["static", "dynamic", "hybrid"].includes(mode)) throw new Error("mode must be static, dynamic, or hybrid");
      const created = (await request("/api/audits", {
        method: "POST",
        body: JSON.stringify({
          project_id: stringArg(args, "project_id"),
          mode,
          repository_id: stringArg(args, "repository_id", false) || undefined,
          target_id: stringArg(args, "target_id", false) || undefined,
          overrides: args.overrides && typeof args.overrides === "object" ? args.overrides : {},
        }),
      })) as { audit?: { id?: string } };
      const auditId = created.audit?.id;
      if (!auditId) throw new Error("Argus did not return an audit id");
      const started = await request(`/api/audits/${encodeURIComponent(auditId)}/start`, { method: "POST" });
      return { audit: created.audit, start: started };
    }
    case "create_task": {
      const auditId = stringArg(args, "audit_id");
      return request(`/api/audits/${encodeURIComponent(auditId)}/tasks`, {
        method: "POST",
        body: JSON.stringify({
          kind: stringArg(args, "kind"),
          payload: args.payload && typeof args.payload === "object" ? args.payload : {},
          agent_role: stringArg(args, "agent_role", false) || undefined,
          phase: typeof args.phase === "number" ? args.phase : undefined,
        }),
      });
    }
    case "get_exploration":
      return request(`/api/audits/${encodeURIComponent(stringArg(args, "audit_id"))}/exploration`);
    case "propose_candidate": {
      const auditId = stringArg(args, "audit_id");
      const manifest = args.manifest;
      if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
        throw new Error("manifest must be an object");
      }
      return request(`/api/audits/${encodeURIComponent(auditId)}/candidates`, {
        method: "POST",
        body: JSON.stringify({
          asset_id: stringArg(args, "asset_id"),
          title: stringArg(args, "title"),
          category: stringArg(args, "category"),
          severity: stringArg(args, "severity"),
          manifest,
          script: stringArg(args, "script"),
          proposed_by: stringArg(args, "proposed_by", false) || undefined,
          impact: stringArg(args, "impact", false) || undefined,
          remediation: stringArg(args, "remediation", false) || undefined,
          intent_node_id: stringArg(args, "intent_node_id", false) || undefined,
          source: args.source && typeof args.source === "object" ? args.source : undefined,
        }),
      });
    }
    case "confirm_candidate": {
      const body: Record<string, unknown> = {};
      const confirmedBy = stringArg(args, "confirmed_by", false);
      if (confirmedBy) body.confirmed_by = confirmedBy;
      return request(`/api/candidates/${encodeURIComponent(stringArg(args, "candidate_id"))}/confirm`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    }
    case "control_task": {
      const action = stringArg(args, "action");
      if (!["cancel", "retry"].includes(action)) throw new Error("action must be cancel or retry");
      return request(`/api/tasks/${encodeURIComponent(stringArg(args, "task_id"))}/${action}`, { method: "POST" });
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

type JsonRpcRequest = {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
};

async function handle(message: JsonRpcRequest, config: AdapterConfig): Promise<Record<string, unknown> | null> {
  if (message.method === "notifications/initialized") return null;
  if (message.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id: message.id ?? null,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "argus-adapter", version: "0.1.0" },
      },
    };
  }
  if (message.method === "ping") {
    return { jsonrpc: "2.0", id: message.id ?? null, result: {} };
  }
  if (message.method === "tools/list") {
    return { jsonrpc: "2.0", id: message.id ?? null, result: { tools: TOOL_DEFINITIONS } };
  }
  if (message.method === "tools/call") {
    const params = message.params ?? {};
    const name = typeof params.name === "string" ? params.name : "";
    const args = params.arguments && typeof params.arguments === "object"
      ? (params.arguments as Record<string, unknown>)
      : {};
    try {
      const result = await callTool(name, args, config);
      return {
        jsonrpc: "2.0",
        id: message.id ?? null,
        result: { content: [{ type: "text", text: JSON.stringify(result) }] },
      };
    } catch (error) {
      return {
        jsonrpc: "2.0",
        id: message.id ?? null,
        result: {
          content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
          isError: true,
        },
      };
    }
  }
  return {
    jsonrpc: "2.0",
    id: message.id ?? null,
    error: { code: -32601, message: `Unknown method: ${message.method}` },
  };
}

async function startServer(): Promise<void> {
  const config = {
    baseUrl: process.env.ARGUS_API_URL ?? "http://127.0.0.1:8787",
    token: process.env.ARGUS_API_TOKEN ?? "",
  };
  const decoder = new TextDecoder();
  let buffer = "";
  for await (const chunk of Bun.stdin.stream()) {
    buffer += decoder.decode(chunk);
    let newline = buffer.indexOf("\n");
    while (newline >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line) {
        let message: JsonRpcRequest;
        try {
          message = JSON.parse(line) as JsonRpcRequest;
        } catch {
          process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } })}\n`);
          newline = buffer.indexOf("\n");
          continue;
        }
        const response = await handle(message, config);
        if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
      }
      newline = buffer.indexOf("\n");
    }
  }
}

if (import.meta.main) void startServer();
