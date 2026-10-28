import type { SessionResources } from "../local/types.ts";

export type HarnessKind = "pi" | "claude-code";
export type HarnessStatus = "ready" | "unauthenticated" | "missing" | "error" | "unknown";

export type HarnessCapabilities = {
  streaming: boolean;
  resume: boolean;
  toolEvents: boolean;
  structuredOutput: boolean;
  cancellation: boolean;
  modelSelection: boolean;
  sessionIdentity: boolean;
  costReporting: boolean;
  rpc: boolean;
  cli: boolean;
  sandbox: boolean;
};

export type HarnessConfig = {
  executable: string;
  provider: string | null;
  model: string | null;
  env: Record<string, string>;
  extra_args: string[];
};

export type HarnessDetection = {
  kind: HarnessKind;
  label: string;
  executable: string;
  version: string | null;
  status: HarnessStatus;
  detail: string;
  auth: { ready: boolean; detail: string };
  capabilities: HarnessCapabilities;
  models: Array<{ id: string; label: string }>;
};

export type HarnessTask = {
  runId: string;
  auditId: string;
  taskId: string;
  role: string;
  prompt: string;
  systemPrompt: string;
  workspace: string;
  model: string | null;
  provider?: string | null;
  timeoutMs: number;
  schema?: unknown;
  maxBudgetUsd?: number | null;
  resumeSessionRef?: string | null;
  metadata?: Record<string, unknown>;
  resources?: SessionResources;
};

export type HarnessUsage = {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cache_read_tokens: number;
  cost_usd: number;
  turns: number | null;
  duration_ms: number;
};

export type HarnessEventType =
  | "session_start"
  | "text_delta"
  | "thinking_delta"
  | "tool_start"
  | "tool_end"
  | "log"
  | "usage"
  | "error"
  | "session_end";

export type HarnessEvent = {
  type: HarnessEventType;
  at: string;
  text?: string;
  toolName?: string;
  toolCallId?: string;
  input?: unknown;
  output?: string;
  isError?: boolean;
  usage?: Partial<HarnessUsage>;
  meta?: Record<string, unknown>;
};

export type HarnessFailureKind =
  | "harness_missing"
  | "harness_auth"
  | "harness_error"
  | "agent_error"
  | "timeout"
  | "cancelled"
  | "invalid_output"
  | "budget_exceeded"
  | "internal";

export type HarnessRunResult = {
  status: "completed" | "failed" | "timeout" | "cancelled";
  text: string;
  structured?: unknown;
  sessionRef: string | null;
  model: string | null;
  usage: HarnessUsage;
  events: HarnessEvent[];
  startedAt: string;
  endedAt: string;
  exitCode: number | null;
  error?: string;
  failureKind?: HarnessFailureKind;
  metadata: Record<string, unknown>;
};

export type HarnessRunHooks = {
  onEvent: (event: HarnessEvent) => void;
  signal?: AbortSignal;
};

export interface HarnessAdapter {
  readonly kind: HarnessKind;
  readonly label: string;
  detect(force?: boolean): Promise<HarnessDetection>;
  health(force?: boolean): Promise<HarnessDetection>;
  capabilities(): HarnessCapabilities;
  run(task: HarnessTask, hooks: HarnessRunHooks): Promise<HarnessRunResult>;
  cancel(runId: string): boolean;
  cleanup(runId: string): Promise<void>;
}

export function emptyUsage(): HarnessUsage {
  return {
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    cache_read_tokens: 0,
    cost_usd: 0,
    turns: null,
    duration_ms: 0,
  };
}

export const PI_CAPABILITIES: HarnessCapabilities = {
  streaming: true,
  resume: true,
  toolEvents: true,
  structuredOutput: true,
  cancellation: true,
  modelSelection: true,
  sessionIdentity: true,
  costReporting: true,
  rpc: true,
  cli: false,
  sandbox: false,
};

export const CLAUDE_CAPABILITIES: HarnessCapabilities = {
  streaming: true,
  resume: true,
  toolEvents: true,
  structuredOutput: true,
  cancellation: true,
  modelSelection: true,
  sessionIdentity: true,
  costReporting: true,
  rpc: false,
  cli: true,
  sandbox: false,
};
