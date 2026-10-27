import type { Coverage, ExplorationNode } from "./graph.ts";
import type { AuditScopeSnapshot } from "./targets.ts";

export type IntentInput = {
  title: string;
  assetIds: string[];
  method: string;
  path: string;
  expectedSignal?: string;
  rationale?: string;
  category?: string;
};

export type IntentDecision = {
  accepted: string[];
  rejected: Array<{ index: number; reason: string }>;
};

export type DynamicPlannerContext = {
  auditId: string;
  snapshot: AuditScopeSnapshot;
  coverage: Coverage[];
  frontier: ExplorationNode[];
};

export type DynamicExecutionResult = {
  costUsd: number;
  facts: Array<{ status: number; assetIds: string[]; summary?: string }>;
};

export type DynamicExecutor = {
  plan(context: DynamicPlannerContext): Promise<IntentInput[]>;
  execute(auditId: string, intent: IntentInput & { nodeId: string }): Promise<DynamicExecutionResult>;
};
