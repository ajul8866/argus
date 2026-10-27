import { WORKER_SCOPES } from "../../web/src/components/worker-tokens.ts";

export type DynamicE2EInput = {
  projectId: string;
  targetId: string;
  repositoryId?: string;
  baseUrl: string;
};

export type DynamicE2EStep = { name: string; detail: string };

export type DynamicE2EPlan = {
  audit: {
    project_id: string;
    repository_id?: string;
    mode: "dynamic" | "hybrid";
    target_id: string;
  };
  workerScopes: readonly string[];
  requiresDocker: boolean;
  steps: DynamicE2EStep[];
};

/**
 * The acceptance run in the spec: a real target, a real broker, a real worker
 * container, and a confirmation that comes from a different run.
 */
export function buildDynamicE2EPlan(input: DynamicE2EInput): DynamicE2EPlan {
  if (!input.projectId?.trim()) throw new Error("projectId is required");
  if (!input.targetId?.trim()) throw new Error("targetId is required");
  if (!input.baseUrl?.trim()) throw new Error("baseUrl is required");
  return {
    audit: {
      project_id: input.projectId,
      ...(input.repositoryId ? { repository_id: input.repositoryId } : {}),
      // Without source the audit has no static half, so it is dynamic only.
      mode: input.repositoryId ? "hybrid" : "dynamic",
      target_id: input.targetId,
    },
    workerScopes: WORKER_SCOPES,
    requiresDocker: true,
    steps: [
      { name: "broker image", detail: "build deploy/Dockerfile.broker and start it on the internal audit network" },
      { name: "worker image", detail: "build deploy/Dockerfile.worker and attach it to the audit and control networks" },
      { name: "audit networks", detail: "internal audit network, broker-only egress network, internal control network" },
      { name: "broker handshake", detail: "write the one-time identity handshake and wait for readiness" },
      { name: "worker proposal", detail: "the worker proposes a candidate through the Argus API with its own token" },
      { name: "independent confirmation", detail: "a different run replays the PoC through the broker and writes the finding" },
    ],
  };
}
