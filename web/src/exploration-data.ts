import { api } from "./api.ts";

export type ExplorationAsset = { id: string; kind: string; assetKey: string };
export type ExplorationNode = {
  id: string;
  kind: string;
  status: string;
  payload: Record<string, unknown>;
  taskId: string | null;
  sessionId: string | null;
};
export type ExplorationEdge = { fromNodeId: string; toNodeId: string; kind: string };
export type CoverageEntry = { assetId: string; kind: string; assetKey: string; tested: boolean };
export type ExplorationPayload = {
  assets: ExplorationAsset[];
  nodes: ExplorationNode[];
  edges: ExplorationEdge[];
  anchors: Array<{ nodeId: string; assetId: string }>;
  coverage: CoverageEntry[];
};

export type CoverageRow = {
  assetId: string;
  kind: string;
  assetKey: string;
  tested: boolean;
  nodes: number;
  findings: number;
};

export function coverageRows(payload: ExplorationPayload): CoverageRow[] {
  const nodes = new Map(payload.nodes.map((node) => [node.id, node]));
  const counts = new Map<string, { nodes: number; findings: number }>();
  for (const { nodeId, assetId } of payload.anchors) {
    const node = nodes.get(nodeId);
    if (!node) continue;
    const count = counts.get(assetId) ?? { nodes: 0, findings: 0 };
    count.nodes += 1;
    if (node.kind === "finding") count.findings += 1;
    counts.set(assetId, count);
  }
  return payload.coverage
    .map((entry) => ({
      ...entry,
      nodes: counts.get(entry.assetId)?.nodes ?? 0,
      findings: counts.get(entry.assetId)?.findings ?? 0,
    }))
    .sort((left, right) => Number(left.tested) - Number(right.tested) || left.assetKey.localeCompare(right.assetKey));
}

export type ExplorationRow = {
  id: string;
  kind: string;
  status: string;
  label: string;
  taskId: string | null;
  sessionId: string | null;
  findingId: string | null;
  assets: string[];
  payload: Record<string, unknown>;
};

export function explorationRows(payload: ExplorationPayload): ExplorationRow[] {
  const assetKeys = new Map(payload.assets.map((asset) => [asset.id, asset.assetKey]));
  const assetsByNode = new Map<string, string[]>();
  for (const { nodeId, assetId } of payload.anchors) {
    const assets = assetsByNode.get(nodeId) ?? [];
    assets.push(assetKeys.get(assetId) ?? assetId);
    assetsByNode.set(nodeId, assets);
  }
  return payload.nodes.map((node) => ({
    id: node.id,
    kind: node.kind,
    status: node.status,
    label:
      (typeof node.payload.title === "string" && node.payload.title) ||
      (typeof node.payload.text === "string" && node.payload.text) ||
      node.kind,
    taskId: node.taskId,
    sessionId: node.sessionId,
    findingId: typeof node.payload.finding_id === "string" ? node.payload.finding_id : null,
    assets: assetsByNode.get(node.id)?.slice() ?? [],
    payload: node.payload,
  }));
}

export type Audit = { id: string; project_name: string; mode?: string; status: string };

export async function selectAudit(params: URLSearchParams): Promise<Audit | null> {
  const projectId = params.get("project");
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  const { audits } = await api<{ audits: Audit[] }>(`/api/audits${query}`);
  if (audits.length === 0) return null;
  const requested = params.get("audit");
  if (requested && audits.some((audit) => audit.id === requested)) {
    return audits.find((audit) => audit.id === requested)!;
  }
  return audits.find((audit) => audit.mode === "dynamic" || audit.mode === "hybrid") ?? audits[0]!;
}
