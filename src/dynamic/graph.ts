import type { Store } from "../db/index.ts";
import { badRequest, notFound, now, parseJson, toJson, uid } from "../util.ts";

export type AssetKind = "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint";
export type Asset = {
  id: string;
  projectId: string;
  kind: AssetKind;
  assetKey: string;
  parentId: string | null;
  data: Record<string, unknown>;
  firstSeenAt: string;
  lastSeenAt: string;
};

export type AssetEdge = { fromAssetId: string; toAssetId: string; kind: string };

export type NodeKind = "goal" | "intent" | "fact" | "finding" | "hint";
export type NodeStatus =
  | "proposed"
  | "approved"
  | "claimed"
  | "running"
  | "completed"
  | "failed"
  | "rejected";

export type ExplorationNode = {
  id: string;
  auditId: string;
  kind: NodeKind;
  status: NodeStatus;
  taskId: string | null;
  sessionId: string | null;
  payload: Record<string, unknown>;
  retryCount: number;
  createdAt: string;
  updatedAt: string;
};

export type Coverage = { assetId: string; kind: AssetKind; assetKey: string; tested: boolean };

export type UpsertAssetInput = {
  projectId: string;
  kind: AssetKind;
  assetKey: string;
  parentId?: string | null;
  data?: Record<string, unknown>;
};

export type CreateNodeInput = {
  auditId: string;
  kind: NodeKind;
  payload: Record<string, unknown>;
  status?: NodeStatus;
  taskId?: string | null;
  sessionId?: string | null;
};

export type EdgeKind = "spawns" | "derived_from" | "yields" | "proves" | "rejects";

const ASSET_KINDS: AssetKind[] = ["root_domain", "subdomain", "ip", "service", "app", "endpoint"];
const NODE_KINDS: NodeKind[] = ["goal", "intent", "fact", "finding", "hint"];
const NODE_STATUSES: NodeStatus[] = [
  "proposed",
  "approved",
  "claimed",
  "running",
  "completed",
  "failed",
  "rejected",
];

type AssetRow = {
  id: string;
  project_id: string;
  kind: AssetKind;
  asset_key: string;
  parent_id: string | null;
  data: string;
  first_seen_at: string;
  last_seen_at: string;
};

type NodeRow = {
  id: string;
  audit_id: string;
  kind: NodeKind;
  status: NodeStatus;
  task_id: string | null;
  session_id: string | null;
  payload: string;
  retry_count: number;
  created_at: string;
  updated_at: string;
};

function assetFromRow(row: AssetRow): Asset {
  return {
    id: row.id,
    projectId: row.project_id,
    kind: row.kind,
    assetKey: row.asset_key,
    parentId: row.parent_id,
    data: parseJson<Record<string, unknown>>(row.data, {}),
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
  };
}

function nodeFromRow(row: NodeRow): ExplorationNode {
  return {
    id: row.id,
    auditId: row.audit_id,
    kind: row.kind,
    status: row.status,
    taskId: row.task_id,
    sessionId: row.session_id,
    payload: parseJson<Record<string, unknown>>(row.payload, {}),
    retryCount: row.retry_count,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class GraphStore {
  constructor(private readonly store: Store) {}

  upsertAsset(input: UpsertAssetInput): Asset {
    if (!ASSET_KINDS.includes(input.kind)) throw badRequest("invalid asset kind");
    if (!input.assetKey?.trim()) throw badRequest("asset_key is required");
    if (!this.store.get("SELECT id FROM projects WHERE id = ?", input.projectId)) throw notFound("Project not found");
    if (input.parentId) {
      const parent = this.store.get<{ project_id: string }>(
        "SELECT project_id FROM assets WHERE id = ?",
        input.parentId,
      );
      if (!parent) throw notFound("Parent asset not found");
      if (parent.project_id !== input.projectId) throw badRequest("Parent asset belongs to another project");
    }
    const timestamp = now();
    const data = input.data ?? {};
    this.store.run(
      `INSERT INTO assets (id, project_id, kind, asset_key, parent_id, data, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(project_id, kind, asset_key) DO UPDATE SET
         data = excluded.data,
         last_seen_at = excluded.last_seen_at`,
      uid(),
      input.projectId,
      input.kind,
      input.assetKey.trim(),
      input.parentId ?? null,
      toJson(data),
      timestamp,
      timestamp,
    );
    const row = this.store.get<AssetRow>(
      "SELECT * FROM assets WHERE project_id = ? AND kind = ? AND asset_key = ?",
      input.projectId,
      input.kind,
      input.assetKey.trim(),
    );
    return assetFromRow(row!);
  }

  listAssets(projectId: string): Asset[] {
    return this.store
      .all<AssetRow>("SELECT * FROM assets WHERE project_id = ? ORDER BY kind, asset_key", projectId)
      .map(assetFromRow);
  }

  linkAssets(fromAssetId: string, toAssetId: string, kind: string): void {
    if (!this.store.get("SELECT id FROM assets WHERE id = ?", fromAssetId)) throw notFound("Asset not found");
    if (!this.store.get("SELECT id FROM assets WHERE id = ?", toAssetId)) throw notFound("Asset not found");
    this.store.run(
      "INSERT OR IGNORE INTO asset_edges (from_asset_id, to_asset_id, kind) VALUES (?, ?, ?)",
      fromAssetId,
      toAssetId,
      kind,
    );
  }

  listAssetEdges(projectId: string): AssetEdge[] {
    return this.store.all<{ from_asset_id: string; to_asset_id: string; kind: string }>(
      `SELECT e.from_asset_id, e.to_asset_id, e.kind
       FROM asset_edges e JOIN assets a ON a.id = e.from_asset_id
       WHERE a.project_id = ? ORDER BY e.from_asset_id, e.to_asset_id, e.kind`,
      projectId,
    ).map((row) => ({ fromAssetId: row.from_asset_id, toAssetId: row.to_asset_id, kind: row.kind }));
  }

  createNode(input: CreateNodeInput): ExplorationNode {
    if (!NODE_KINDS.includes(input.kind)) throw badRequest("invalid exploration node kind");
    const status = input.status ?? (input.kind === "intent" || input.kind === "hint" ? "proposed" : "completed");
    if (!NODE_STATUSES.includes(status)) throw badRequest("invalid exploration node status");
    if (!this.store.get("SELECT id FROM audits WHERE id = ?", input.auditId)) throw notFound("Audit not found");
    const timestamp = now();
    const id = uid();
    this.store.run(
      `INSERT INTO exploration_nodes
       (id, audit_id, kind, status, task_id, session_id, payload, retry_count, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
      id,
      input.auditId,
      input.kind,
      status,
      input.taskId ?? null,
      input.sessionId ?? null,
      toJson(input.payload ?? {}),
      timestamp,
      timestamp,
    );
    return this.getNode(id)!;
  }

  getNode(id: string): ExplorationNode | null {
    const row = this.store.get<NodeRow>("SELECT * FROM exploration_nodes WHERE id = ?", id);
    return row ? nodeFromRow(row) : null;
  }

  updateNodeStatus(id: string, status: NodeStatus, patch: { taskId?: string | null; sessionId?: string | null } = {}): void {
    if (!NODE_STATUSES.includes(status)) throw badRequest("invalid exploration node status");
    const changed = this.store.changes(
      `UPDATE exploration_nodes SET status = ?, updated_at = ?,
         task_id = COALESCE(?, task_id), session_id = COALESCE(?, session_id)
       WHERE id = ?`,
      status,
      now(),
      patch.taskId ?? null,
      patch.sessionId ?? null,
      id,
    );
    if (changed === 0) throw notFound("Exploration node not found");
  }

  linkNodes(fromNodeId: string, toNodeId: string, kind: EdgeKind): void {
    if (!this.getNode(fromNodeId)) throw notFound("Exploration node not found");
    if (!this.getNode(toNodeId)) throw notFound("Exploration node not found");
    this.store.run(
      "INSERT OR IGNORE INTO exploration_edges (from_node_id, to_node_id, kind) VALUES (?, ?, ?)",
      fromNodeId,
      toNodeId,
      kind,
    );
  }

  anchor(nodeId: string, assetId: string): void {
    if (!this.getNode(nodeId)) throw notFound("Exploration node not found");
    if (!this.store.get("SELECT id FROM assets WHERE id = ?", assetId)) throw notFound("Asset not found");
    this.store.run("INSERT OR IGNORE INTO anchors (node_id, asset_id) VALUES (?, ?)", nodeId, assetId);
  }

  listNodes(auditId: string): ExplorationNode[] {
    return this.store
      .all<NodeRow>(
        "SELECT * FROM exploration_nodes WHERE audit_id = ? ORDER BY created_at, id",
        auditId,
      )
      .map(nodeFromRow);
  }

  listEdges(auditId: string): Array<{ fromNodeId: string; toNodeId: string; kind: EdgeKind }> {
    return this.store
      .all<{ from_node_id: string; to_node_id: string; kind: EdgeKind }>(
        `SELECT e.from_node_id, e.to_node_id, e.kind
         FROM exploration_edges e JOIN exploration_nodes n ON n.id = e.from_node_id
         WHERE n.audit_id = ? ORDER BY e.from_node_id, e.to_node_id, e.kind`,
        auditId,
      )
      .map((row) => ({ fromNodeId: row.from_node_id, toNodeId: row.to_node_id, kind: row.kind }));
  }

  listAnchors(auditId: string): Array<{ nodeId: string; assetId: string }> {
    return this.store
      .all<{ node_id: string; asset_id: string }>(
        `SELECT an.node_id, an.asset_id
         FROM anchors an JOIN exploration_nodes n ON n.id = an.node_id
         WHERE n.audit_id = ? ORDER BY an.node_id, an.asset_id`,
        auditId,
      )
      .map((row) => ({ nodeId: row.node_id, assetId: row.asset_id }));
  }

  listGoal(auditId: string): ExplorationNode | null {    const row = this.store.get<NodeRow>(
      "SELECT * FROM exploration_nodes WHERE audit_id = ? AND kind = 'goal' ORDER BY created_at, id LIMIT 1",
      auditId,
    );
    return row ? nodeFromRow(row) : null;
  }

  listFrontier(auditId: string): ExplorationNode[] {
    return this.store
      .all<NodeRow>(
        `SELECT * FROM exploration_nodes
         WHERE audit_id = ? AND kind = 'intent' AND status IN ('proposed','approved')
         ORDER BY created_at, id`,
        auditId,
      )
      .map(nodeFromRow);
  }

  listLineage(auditId: string, rootNodeId: string): ExplorationNode[] {
    return this.store
      .all<NodeRow>(
        `WITH RECURSIVE tree(id, depth) AS (
           SELECT id, 0 FROM exploration_nodes WHERE id = ? AND audit_id = ?
           UNION
           SELECT e.to_node_id, tree.depth + 1
           FROM exploration_edges e JOIN tree ON e.from_node_id = tree.id
         )
         SELECT n.* FROM tree JOIN exploration_nodes n ON n.id = tree.id
         ORDER BY tree.depth, n.created_at`,
        rootNodeId,
        auditId,
      )
      .map(nodeFromRow);
  }

  coverage(auditId: string): Coverage[] {
    return this.store
      .all<{ asset_id: string; kind: AssetKind; asset_key: string; tested: number }>(
        `SELECT a.id AS asset_id, a.kind, a.asset_key,
           EXISTS(
             SELECT 1 FROM anchors an
             JOIN exploration_nodes n ON n.id = an.node_id
             WHERE an.asset_id = a.id AND n.audit_id = ?
               AND n.kind = 'fact'
               AND n.status = 'completed'
               AND EXISTS (
                 SELECT 1 FROM exploration_edges e
                 WHERE e.to_node_id = n.id AND e.kind = 'yields'
               )
           ) AS tested
         FROM assets a
         WHERE a.project_id = (SELECT project_id FROM audits WHERE id = ?)
         ORDER BY a.kind, a.asset_key`,
        auditId,
        auditId,
      )
      .map((row) => ({
        assetId: row.asset_id,
        kind: row.kind,
        assetKey: row.asset_key,
        tested: row.tested === 1,
      }));
  }
}
