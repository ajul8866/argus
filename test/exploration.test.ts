import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { GraphStore } from "../src/dynamic/graph.ts";

let dir: string;
let store: Store;
let graph: GraphStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "argus-graph-"));
  store = new Store({ dataDir: dir } as Config);
  store.run(
    `INSERT INTO projects (id, name, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
     VALUES ('p1','Demo', ?, '**/*', '', 'Tester', 'AUTH-TEST', ?, ?)`,
    dir,
    "2026-10-27T00:00:00.000Z",
    "2026-10-27T00:00:00.000Z",
  );
  store.run(
    "INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, mode, created_at) VALUES ('a1','p1',NULL,'running',1,'{}','dynamic',?)",
    "2026-10-27T00:00:00.000Z",
  );
  graph = new GraphStore(store);
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("GraphStore", () => {
  test("upserts assets and links them", () => {
    const app = graph.upsertAsset({
      projectId: "p1",
      kind: "app",
      assetKey: "https://app.example.test",
      data: { name: "app" },
    });
    const endpoint = graph.upsertAsset({
      projectId: "p1",
      kind: "endpoint",
      assetKey: "GET /invoices/:id",
      parentId: app.id,
    });
    const again = graph.upsertAsset({
      projectId: "p1",
      kind: "app",
      assetKey: "https://app.example.test",
      data: { name: "app v2" },
    });

    expect(again.id).toBe(app.id);
    expect(again.data).toEqual({ name: "app v2" });
    expect(graph.listAssets("p1")).toHaveLength(2);

    graph.linkAssets(app.id, endpoint.id, "contains");
    expect(graph.listAssetEdges("p1")).toEqual([
      { fromAssetId: app.id, toAssetId: endpoint.id, kind: "contains" },
    ]);
  });

  test("builds goal, intent, and fact lineage with anchors", () => {
    const endpoint = graph.upsertAsset({
      projectId: "p1",
      kind: "endpoint",
      assetKey: "GET /invoices/:id",
    });
    const goal = graph.createNode({ auditId: "a1", kind: "goal", payload: { text: "test the app" } });
    const intent = graph.createNode({
      auditId: "a1",
      kind: "intent",
      status: "approved",
      payload: { title: "read invoice" },
    });
    const fact = graph.createNode({
      auditId: "a1",
      kind: "fact",
      status: "completed",
      payload: { status: 200 },
    });

    graph.linkNodes(goal.id, intent.id, "spawns");
    graph.linkNodes(intent.id, fact.id, "yields");
    graph.anchor(intent.id, endpoint.id);
    graph.anchor(fact.id, endpoint.id);

    expect(graph.listGoal("a1")?.id).toBe(goal.id);
    expect(graph.listFrontier("a1").map((node) => node.id)).toEqual([intent.id]);
    expect(graph.listLineage("a1", goal.id).map((node) => node.id)).toEqual([goal.id, intent.id, fact.id]);
    expect(graph.coverage("a1").find((asset) => asset.assetId === endpoint.id)?.tested).toBe(true);
  });

  test("rejects an unknown node kind", () => {
    expect(() => graph.createNode({ auditId: "a1", kind: "bogus" as never, payload: {} })).toThrow();
  });
});
