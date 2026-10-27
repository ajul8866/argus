import { describe, expect, test } from "bun:test";
import { coverageRows, type ExplorationPayload } from "../web/src/pages/coverage.ts";
import { explorationRows } from "../web/src/pages/exploration.ts";

function payload(): ExplorationPayload {
  return {
    assets: [
      { id: "a1", kind: "app", assetKey: "old" },
      { id: "a1", kind: "app", assetKey: "current" },
    ],
    nodes: [
      { id: "n1", kind: "fact", status: "completed", payload: { title: "", text: "Fallback text" }, taskId: null, sessionId: null },
      { id: "n1", kind: "finding", status: "completed", payload: { title: "Finding", finding_id: "f1" }, taskId: "t1", sessionId: "s1" },
      { id: "n2", kind: "intent", status: "queued", payload: { title: 1, text: "" }, taskId: null, sessionId: null },
    ],
    edges: [],
    anchors: [
      { nodeId: "n1", assetId: "missing" },
      { nodeId: "n1", assetId: "a1" },
      { nodeId: "n1", assetId: "a1" },
      { nodeId: "missing", assetId: "a1" },
    ],
    coverage: [
      { assetId: "a1", kind: "app", assetKey: "z", tested: true },
      { assetId: "a2", kind: "app", assetKey: "z", tested: false },
      { assetId: "a1", kind: "app", assetKey: "a", tested: false },
      { assetId: "a3", kind: "app", assetKey: "a", tested: false },
    ],
  };
}

describe("exploration view data", () => {
  test("empty graphs produce empty rows", () => {
    const empty = { assets: [], nodes: [], edges: [], anchors: [], coverage: [] };
    expect(coverageRows(empty)).toEqual([]);
    expect(explorationRows(empty)).toEqual([]);
  });

  test("coverage preserves duplicate anchors, ignores unknown nodes, and sorts untested assets stably", () => {
    expect(coverageRows(payload())).toEqual([
      { assetId: "a1", kind: "app", assetKey: "a", tested: false, nodes: 2, findings: 2 },
      { assetId: "a3", kind: "app", assetKey: "a", tested: false, nodes: 0, findings: 0 },
      { assetId: "a2", kind: "app", assetKey: "z", tested: false, nodes: 0, findings: 0 },
      { assetId: "a1", kind: "app", assetKey: "z", tested: true, nodes: 2, findings: 2 },
    ]);
  });

  test("exploration preserves node and anchor order, duplicate assets, and missing asset identifiers", () => {
    const input = payload();
    const rows = explorationRows(input);
    expect(rows).toEqual([
      { id: "n1", kind: "fact", status: "completed", label: "Fallback text", taskId: null, sessionId: null, findingId: null, assets: ["missing", "current", "current"], payload: input.nodes[0]!.payload },
      { id: "n1", kind: "finding", status: "completed", label: "Finding", taskId: "t1", sessionId: "s1", findingId: "f1", assets: ["missing", "current", "current"], payload: input.nodes[1]!.payload },
      { id: "n2", kind: "intent", status: "queued", label: "intent", taskId: null, sessionId: null, findingId: null, assets: [], payload: input.nodes[2]!.payload },
    ]);
    expect(rows[0]!.payload).toBe(input.nodes[0]!.payload);
    rows[0]!.assets.push("local");
    expect(rows[1]!.assets).toEqual(["missing", "current", "current"]);
    expect(input.anchors).toHaveLength(4);
  });
});
