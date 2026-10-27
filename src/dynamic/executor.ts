import { request as httpRequest } from "node:http";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import type { DynamicExecutor, DynamicExecutionResult, DynamicPlannerContext } from "../orchestrator/engine.ts";
import { BrokerServer } from "./broker.ts";
import { CredentialBroker } from "./credentials.ts";
import type { EgressPolicy } from "./egress.ts";
import { GraphStore } from "./graph.ts";
import { TargetService } from "./targets.ts";

function proxyGet(port: number, target: string, identityId: string | null): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (identityId) headers["x-argus-identity"] = identityId;
    const request = httpRequest(
      { host: "127.0.0.1", port, method: "GET", path: target, headers },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    request.on("error", reject);
    request.end();
  });
}

export type BrokerCheckExchanges = {
  positive: { status: number; body: string };
  exploit: { status: number; body: string };
  negative: { status: number; body: string };
};

/**
 * Executes the three PoC checks through a fresh per-audit broker. Used by
 * reverification so a recorded exchange always comes from a real request.
 */
export async function runPocChecks(
  config: Config,
  store: Store,
  auditId: string,
  manifest: {
    checks: Record<"positive" | "exploit" | "negative", { identity: string; request: { method: string; path: string } }>;
  },
): Promise<BrokerCheckExchanges> {
  const snapshot = new TargetService(store).getSnapshot(auditId)?.snapshot;
  if (!snapshot) throw new Error("The audit has no scope snapshot");
  const policy: EgressPolicy = {
    baseUrl: snapshot.target.base_url,
    allowedHosts: snapshot.target.allowed_hosts,
    allowedCidrs: snapshot.target.allowed_cidrs,
    allowedMethods: snapshot.target.allowed_methods,
    maxRps: snapshot.target.max_rps,
    tls: snapshot.target.tls,
    authorizedActions: snapshot.authorization.authorized_actions,
    restrictions: snapshot.authorization.restrictions,
  };
  const broker = new BrokerServer({ policy, credentials: new CredentialBroker(config, store) });
  const port = (await broker.start()).port;
  try {
    const run = async (name: "positive" | "exploit" | "negative") => {
      const check = manifest.checks[name];
      const target = new URL(check.request.path, snapshot.target.base_url).toString();
      return proxyGet(port, target, check.identity);
    };
    return { positive: await run("positive"), exploit: await run("exploit"), negative: await run("negative") };
  } finally {
    await broker.stop();
  }
}

/**
 * The default executor for a dynamic audit. It establishes a baseline response
 * for the app asset through the per-audit broker. It is deliberately small: the
 * harness-backed planner and worker replace it when a harness profile is wired.
 */
export function createBrokerDynamicExecutor(config: Config, store: Store): DynamicExecutor {
  const targets = new TargetService(store);
  const graph = new GraphStore(store);
  const credentials = new CredentialBroker(config, store);

  return {
    async plan(context: DynamicPlannerContext) {
      const audit = store.get<{ project_id: string }>("SELECT project_id FROM audits WHERE id = ?", context.auditId);
      if (!audit) return [];
      if (!context.snapshot.target.allowed_methods.map((method) => method.toUpperCase()).includes("GET")) return [];
      const assets = graph.listAssets(audit.project_id);
      const app =
        assets.find((asset) => asset.kind === "app" && asset.assetKey === context.snapshot.target.base_url) ??
        assets.find((asset) => asset.kind === "app");
      if (!app) return [];
      const tested = context.coverage.find((entry) => entry.assetId === app.id)?.tested;
      if (tested) return [];
      return [
        {
          title: "Baseline probe of the authorized target",
          assetIds: [app.id],
          method: "GET",
          path: new URL(context.snapshot.target.base_url).pathname || "/",
          expectedSignal: "A recorded response for the app asset.",
          rationale: "Establish a baseline response before deeper exploration.",
          category: "recon",
        },
      ];
    },

    async execute(auditId, intent): Promise<DynamicExecutionResult> {
      const snapshot = targets.getSnapshot(auditId)?.snapshot;
      if (!snapshot) throw new Error("The audit has no scope snapshot");
      const policy: EgressPolicy = {
        baseUrl: snapshot.target.base_url,
        allowedHosts: snapshot.target.allowed_hosts,
        allowedCidrs: snapshot.target.allowed_cidrs,
        allowedMethods: snapshot.target.allowed_methods,
        maxRps: snapshot.target.max_rps,
        tls: snapshot.target.tls,
        authorizedActions: snapshot.authorization.authorized_actions,
        restrictions: snapshot.authorization.restrictions,
      };
      const broker = new BrokerServer({ policy, credentials });
      const port = (await broker.start()).port;
      try {
        const target = new URL(intent.path, snapshot.target.base_url).toString();
        const response = await proxyGet(port, target, snapshot.identities[0]?.id ?? null);
        return {
          costUsd: 0,
          facts: [
            {
              status: response.status,
              assetIds: intent.assetIds,
              summary: `${intent.method} ${intent.path} → ${response.status}`,
            },
          ],
        };
      } finally {
        await broker.stop();
      }
    },
  };
}
