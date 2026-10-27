import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import type { DynamicExecutor, DynamicExecutionResult, DynamicPlannerContext } from "./types.ts";
import { BrokerServer } from "./broker.ts";
import { CredentialBroker } from "./credentials.ts";
import type { EgressPolicy } from "./egress.ts";
import { GraphStore } from "./graph.ts";
import { TargetService, type AuditScopeSnapshot } from "./targets.ts";
import { requestThroughBroker, type BrokerResponse } from "./http.ts";
import type { PocExchange } from "./poc.ts";

export type BrokerCheckExchanges = {
  positive: PocExchange;
  exploit: PocExchange;
  negative: PocExchange;
};

/**
 * Replay is live testing: the authorization captured at start must still be
 * active, and the target must still be enabled. Revocation must stop traffic,
 * not merely be recorded in the snapshot.
 */
function assertReplayAuthorized(targets: TargetService, snapshot: AuditScopeSnapshot): void {
  const target = targets.getTarget(snapshot.target.id);
  if (!target || target.status !== "active") {
    throw new Error("The target is no longer active; refusing to replay the PoC");
  }
  const live = targets.getAuthorization(snapshot.authorization.id);
  const nowMs = Date.now();
  if (
    !live ||
    live.targetId !== snapshot.target.id ||
    live.status !== "active" ||
    Date.parse(live.validFrom) > nowMs ||
    Date.parse(live.validUntil) <= nowMs
  ) {
    throw new Error("The target authorization is no longer active; refusing to replay the PoC");
  }
}

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
  const targets = new TargetService(store);
  const snapshot = targets.getSnapshot(auditId)?.snapshot;
  if (!snapshot) throw new Error("The audit has no scope snapshot");
  assertReplayAuthorized(targets, snapshot);
  const scoped = new Set(snapshot.identities.map((identity) => identity.id));
  const identities = (["positive", "exploit", "negative"] as const).map((name) => manifest.checks[name].identity);
  for (const identityId of identities) {
    if (!scoped.has(identityId)) {
      throw new Error(`Identity ${identityId} is not part of this audit scope`);
    }
  }
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
  const credentials = new CredentialBroker(config, store);
  const secrets = credentials.secretValues(identities);
  if (secrets.some((secret) => secret.length < 4)) {
    throw new Error("An identity secret is too short to redact safely");
  }
  const manifestText = JSON.stringify(manifest);
  if (secrets.some((secret) => manifestText.includes(secret))) {
    throw new Error("The PoC manifest contains an identity secret; refusing to replay it");
  }
  const broker = new BrokerServer({ policy, credentials, targetId: snapshot.target.id });
  const port = (await broker.start()).port;
  const sanitize = (exchange: BrokerResponse): PocExchange => {
    const evidenceBody = credentials.redactExchange({}, exchange.body, secrets).body;
    credentials.assertNoSecrets(evidenceBody, secrets);
    return { ...exchange, body: exchange.body, evidenceBody };
  };
  try {
    const run = async (name: "positive" | "exploit" | "negative") => {
      const check = manifest.checks[name];
      const target = new URL(check.request.path, snapshot.target.base_url).toString();
      return sanitize(await requestThroughBroker(port, target, check.request.method, check.identity));
    };
    return {
      positive: await run("positive"),
      exploit: await run("exploit"),
      negative: await run("negative"),
    };
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
      assertReplayAuthorized(targets, snapshot);
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
      const broker = new BrokerServer({ policy, credentials, targetId: snapshot.target.id });
      const port = (await broker.start()).port;
      try {
        const target = new URL(intent.path, snapshot.target.base_url).toString();
        const response = await requestThroughBroker(port, target, intent.method, snapshot.identities[0]?.id ?? null);
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
