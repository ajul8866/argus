import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { badRequest, now, notFound, sha256, toJson, uid } from "../util.ts";
import { redactSecrets } from "../security/redact.ts";
import type { EvidenceStore } from "../orchestrator/evidence.ts";
import { GraphStore } from "./graph.ts";
import { evaluateRun, type PocExchange, type PocManifest, type PocRunResult } from "./poc.ts";
import { TargetService } from "./targets.ts";
import { verifyQuote } from "../repo/workspace.ts";
import { existsSync } from "node:fs";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Exchanges must come from the broker replay, never from the caller. */
export type ProvenExchanges = {
  positive: PocExchange;
  exploit: PocExchange;
  negative: PocExchange;
};

/**
 * The only source of exchange data is a broker replay. A caller supplies the
 * manifest; the service performs the requests itself.
 */
export type PocReplay = (auditId: string, manifest: PocManifest) => Promise<ProvenExchanges>;

export type DynamicProofInput = {
  auditId: string;
  assetId: string;
  title: string;
  category: string;
  severity: FindingSeverity;
  manifest: PocManifest;
  script: string;
  impact?: string;
  remediation?: string;
  intentNodeId?: string | null;
  source?: { path: string; start_line: number; end_line: number; quote: string } | null;
};

export type DynamicProofResult = {
  findingId: string;
  candidateId: string;
  code: string;
  evidenceIds: string[];
  run: PocRunResult;
};

type AuditRow = {
  id: string;
  project_id: string;
  repository_id: string | null;
  mode: "static" | "dynamic" | "hybrid";
};

type RepositoryRow = { commit_sha: string | null };

function redact(value: string): string {
  return redactSecrets(value).text;
}

export class DynamicProofService {
  private readonly graph: GraphStore;

  constructor(
    private readonly store: Store,
    private readonly evidence: EvidenceStore,
    private readonly replay: PocReplay,
    graph?: GraphStore,
  ) {
    this.graph = graph ?? new GraphStore(store);
  }

  async record(input: DynamicProofInput): Promise<DynamicProofResult> {
    const audit = this.store.get<AuditRow>(
      "SELECT id, project_id, repository_id, mode FROM audits WHERE id = ?",
      input.auditId,
    );
    if (!audit) throw notFound("Audit not found");
    if (audit.mode === "static") throw badRequest("Static audits cannot store dynamic proof");
    const asset = this.graph.listAssets(audit.project_id).find((entry) => entry.id === input.assetId);
    if (!asset) throw notFound("Asset not found in the audit project");
    if (!input.title?.trim()) throw badRequest("title is required");
    if (!input.category?.trim()) throw badRequest("category is required");
    if (!["critical", "high", "medium", "low", "info"].includes(input.severity)) {
      throw badRequest("invalid severity");
    }

    const replay = await this.replay(input.auditId, input.manifest);
    const run = evaluateRun(input.manifest, replay);
    if (run.status !== "passed") {
      throw badRequest(`PoC did not pass: ${run.reason ?? run.status}`);
    }

    let source: { path: string; start_line: number; end_line: number; quote: string } | null = null;
    if (input.source) {
      const snapshot = new TargetService(this.store).getSnapshot(input.auditId)?.snapshot;
      const repositoryId = snapshot?.repository?.id ?? null;
      const repository = repositoryId
        ? this.store.get<{ path: string }>("SELECT path FROM repositories WHERE id = ?", repositoryId)
        : null;
      if (!repository || !existsSync(repository.path)) {
        throw badRequest("A source quote requires an imported repository snapshot");
      }
      const check = await verifyQuote(
        repository.path,
        { include: ["**/*"], exclude: [] },
        { path: input.source.path, quote: input.source.quote },
      );
      if (!check.found) {
        throw badRequest(`The source quote was not found in ${input.source.path}: ${check.detail}`);
      }
      source = {
        path: check.path,
        start_line: check.line_start ?? input.source.start_line,
        end_line: check.line_end ?? input.source.end_line,
        quote: input.source.quote,
      };
    }

    const findingId = uid();
    const candidateId = uid();
    const code = this.nextCode(input.auditId);
    const commit = audit.repository_id
      ? this.store.get<RepositoryRow>("SELECT commit_sha FROM repositories WHERE id = ?", audit.repository_id)
          ?.commit_sha ?? null
      : null;

    const scriptEvidence = await this.evidence.append({
      auditId: input.auditId,
      findingId,
      kind: "poc_script",
      title: `${input.title} PoC script`,
      content: redact(input.script),
      redacted: true,
    });
    const exchangeIds: string[] = [];
    for (const name of ["positive", "exploit", "negative"] as const) {
      const check = input.manifest.checks[name];
      const exchange = replay[name];
      const row = await this.evidence.append({
        auditId: input.auditId,
        findingId,
        kind: "http_exchange",
        title: `${input.title} ${name} exchange`,
        content: {
          check: name,
          identity: check.identity,
          method: check.request.method,
          path: check.request.path,
          status: exchange.status,
          body: redact(exchange.body),
        },
        redacted: true,
      });
      exchangeIds.push(row.id);
    }
    const proofEvidence = await this.evidence.append({
      auditId: input.auditId,
      findingId,
      kind: "dynamic_proof",
      title: `${input.title} proof`,
      content: {
        manifest: { ...input.manifest, script_evidence_id: scriptEvidence.id },
        result: run,
        exchanges: {
          positive: { status: replay.positive.status, body_sha256: sha256(replay.positive.body) },
          exploit: { status: replay.exploit.status, body_sha256: sha256(replay.exploit.body) },
          negative: { status: replay.negative.status, body_sha256: sha256(replay.negative.body) },
        },
      },
      redacted: true,
    });

    const positive = input.manifest.checks.positive;
    const exploit = input.manifest.checks.exploit;
    const negative = input.manifest.checks.negative;
    const observed = `${exploit.identity} received HTTP ${replay.exploit.status} for ${input.manifest.object.object_id}, an object owned by ${input.manifest.object.owner_identity}.`;
    const rootCause = source
      ? `The handler at ${source.path}:${source.start_line} does not enforce object ownership.`
      : "No source root cause was identified. The finding is proven by the reproducible exchange.";
    const impact =
      input.impact ??
      `An authenticated identity can read another identity's ${input.manifest.object.object_id}.`;
    const remediation =
      input.remediation ?? "Enforce object ownership on the handler before returning the object.";
    const files = source
      ? toJson([{ path: source.path, start_line: source.start_line, end_line: source.end_line }])
      : "[]";
    const payload = {
      provenance: "dynamic",
      link_key: source ? `${source.path}:${input.category}` : null,
      manifest: { ...input.manifest, script_evidence_id: scriptEvidence.id },
      run,
      object: input.manifest.object,
      evidence_ids: [scriptEvidence.id, ...exchangeIds, proofEvidence.id],
      exchange_statuses: {
        positive: replay.positive.status,
        exploit: replay.exploit.status,
        negative: replay.negative.status,
      },
    };

    this.store.transaction(() => {
      this.store.run(
        `INSERT INTO candidates
         (id, audit_id, area_id, discovery_task_id, discovery_session_id, title, category, cwe, severity,
          status, finding_id, provenance, link_key, payload, created_at)
         VALUES (?, ?, NULL, NULL, NULL, ?, ?, NULL, ?, 'confirmed', ?, 'dynamic', ?, ?, ?)`,
        candidateId,
        input.auditId,
        input.title.trim(),
        input.category.trim(),
        input.severity,
        findingId,
        input.source ? `${input.source.path}:${input.category}` : null,
        toJson(payload),
        now(),
      );
      this.store.run(
        `INSERT INTO findings
         (id, code, audit_id, project_id, candidate_id, title, category, cwe, severity, status,
          repository_commit, files, root_cause, preconditions, reproduction, expected, observed,
          impact, remediation, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 'confirmed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        findingId,
        code,
        input.auditId,
        audit.project_id,
        candidateId,
        input.title.trim(),
        input.category.trim(),
        input.severity,
        commit,
        files,
        rootCause,
        toJson([
          `Authenticated as ${exploit.identity}.`,
          `Object ${input.manifest.object.object_id} belongs to ${input.manifest.object.owner_identity}.`,
        ]),
        toJson([
          `Authenticate as ${positive.identity} and request ${positive.request.method} ${positive.request.path}; expect ${String(positive.expect.status)} (positive control).`,
          `Authenticate as ${exploit.identity} and request ${exploit.request.method} ${exploit.request.path}; expected ${String(exploit.expect.status)}.`,
          `Authenticate as ${negative.identity} and request ${negative.request.method} ${negative.request.path}; expect ${String(negative.expect.status)} (negative control).`,
        ]),
        `The ${exploit.identity} must not receive an object owned by ${input.manifest.object.owner_identity}.`,
        observed,
        impact,
        remediation,
        now(),
        now(),
      );
    });

    const node = this.graph.createNode({
      auditId: input.auditId,
      kind: "finding",
      status: "completed",
      payload: { finding_id: findingId, candidate_id: candidateId, code, title: input.title.trim() },
    });
    this.graph.anchor(node.id, input.assetId);
    if (input.intentNodeId) {
      const intent = this.graph.getNode(input.intentNodeId);
      if (intent && intent.auditId === input.auditId) this.graph.linkNodes(intent.id, node.id, "proves");
    }

    return {
      findingId,
      candidateId,
      code,
      evidenceIds: [scriptEvidence.id, ...exchangeIds, proofEvidence.id],
      run,
    };
  }

  private nextCode(auditId: string): string {
    const count = this.store.get<{ count: number }>(
      "SELECT COUNT(*) AS count FROM findings WHERE audit_id = ?",
      auditId,
    )?.count ?? 0;
    return `DYN-${String(count + 1).padStart(3, "0")}`;
  }
}
