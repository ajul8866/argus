import type { Store } from "../db/index.ts";
import { badRequest, conflict, notFound, now, sha256, toJson, uid } from "../util.ts";
import { KeyedSerialQueue } from "../concurrency.ts";
import { redactSecrets } from "../security/redact.ts";
import type { EvidenceStore } from "../orchestrator/evidence.ts";
import { GraphStore } from "./graph.ts";
import { evaluateRun, validatePoc, type PocExchange, type PocManifest, type PocRunResult } from "./poc.ts";
import { TargetService } from "./targets.ts";
import { verifyQuote } from "../repo/workspace.ts";
import { existsSync } from "node:fs";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Exchanges come from a broker replay, never from the caller. */
export type ProvenExchanges = {
  positive: PocExchange;
  exploit: PocExchange;
  negative: PocExchange;
};

export type PocReplay = (auditId: string, manifest: PocManifest) => Promise<ProvenExchanges>;

export type ProposeInput = {
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
  /** Task that proposed the candidate. A candidate cannot confirm itself. */
  proposedBy: string;
};

export type ProposeResult = { candidateId: string; sourceVerified: boolean; sourceDetail: string };

export type ConfirmResult = {
  candidateId: string;
  verdict: "CONFIRMED" | "REFUTED" | "INCONCLUSIVE";
  findingId: string | null;
  code: string | null;
  evidenceIds: string[];
  run: PocRunResult;
};

type AuditRow = {
  id: string;
  project_id: string;
  repository_id: string | null;
  mode: "static" | "dynamic" | "hybrid";
};

type CandidateRow = {
  id: string;
  audit_id: string;
  status: string;
  provenance: string;
  title: string;
  category: string;
  severity: string;
  finding_id: string | null;
  payload: string;
};

type StoredProposal = {
  asset_id: string;
  intent_node_id: string | null;
  manifest: PocManifest;
  script: string;
  impact: string | null;
  remediation: string | null;
  source: { path: string; start_line: number; end_line: number; quote: string } | null;
  source_verified: boolean;
  proposed_by: string;
};

function redact(value: string): string {
  return redactSecrets(value).text;
}

/**
 * Confirmation includes an awaited network replay. Serialize per candidate
 * process-wide: the API constructs a DynamicProofService per request, so an
 * instance field would not protect two simultaneous confirms.
 */
const confirmations = new KeyedSerialQueue();

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

  /**
   * A worker proposes a candidate. Nothing is confirmed here: the source quote
   * is checked against the snapshot and the proposal waits for a separate
   * confirmation run. Spec section 6.5.
   */
  async propose(input: ProposeInput): Promise<ProposeResult> {
    const audit = this.store.get<AuditRow>(
      "SELECT id, project_id, repository_id, mode FROM audits WHERE id = ?",
      input.auditId,
    );
    if (!audit) throw notFound("Audit not found");
    if (audit.mode === "static") throw badRequest("Static audits cannot store dynamic candidates");
    if (!this.graph.listAssets(audit.project_id).some((entry) => entry.id === input.assetId)) {
      throw notFound("Asset not found in the audit project");
    }
    if (!input.title?.trim()) throw badRequest("title is required");
    if (!input.category?.trim()) throw badRequest("category is required");
    if (!["critical", "high", "medium", "low", "info"].includes(input.severity)) {
      throw badRequest("invalid severity");
    }
    if (!input.proposedBy?.trim()) throw badRequest("proposed_by is required");
    validatePoc(input.manifest);
    const snapshot = new TargetService(this.store).getSnapshot(input.auditId)?.snapshot;
    if (!snapshot) throw conflict("The audit has no scope snapshot");
    const scopedIdentities = new Set(snapshot.identities.map((identity) => identity.id));
    for (const name of ["positive", "exploit", "negative"] as const) {
      const identityId = input.manifest.checks[name].identity;
      if (!scopedIdentities.has(identityId)) {
        throw badRequest(`${name}.identity is not registered in this audit scope`);
      }
    }

    let source: StoredProposal["source"] = null;
    let sourceVerified = false;
    let sourceDetail = "No source quote was provided.";
    if (input.source) {
      const checked = await this.checkQuote(input.auditId, input.source);
      sourceVerified = checked.verified;
      sourceDetail = checked.detail;
      source = checked.source;
      // A quote that does not occur in the snapshot makes the source claim
      // false, so the candidate cannot become a finding.
      if (!checked.verified) {
        const candidateId = uid();
        this.store.run(
          `INSERT INTO candidates
           (id, audit_id, area_id, discovery_task_id, discovery_session_id, title, category, cwe, severity,
            status, finding_id, provenance, link_key, payload, created_at)
           VALUES (?, ?, NULL, NULL, NULL, ?, ?, NULL, ?, 'refuted', NULL, 'dynamic', NULL, ?, ?)`,
          candidateId,
          input.auditId,
          input.title.trim(),
          input.category.trim(),
          input.severity,
          toJson({
            asset_id: input.assetId,
            manifest: input.manifest,
            source_check: { verified: false, detail: checked.detail },
            proposed_by: input.proposedBy,
          }),
          now(),
        );
        throw badRequest(`The source quote was not found in ${input.source.path}: ${checked.detail}`);
      }
    }

    const candidateId = uid();
    const proposal: StoredProposal = {
      asset_id: input.assetId,
      intent_node_id: input.intentNodeId ?? null,
      manifest: input.manifest,
      script: redact(input.script),
      impact: input.impact ?? null,
      remediation: input.remediation ?? null,
      source,
      source_verified: sourceVerified,
      proposed_by: input.proposedBy,
    };
    this.store.run(
      `INSERT INTO candidates
       (id, audit_id, area_id, discovery_task_id, discovery_session_id, title, category, cwe, severity,
        status, finding_id, provenance, link_key, payload, created_at)
       VALUES (?, ?, NULL, NULL, NULL, ?, ?, NULL, ?, 'discovered', NULL, 'dynamic', ?, ?, ?)`,
      candidateId,
      input.auditId,
      input.title.trim(),
      input.category.trim(),
      input.severity,
      source ? `${source.path}:${input.category.trim()}` : null,
      toJson(proposal),
      now(),
    );
    return { candidateId, sourceVerified, sourceDetail };
  }

  /**
   * An independent run confirms a proposed candidate: it replays the PoC
   * through the broker and only then writes the finding and its evidence.
   */
  async confirm(candidateId: string, confirmedBy: string): Promise<ConfirmResult> {
    return confirmations.run(candidateId, () => this.confirmInternal(candidateId, confirmedBy));
  }

  private async confirmInternal(candidateId: string, confirmedBy: string): Promise<ConfirmResult> {
    const row = this.store.get<CandidateRow>("SELECT * FROM candidates WHERE id = ?", candidateId);
    if (!row) throw notFound("Candidate not found");
    if (row.provenance !== "dynamic") throw badRequest("Only dynamic candidates are confirmed here");
    if (!["discovered", "confirming"].includes(row.status)) {
      throw conflict(`Candidate is ${row.status} and cannot be confirmed again`);
    }
    const proposal = JSON.parse(row.payload) as StoredProposal;
    if (!proposal?.manifest) throw conflict("Candidate has no PoC manifest");
    if (!confirmedBy?.trim()) throw badRequest("confirmed_by is required");
    if (confirmedBy === proposal.proposed_by) {
      throw conflict("A candidate cannot be confirmed by the task that proposed it");
    }
    const audit = this.store.get<AuditRow>(
      "SELECT id, project_id, repository_id, mode FROM audits WHERE id = ?",
      row.audit_id,
    );
    if (!audit) throw notFound("Audit not found");

    const claimed = this.store.changes(
      "UPDATE candidates SET status = 'confirming' WHERE id = ? AND status IN ('discovered','confirming')",
      candidateId,
    );
    if (claimed !== 1) {
      throw conflict("Candidate is already being confirmed or was decided by another request");
    }

    let replay: ProvenExchanges;
    try {
      replay = await this.replay(row.audit_id, proposal.manifest);
    } catch (error) {
      this.store.run("UPDATE candidates SET status = 'inconclusive' WHERE id = ? AND status = 'confirming'", candidateId);
      this.writeVerification(row, "INCONCLUSIVE", `The broker replay failed: ${String(error)}`, {}, confirmedBy);
      return {
        candidateId,
        verdict: "INCONCLUSIVE",
        findingId: null,
        code: null,
        evidenceIds: [],
        run: { status: "error", positive: false, exploit: false, negative: false, reason: "replay failed" },
      };
    }

    const run = evaluateRun(proposal.manifest, replay);
    if (run.status !== "passed") {
      // A transport/broker error cannot refute a candidate: only a run whose
      // positive control passed and whose exploit check failed can do that.
      const verdict = run.status === "failed" && run.positive ? "REFUTED" : "INCONCLUSIVE";
      this.store.run(
        "UPDATE candidates SET status = ? WHERE id = ? AND status = 'confirming'",
        verdict === "REFUTED" ? "refuted" : "inconclusive",
        candidateId,
      );
      this.writeVerification(row, verdict, `Replay verdict: ${run.reason ?? run.status}`, run, confirmedBy);
      return { candidateId, verdict, findingId: null, code: null, evidenceIds: [], run };
    }

    const result = await this.writeFinding(row, audit, proposal, replay, run, confirmedBy);
    return { candidateId, verdict: "CONFIRMED", ...result, run };
  }

  private async writeFinding(
    row: CandidateRow,
    audit: AuditRow,
    proposal: StoredProposal,
    replay: ProvenExchanges,
    run: PocRunResult,
    confirmedBy: string,
  ): Promise<{ findingId: string; code: string; evidenceIds: string[] }> {
    const findingId = uid();
    let code = "";
    const commit = audit.repository_id
      ? this.store.get<{ commit_sha: string | null }>(
          "SELECT commit_sha FROM repositories WHERE id = ?",
          audit.repository_id,
        )?.commit_sha ?? null
      : null;

    const scriptEvidence = await this.evidence.append({
      auditId: row.audit_id,
      findingId,
      kind: "poc_script",
      title: `${row.title} PoC script`,
      content: proposal.script,
      redacted: true,
    });
    const exchangeIds: string[] = [];
    for (const name of ["positive", "exploit", "negative"] as const) {
      const check = proposal.manifest.checks[name];
      const exchange = replay[name];
      const evidenceRow = await this.evidence.append({
        auditId: row.audit_id,
        findingId,
        kind: "http_exchange",
        title: `${row.title} ${name} exchange`,
        content: {
          check: name,
          identity: check.identity,
          method: check.request.method,
          path: check.request.path,
          status: exchange.status,
          body: redact(exchange.evidenceBody ?? exchange.body),
        },
        redacted: true,
      });
      exchangeIds.push(evidenceRow.id);
    }
    const proofEvidence = await this.evidence.append({
      auditId: row.audit_id,
      findingId,
      kind: "dynamic_proof",
      title: `${row.title} proof`,
      content: {
        manifest: { ...proposal.manifest, script_evidence_id: scriptEvidence.id },
        result: run,
        confirmed_by: confirmedBy,
        exchanges: {
          positive: { status: replay.positive.status, body_sha256: sha256(replay.positive.evidenceBody ?? replay.positive.body) },
          exploit: { status: replay.exploit.status, body_sha256: sha256(replay.exploit.evidenceBody ?? replay.exploit.body) },
          negative: { status: replay.negative.status, body_sha256: sha256(replay.negative.evidenceBody ?? replay.negative.body) },
        },
      },
      redacted: true,
    });

    const positive = proposal.manifest.checks.positive;
    const exploit = proposal.manifest.checks.exploit;
    const negative = proposal.manifest.checks.negative;
    const observed = `${exploit.identity} received HTTP ${replay.exploit.status} for ${proposal.manifest.object.object_id}, an object owned by ${proposal.manifest.object.owner_identity}.`;
    const source = proposal.source;
    const rootCause = source
      ? `The handler at ${source.path}:${source.start_line} does not enforce object ownership.`
      : "No source root cause was identified. The finding is proven by the reproducible exchange.";
    const impact =
      proposal.impact ??
      `An authenticated identity can read another identity's ${proposal.manifest.object.object_id}.`;
    const remediation =
      proposal.remediation ?? "Enforce object ownership on the handler before returning the object.";
    const files = source
      ? toJson([{ path: source.path, start_line: source.start_line, end_line: source.end_line }])
      : "[]";
    const evidenceIds = [scriptEvidence.id, ...exchangeIds, proofEvidence.id];

    this.store.transaction(() => {
      // Allocate the human-readable code inside the transaction so two
      // confirmations for different candidates cannot choose the same code.
      code = this.nextCode(row.audit_id);
      this.store.run(
        `INSERT INTO findings
         (id, code, audit_id, project_id, candidate_id, title, category, cwe, severity, status,
          repository_commit, files, root_cause, preconditions, reproduction, expected, observed,
          impact, remediation, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 'confirmed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        findingId,
        code,
        row.audit_id,
        audit.project_id,
        row.id,
        row.title,
        row.category,
        row.severity,
        commit,
        files,
        rootCause,
        toJson([
          `Authenticated as ${exploit.identity}.`,
          `Object ${proposal.manifest.object.object_id} belongs to ${proposal.manifest.object.owner_identity}.`,
        ]),
        toJson([
          `Authenticate as ${positive.identity} and request ${positive.request.method} ${positive.request.path}; expect ${String(positive.expect.status)} (positive control).`,
          `Authenticate as ${exploit.identity} and request ${exploit.request.method} ${exploit.request.path}; expected ${String(exploit.expect.status)}.`,
          `Authenticate as ${negative.identity} and request ${negative.request.method} ${negative.request.path}; expect ${String(negative.expect.status)} (negative control).`,
        ]),
        `The ${exploit.identity} must not receive an object owned by ${proposal.manifest.object.owner_identity}.`,
        observed,
        impact,
        remediation,
        now(),
        now(),
      );
      const updated = this.store.changes(
        "UPDATE candidates SET status = 'confirmed', finding_id = ? WHERE id = ? AND status = 'confirming'",
        findingId,
        row.id,
      );
      if (updated !== 1) throw new Error("The candidate was not in a confirming state");
    });

    this.writeVerification(row, "CONFIRMED", "An independent replay passed all three PoC checks.", run, confirmedBy);

    const node = this.graph.createNode({
      auditId: row.audit_id,
      kind: "finding",
      status: "completed",
      payload: { finding_id: findingId, candidate_id: row.id, code, title: row.title },
    });
    this.graph.anchor(node.id, proposal.asset_id);
    if (proposal.intent_node_id) {
      const intent = this.graph.getNode(proposal.intent_node_id);
      if (intent && intent.auditId === row.audit_id) this.graph.linkNodes(intent.id, node.id, "proves");
    }

    return { findingId, code, evidenceIds };
  }

  private writeVerification(
    row: CandidateRow,
    verdict: string,
    rationale: string,
    evidenceCheck: Record<string, unknown>,
    confirmedBy: string,
  ): void {
    this.store.run(
      `INSERT INTO verifications
       (id, audit_id, candidate_id, finding_id, kind, agent_session_id, discovery_session_id, verdict,
        rationale, evidence_check, payload, created_at)
       VALUES (?, ?, ?, ?, 'confirmation', NULL, NULL, ?, ?, ?, ?, ?)`,
      uid(),
      row.audit_id,
      row.id,
      row.finding_id,
      verdict,
      rationale,
      toJson(evidenceCheck),
      toJson({ source: "broker_replay", confirmed_by: confirmedBy }),
      now(),
    );
  }

  private async checkQuote(
    auditId: string,
    source: { path: string; start_line: number; end_line: number; quote: string },
  ): Promise<{
    verified: boolean;
    detail: string;
    source: { path: string; start_line: number; end_line: number; quote: string };
  }> {
    const snapshot = new TargetService(this.store).getSnapshot(auditId)?.snapshot;
    const repositoryId = snapshot?.repository?.id ?? null;
    const repository = repositoryId
      ? this.store.get<{ path: string }>("SELECT path FROM repositories WHERE id = ?", repositoryId)
      : null;
    if (!repository || !existsSync(repository.path)) {
      return { verified: false, detail: "No imported repository snapshot is attached to this audit.", source };
    }
    const check = await verifyQuote(
      repository.path,
      { include: ["**/*"], exclude: [] },
      { path: source.path, quote: source.quote },
    );
    return {
      verified: check.found,
      detail: check.detail,
      source: {
        path: check.path,
        start_line: check.line_start ?? source.start_line,
        end_line: check.line_end ?? source.end_line,
        quote: source.quote,
      },
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
