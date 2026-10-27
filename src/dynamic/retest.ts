import type { Store } from "../db/index.ts";
import { badRequest, notFound, now, toJson, uid } from "../util.ts";

export type RetestVerdict = "still_reproducible" | "fixed" | "cannot_confirm";

export type RetestExecutorResult = {
  positivePassed: boolean;
  exploitPassed: boolean;
  evidenceRefs: string[];
  error?: string;
};

export type RetestExecutor = (input: {
  findingId: string;
  auditId: string;
  environmentManifest: string;
  positiveCheck: string | null;
}) => Promise<RetestExecutorResult>;

export type RequestRetestInput = {
  findingId: string;
  auditId: string;
  reason: string;
  fixReference?: string | null;
  authorizationSnapshot: string;
  environmentManifest: string;
  commitSha?: string | null;
  buildRef?: string | null;
  environmentMatch?: boolean;
  positiveCheck?: string | null;
  requestedBy?: string | null;
};

type RetestRow = {
  id: string;
  finding_id: string;
  audit_id: string;
  requested_by: string | null;
  reason: string;
  fix_reference: string | null;
  authorization_snapshot: string;
  environment_manifest: string;
  commit_sha: string | null;
  build_ref: string | null;
  environment_match: number | null;
  executed_by: string | null;
  positive_check: string | null;
  status: "queued" | "running" | "completed" | "failed";
  verdict: RetestVerdict | null;
  evidence_refs: string | null;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
};

export function retestVerdict(
  positivePassed: boolean,
  exploitPassed: boolean,
  environmentMatch: boolean,
): RetestVerdict {
  if (!positivePassed) return "cannot_confirm";
  if (exploitPassed) return "still_reproducible";
  if (!environmentMatch) return "cannot_confirm";
  return "fixed";
}

export class RetestService {
  constructor(
    private readonly store: Store,
    private readonly executor: RetestExecutor,
  ) {}

  request(input: RequestRetestInput): string {
    const finding = this.store.get<{ id: string; audit_id: string }>(
      "SELECT id, audit_id FROM findings WHERE id = ?",
      input.findingId,
    );
    if (!finding) throw notFound("Finding not found");
    if (finding.audit_id !== input.auditId) throw badRequest("Finding belongs to another audit");
    if (!input.reason?.trim()) throw badRequest("reason is required");
    if (!input.authorizationSnapshot) throw badRequest("authorization_snapshot is required");
    if (!input.environmentManifest) throw badRequest("environment_manifest is required");
    const id = uid();
    this.store.run(
      `INSERT INTO retests
       (id, finding_id, audit_id, requested_by, reason, fix_reference, authorization_snapshot,
        environment_manifest, commit_sha, build_ref, environment_match, executed_by, positive_check,
        status, verdict, evidence_refs, started_at, ended_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, 'queued', NULL, NULL, NULL, NULL, ?)`,
      id,
      input.findingId,
      input.auditId,
      input.requestedBy ?? null,
      input.reason.trim(),
      input.fixReference ?? null,
      input.authorizationSnapshot,
      input.environmentManifest,
      input.commitSha ?? null,
      input.buildRef ?? null,
      input.environmentMatch === false ? 0 : 1,
      input.positiveCheck ?? null,
      now(),
    );
    return id;
  }

  async run(retestId: string): Promise<RetestVerdict> {
    const row = this.store.get<RetestRow>("SELECT * FROM retests WHERE id = ?", retestId);
    if (!row) throw notFound("Retest not found");
    if (row.status === "completed" && row.verdict) return row.verdict;
    this.store.run(
      "UPDATE retests SET status = 'running', started_at = COALESCE(started_at, ?) WHERE id = ?",
      now(),
      retestId,
    );
    try {
      const result = await this.executor({
        findingId: row.finding_id,
        auditId: row.audit_id,
        environmentManifest: row.environment_manifest,
        positiveCheck: row.positive_check,
      });
      const verdict = retestVerdict(
        result.positivePassed,
        result.exploitPassed,
        row.environment_match === 1,
      );
      this.store.run(
        `UPDATE retests SET status = 'completed', verdict = ?, evidence_refs = ?, positive_check = ?,
           executed_by = ?, ended_at = ? WHERE id = ?`,
        verdict,
        toJson(result.evidenceRefs),
        toJson({ positivePassed: result.positivePassed, exploitPassed: result.exploitPassed }),
        "retester",
        now(),
        retestId,
      );
      return verdict;
    } catch (error) {
      this.store.run(
        "UPDATE retests SET status = 'failed', verdict = 'cannot_confirm', evidence_refs = ?, ended_at = ? WHERE id = ?",
        toJson({ error: error instanceof Error ? error.message : String(error) }),
        now(),
        retestId,
      );
      return "cannot_confirm";
    }
  }
}
