import type { QuoteCheck } from "../repo/workspace.ts";
import { verifyQuote } from "../repo/workspace.ts";
import type { Scope } from "../util.ts";

export type ExcerptInput = { path: string; quote: string; start_line?: number; end_line?: number };

export type EvidenceEvaluation = {
  checks: QuoteCheck[];
  /** Excerpts that occur in the repository at the audited snapshot. */
  verifiedCount: number;
  /** Verified excerpts located in a file the candidate or finding affects. */
  relevantCount: number;
};

/**
 * The platform evidence gate shared by independent confirmation and
 * reverification: verify every agent-supplied excerpt against the repository
 * snapshot, then count how many land on an affected file.
 */
export async function evaluateEvidence(
  repoRoot: string,
  scope: Scope,
  excerpts: ExcerptInput[],
  affectedPaths: ReadonlySet<string>,
): Promise<EvidenceEvaluation> {
  const checks: QuoteCheck[] = [];
  for (const excerpt of excerpts) {
    checks.push(await verifyQuote(repoRoot, scope, excerpt));
  }
  const verifiedCount = checks.filter((check) => check.found).length;
  const relevantCount = checks.filter((check) => check.found && affectedPaths.has(check.path)).length;
  return { checks, verifiedCount, relevantCount };
}
