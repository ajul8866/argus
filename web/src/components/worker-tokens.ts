import { api } from "../api.ts";

/** A worker never gets confirmation rights: a candidate cannot confirm itself. */
export const WORKER_SCOPES = ["audit:read", "audit:propose_candidate"] as const;

export type WorkerToken = { id: string; raw: string };

export async function createWorkerToken(auditId: string, label: string): Promise<WorkerToken> {
  const { token } = await api<{ token: { id: string; raw: string } }>("/api/tokens", {
    method: "POST",
    body: { label, audit_id: auditId, scopes: [...WORKER_SCOPES] },
  });
  return { id: token.id, raw: token.raw };
}

export async function revokeWorkerToken(tokenId: string): Promise<void> {
  await api(`/api/tokens/${encodeURIComponent(tokenId)}`, { method: "DELETE" });
}

export type WorkerTokenRow = {
  id: string;
  label: string;
  scopes: string[];
  audit_id: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
};

export async function listWorkerTokens(): Promise<WorkerTokenRow[]> {
  const { tokens } = await api<{ tokens: WorkerTokenRow[] }>("/api/tokens");
  return tokens;
}
