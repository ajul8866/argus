import { randomBytes } from "node:crypto";
import type { Store } from "../db/index.ts";
import { badRequest, notFound, now, parseJson, sha256, toJson, uid } from "../util.ts";

export type ApiToken = {
  id: string;
  userId: string;
  label: string;
  scopes: string[];
  projectId: string | null;
  auditId: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
};

export type TokenUser = {
  id: string;
  email: string;
  name: string;
  role: string;
};

export type CreateTokenInput = {
  userId: string;
  label: string;
  scopes: string[];
  projectId?: string | null;
  auditId?: string | null;
  expiresAt?: string | null;
};

type TokenRow = {
  id: string;
  user_id: string;
  label: string;
  token_hash: string;
  scopes: string;
  project_id: string | null;
  audit_id: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
};

function tokenFromRow(row: TokenRow): ApiToken {
  return {
    id: row.id,
    userId: row.user_id,
    label: row.label,
    scopes: parseJson<string[]>(row.scopes, []),
    projectId: row.project_id,
    auditId: row.audit_id,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    lastUsedAt: row.last_used_at,
    createdAt: row.created_at,
  };
}

function isExpired(expiresAt: string | null, at: number): boolean {
  if (!expiresAt) return false;
  const timestamp = Date.parse(expiresAt);
  return !Number.isFinite(timestamp) || timestamp <= at;
}

export class TokenService {
  constructor(private readonly store: Store) {}

  create(input: CreateTokenInput): { token: ApiToken; raw: string } {
    const user = this.store.get<{ id: string }>("SELECT id FROM users WHERE id = ? AND disabled = 0", input.userId);
    if (!user) throw notFound("User not found");
    const label = input.label?.trim();
    if (!label) throw badRequest("label is required");
    const scopes = [...new Set((input.scopes ?? []).map((scope) => scope.trim()).filter(Boolean))];
    if (scopes.length === 0) throw badRequest("scopes must not be empty");
    if (input.projectId && !this.store.get("SELECT id FROM projects WHERE id = ?", input.projectId)) {
      throw notFound("Project not found");
    }
    if (input.auditId && !this.store.get("SELECT id FROM audits WHERE id = ?", input.auditId)) {
      throw notFound("Audit not found");
    }
    const raw = `argus_${randomBytes(32).toString("base64url")}`;
    const id = uid();
    const timestamp = now();
    const expiresAt = input.expiresAt === undefined
      ? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
      : input.expiresAt;
    this.store.run(
      `INSERT INTO api_tokens
       (id, user_id, label, token_hash, scopes, project_id, audit_id, expires_at, revoked_at, last_used_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`,
      id,
      input.userId,
      label,
      sha256(raw),
      toJson(scopes),
      input.projectId ?? null,
      input.auditId ?? null,
      expiresAt,
      timestamp,
    );
    return { token: this.get(id)!, raw };
  }

  get(id: string): ApiToken | null {
    const row = this.store.get<TokenRow>("SELECT * FROM api_tokens WHERE id = ?", id);
    return row ? tokenFromRow(row) : null;
  }

  verify(raw: string): { token: ApiToken; user: TokenUser } | null {
    if (!raw.startsWith("argus_")) return null;
    const row = this.store.get<TokenRow>("SELECT * FROM api_tokens WHERE token_hash = ?", sha256(raw));
    if (!row) return null;
    if (row.revoked_at) return null;
    if (isExpired(row.expires_at, Date.now())) return null;
    const user = this.store.get<TokenUser & { disabled: number }>(
      "SELECT id, email, name, role, disabled FROM users WHERE id = ?",
      row.user_id,
    );
    if (!user || user.disabled === 1) return null;
    this.store.run("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", now(), row.id);
    return {
      token: tokenFromRow({ ...row, last_used_at: now() }),
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
    };
  }

  revoke(id: string): void {
    const changed = this.store.changes("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", now(), id);
    if (changed === 0) throw notFound("Token not found or already revoked");
  }

  listForUser(userId: string): ApiToken[] {
    return this.store
      .all<TokenRow>("SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC, id", userId)
      .map(tokenFromRow);
  }

  hasScope(token: ApiToken, scope: string): boolean {
    return token.scopes.includes(scope);
  }

  allowsProject(token: ApiToken, projectId: string): boolean {
    return token.projectId === null || token.projectId === projectId;
  }

  allowsAudit(token: ApiToken, auditId: string): boolean {
    return token.auditId === null || token.auditId === auditId;
  }
}
