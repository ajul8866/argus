import type { Store } from "../db/index.ts";
import { AppError, badRequest, notFound, now, sha256, toJson, uid } from "../util.ts";

export type AuthorizedActions = {
  methods?: string[];
  allow_state_changing?: boolean;
  allow_file_upload?: boolean;
  allow_bruteforce?: boolean;
  require_approval_for?: string[];
};

export type Restrictions = {
  allowed_paths?: string[];
  denied_paths?: string[];
  notes?: string;
};

export type ProjectTarget = {
  id: string;
  projectId: string;
  label: string;
  baseUrl: string;
  environment: string;
  repositoryId: string | null;
  allowedHosts: string[];
  allowedCidrs: string[];
  allowedMethods: string[];
  maxRps: number;
  tlsRequired: boolean;
  status: "active" | "disabled";
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
};

export type TargetAuthorization = {
  id: string;
  targetId: string;
  authorizedBy: string;
  reference: string;
  validFrom: string;
  validUntil: string;
  authorizedActions: AuthorizedActions;
  restrictions: Restrictions;
  status: "active" | "expired" | "revoked";
  createdBy: string | null;
  createdAt: string;
};

export type TestIdentity = {
  id: string;
  targetId: string;
  label: string;
  role: string;
  authKind: "none" | "header" | "cookie" | "basic";
  status: "active" | "expired" | "disabled";
  createdAt: string;
  updatedAt: string;
};

export type CreateTargetInput = {
  projectId: string;
  label: string;
  baseUrl: string;
  environment: string;
  repositoryId?: string | null;
  allowedHosts: string[];
  allowedCidrs?: string[];
  allowedMethods?: string[];
  maxRps?: number;
  tlsRequired?: boolean;
  createdBy?: string | null;
};

export type CreateAuthorizationInput = {
  targetId: string;
  authorizedBy: string;
  reference: string;
  validFrom: string;
  validUntil: string;
  authorizedActions: AuthorizedActions;
  restrictions?: Restrictions;
  createdBy?: string | null;
};

export type CreateIdentityInput = {
  targetId: string;
  label: string;
  role: string;
  authKind: "none" | "header" | "cookie" | "basic";
  secretRef?: string | null;
  status?: "active" | "expired" | "disabled";
};

export type AuditBudget = {
  max_usd: number;
  exploration_cap_usd: number;
  verification_reserve_usd: number;
  max_tasks: number;
  max_requests: number;
  max_runtime_minutes: number;
};

export type AuditScopeSnapshot = {
  mode: "static" | "dynamic" | "hybrid";
  target: {
    id: string;
    base_url: string;
    allowed_hosts: string[];
    allowed_cidrs: string[];
    allowed_methods: string[];
    max_rps: number;
    tls: boolean;
  };
  authorization: {
    id: string;
    authorized_by: string;
    reference: string;
    valid_from: string;
    valid_until: string;
    authorized_actions: AuthorizedActions;
    restrictions: Restrictions;
  };
  identities: Array<{ id: string; role: string }>;
  permissions: string[];
  budget: AuditBudget;
  repository: { id: string; commit_sha: string | null } | null;
  created_by: string | null;
  created_at: string;
};

export type CreateSnapshotInput = {
  auditId: string;
  mode: "static" | "dynamic" | "hybrid";
  targetId: string;
  permissions: string[];
  budget: AuditBudget;
  repository: { id: string; commit_sha: string | null } | null;
  createdBy?: string | null;
  at?: string;
};

type TargetRow = {
  id: string;
  project_id: string;
  label: string;
  base_url: string;
  environment: string;
  repository_id: string | null;
  allowed_hosts: string;
  allowed_cidrs: string;
  allowed_methods: string;
  max_rps: number;
  tls_required: number;
  status: "active" | "disabled";
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

type AuthorizationRow = {
  id: string;
  target_id: string;
  authorized_by: string;
  authorization_ref: string;
  valid_from: string;
  valid_until: string;
  authorized_actions: string;
  restrictions: string;
  status: "active" | "expired" | "revoked";
  created_by: string | null;
  created_at: string;
};

type IdentityRow = {
  id: string;
  target_id: string;
  label: string;
  role: string;
  auth_kind: "none" | "header" | "cookie" | "basic";
  secret_ref: string | null;
  status: "active" | "expired" | "disabled";
  created_at: string;
  updated_at: string;
};

type SnapshotRow = {
  audit_id: string;
  created_at: string;
  snapshot: string;
  sha256: string;
};

function parseArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function parseObject<T>(value: string, fallback: T): T {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as T) : fallback;
  } catch {
    return fallback;
  }
}

function targetFromRow(row: TargetRow): ProjectTarget {
  return {
    id: row.id,
    projectId: row.project_id,
    label: row.label,
    baseUrl: row.base_url,
    environment: row.environment,
    repositoryId: row.repository_id,
    allowedHosts: parseArray(row.allowed_hosts),
    allowedCidrs: parseArray(row.allowed_cidrs),
    allowedMethods: parseArray(row.allowed_methods),
    maxRps: row.max_rps,
    tlsRequired: row.tls_required === 1,
    status: row.status,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function authorizationFromRow(row: AuthorizationRow): TargetAuthorization {
  return {
    id: row.id,
    targetId: row.target_id,
    authorizedBy: row.authorized_by,
    reference: row.authorization_ref,
    validFrom: row.valid_from,
    validUntil: row.valid_until,
    authorizedActions: parseObject<AuthorizedActions>(row.authorized_actions, {}),
    restrictions: parseObject<Restrictions>(row.restrictions, {}),
    status: row.status,
    createdBy: row.created_by,
    createdAt: row.created_at,
  };
}

function identityFromRow(row: IdentityRow): TestIdentity {
  return {
    id: row.id,
    targetId: row.target_id,
    label: row.label,
    role: row.role,
    authKind: row.auth_kind,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function requireUrl(value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw badRequest("base_url must be an absolute URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw badRequest("base_url must use http or https");
  }
  if (parsed.username || parsed.password) {
    throw badRequest("base_url must not contain credentials");
  }
}

function normalizeHosts(hosts: string[]): string[] {
  const normalized = hosts.map((host) => host.trim().toLowerCase()).filter(Boolean);
  if (normalized.length === 0) throw badRequest("allowed_hosts must not be empty");
  for (const host of normalized) {
    if (host.includes("/") || host.includes("://")) throw badRequest("allowed_hosts entries must be hostnames");
  }
  return [...new Set(normalized)];
}

function normalizeMethods(methods: string[] | undefined): string[] {
  const normalized = (methods ?? ["GET", "HEAD", "OPTIONS"]).map((method) => method.trim().toUpperCase()).filter(Boolean);
  if (normalized.length === 0) throw badRequest("allowed_methods must not be empty");
  return [...new Set(normalized)];
}

function parseTime(value: string, field: string): number {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw badRequest(`${field} must be an ISO timestamp`);
  return time;
}

export class TargetService {
  constructor(private readonly store: Store) {}

  createTarget(input: CreateTargetInput): ProjectTarget {
    if (!input.projectId || !this.store.get("SELECT id FROM projects WHERE id = ?", input.projectId)) {
      throw notFound("Project not found");
    }
    requireUrl(input.baseUrl);
    if (!input.label?.trim()) throw badRequest("label is required");
    if (!input.environment?.trim()) throw badRequest("environment is required");
    const maxRps = input.maxRps ?? 5;
    if (!Number.isFinite(maxRps) || maxRps <= 0) throw badRequest("max_rps must be positive");
    const hosts = normalizeHosts(input.allowedHosts ?? []);
    const cidrs = [...new Set((input.allowedCidrs ?? []).map((cidr) => cidr.trim()).filter(Boolean))];
    if (cidrs.length === 0 && hosts.length === 0) throw badRequest("a target needs at least one allowed host or CIDR");
    const methods = normalizeMethods(input.allowedMethods);
    const timestamp = now();
    const id = uid();

    this.store.run(
      `INSERT INTO project_targets
       (id, project_id, label, base_url, environment, repository_id, allowed_hosts, allowed_cidrs,
        allowed_methods, max_rps, tls_required, status, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
      id,
      input.projectId,
      input.label.trim(),
      input.baseUrl,
      input.environment.trim(),
      input.repositoryId ?? null,
      toJson(hosts),
      toJson(cidrs),
      toJson(methods),
      maxRps,
      input.tlsRequired === false ? 0 : 1,
      input.createdBy ?? null,
      timestamp,
      timestamp,
    );

    return this.getTarget(id)!;
  }

  getTarget(id: string): ProjectTarget | null {
    const row = this.store.get<TargetRow>("SELECT * FROM project_targets WHERE id = ?", id);
    return row ? targetFromRow(row) : null;
  }

  listTargets(projectId: string): ProjectTarget[] {
    return this.store
      .all<TargetRow>("SELECT * FROM project_targets WHERE project_id = ? ORDER BY created_at, id", projectId)
      .map(targetFromRow);
  }

  createAuthorization(input: CreateAuthorizationInput): TargetAuthorization {
    const target = this.getTarget(input.targetId);
    if (!target) throw notFound("Target not found");
    if (!input.authorizedBy?.trim()) throw badRequest("authorized_by is required");
    if (!input.reference?.trim()) throw badRequest("authorization reference is required");
    const starts = parseTime(input.validFrom, "valid_from");
    const ends = parseTime(input.validUntil, "valid_until");
    if (ends <= starts) throw badRequest("authorization valid_until must be after valid_from");
    if (!input.authorizedActions || typeof input.authorizedActions !== "object") {
      throw badRequest("authorized_actions is required");
    }
    const id = uid();
    // Store canonical UTC so the lexical comparison in activeAuthorization
    // cannot be fooled by an offset such as +14:00.
    this.store.run(
      `INSERT INTO target_authorizations
       (id, target_id, authorized_by, authorization_ref, valid_from, valid_until, authorized_actions,
        restrictions, status, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
      id,
      input.targetId,
      input.authorizedBy.trim(),
      input.reference.trim(),
      new Date(starts).toISOString(),
      new Date(ends).toISOString(),
      toJson(input.authorizedActions),
      toJson(input.restrictions ?? {}),
      input.createdBy ?? null,
      now(),
    );
    return this.getAuthorization(id)!;
  }

  getAuthorization(id: string): TargetAuthorization | null {
    const row = this.store.get<AuthorizationRow>("SELECT * FROM target_authorizations WHERE id = ?", id);
    return row ? authorizationFromRow(row) : null;
  }

  listAuthorizations(targetId: string): TargetAuthorization[] {
    return this.store
      .all<AuthorizationRow>(
        "SELECT * FROM target_authorizations WHERE target_id = ? ORDER BY created_at DESC, id",
        targetId,
      )
      .map(authorizationFromRow);
  }

  activeAuthorization(targetId: string, at: string = now()): TargetAuthorization | null {
    const row = this.store.get<AuthorizationRow>(
      `SELECT * FROM target_authorizations
       WHERE target_id = ? AND status = 'active' AND valid_from <= ? AND valid_until >= ?
       ORDER BY valid_until DESC LIMIT 1`,
      targetId,
      at,
      at,
    );
    return row ? authorizationFromRow(row) : null;
  }

  createIdentity(input: CreateIdentityInput): TestIdentity {
    const target = this.getTarget(input.targetId);
    if (!target) throw notFound("Target not found");
    if (!input.label?.trim()) throw badRequest("label is required");
    if (!input.role?.trim()) throw badRequest("role is required");
    if (!["none", "header", "cookie", "basic"].includes(input.authKind)) {
      throw badRequest("auth_kind must be none, header, cookie, or basic");
    }
    if (input.authKind !== "none" && !input.secretRef) {
      throw badRequest("secret_ref is required for an authenticated identity");
    }
    const timestamp = now();
    const id = uid();
    this.store.run(
      `INSERT INTO test_identities
       (id, target_id, label, role, auth_kind, secret_ref, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      input.targetId,
      input.label.trim(),
      input.role.trim(),
      input.authKind,
      input.secretRef ?? null,
      input.status ?? "active",
      timestamp,
      timestamp,
    );
    return this.getIdentity(id)!;
  }

  getIdentity(id: string): TestIdentity | null {
    const row = this.store.get<IdentityRow>("SELECT * FROM test_identities WHERE id = ?", id);
    return row ? identityFromRow(row) : null;
  }

  listIdentities(targetId: string): TestIdentity[] {
    return this.store
      .all<IdentityRow>("SELECT * FROM test_identities WHERE target_id = ? ORDER BY created_at, id", targetId)
      .map(identityFromRow);
  }

  getIdentitySecretRef(id: string): string | null {
    const row = this.store.get<{ secret_ref: string | null }>(
      "SELECT secret_ref FROM test_identities WHERE id = ?",
      id,
    );
    return row?.secret_ref ?? null;
  }

  createSnapshot(input: CreateSnapshotInput): { snapshot: AuditScopeSnapshot; sha256: string } {
    if (this.store.get("SELECT audit_id FROM audit_scope_snapshots WHERE audit_id = ?", input.auditId)) {
      throw new AppError(409, "scope_snapshot_exists", "This audit already has a scope snapshot");
    }
    const target = this.getTarget(input.targetId);
    if (!target) throw notFound("Target not found");
    if (target.status !== "active") throw new AppError(409, "target_disabled", "Target is disabled");
    const authorization = this.activeAuthorization(target.id, input.at);
    if (!authorization) {
      throw new AppError(409, "authorization_invalid", "No active authorization covers this audit");
    }
    const identities = this.listIdentities(target.id).filter((identity) => identity.status === "active");
    if (identities.length === 0) {
      throw new AppError(409, "identity_required", "At least one active test identity is required");
    }
    const createdAt = now();
    const snapshot: AuditScopeSnapshot = {
      mode: input.mode,
      target: {
        id: target.id,
        base_url: target.baseUrl,
        allowed_hosts: target.allowedHosts,
        allowed_cidrs: target.allowedCidrs,
        allowed_methods: target.allowedMethods,
        max_rps: target.maxRps,
        tls: target.tlsRequired,
      },
      authorization: {
        id: authorization.id,
        authorized_by: authorization.authorizedBy,
        reference: authorization.reference,
        valid_from: authorization.validFrom,
        valid_until: authorization.validUntil,
        authorized_actions: authorization.authorizedActions,
        restrictions: authorization.restrictions,
      },
      identities: identities.map((identity) => ({ id: identity.id, role: identity.role })),
      permissions: [...new Set(input.permissions)],
      budget: input.budget,
      repository: input.repository,
      created_by: input.createdBy ?? null,
      created_at: createdAt,
    };
    const canonical = JSON.stringify(snapshot);
    const digest = sha256(canonical);
    this.store.run(
      "INSERT INTO audit_scope_snapshots (audit_id, created_at, snapshot, sha256) VALUES (?, ?, ?, ?)",
      input.auditId,
      createdAt,
      canonical,
      digest,
    );
    return { snapshot, sha256: digest };
  }

  getSnapshot(auditId: string): { snapshot: AuditScopeSnapshot; sha256: string } | null {
    const row = this.store.get<SnapshotRow>("SELECT * FROM audit_scope_snapshots WHERE audit_id = ?", auditId);
    if (!row) return null;
    return { snapshot: JSON.parse(row.snapshot) as AuditScopeSnapshot, sha256: row.sha256 };
  }
}
