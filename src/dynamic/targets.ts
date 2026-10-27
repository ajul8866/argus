import type { Store } from "../db/index.ts";
import { badRequest, notFound, now, toJson, uid } from "../util.ts";

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
    this.store.run(
      `INSERT INTO target_authorizations
       (id, target_id, authorized_by, authorization_ref, valid_from, valid_until, authorized_actions,
        restrictions, status, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
      id,
      input.targetId,
      input.authorizedBy.trim(),
      input.reference.trim(),
      input.validFrom,
      input.validUntil,
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
}
