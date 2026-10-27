import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import type { Config } from "../config.ts";
import { APP_NAME, APP_VERSION, PHASE_NAMES } from "../config.ts";
import { DEFAULT_SETTINGS } from "../settings.ts";
import type { Store } from "../db/index.ts";
import type { AuthContext, AuthService, User } from "../auth.ts";
import { roleAtLeast } from "../auth.ts";
import type { EventLog, LiveEvent } from "../events.ts";
import type { HarnessManager } from "../harness/manager.ts";
import type { HarnessConfig, HarnessKind } from "../harness/types.ts";
import type { AuditEngine } from "../orchestrator/engine.ts";
import type { EvidenceStore, EvidenceRow } from "../orchestrator/evidence.ts";
import type { ReportService } from "../reports/generator.ts";
import { REPORT_FORMATS, type ReportFormat } from "../reports/generator.ts";
import { DEFAULT_EXCLUDES } from "../repo/inventory.ts";
import { importRepository } from "../repo/import.ts";
import { assertAuthorizedRoot, readScopedFile } from "../repo/workspace.ts";
import { listRepositoryFolders } from "../repo/directories.ts";
import { agentDefinition, getSetting, harnessConfig, listAgents, listSettings, saveHarnessConfig, setSetting } from "../settings.ts";
import { decryptSecret, encryptSecret, type StoredCredential } from "../security/credentials.ts";
import { redactObject, redactSecrets } from "../security/redact.ts";
import {
  AppError,
  badRequest,
  conflict,
  matchesScope,
  normalizePath,
  notFound,
  now,
  parseJson,
  safeJoin,
  sha256,
  toJson,
  uid,
  validateScopeGlobs,
} from "../util.ts";
import { clientIp, errorResponse, json, optionalString, readJson, requireString, requireStringArray } from "./http.ts";
import { sseResponse } from "./sse.ts";
import { LocalCatalog } from "../local/catalog.ts";
import { localResourceRoutes } from "./local-resources.ts";
import { TargetService, type AuthorizedActions, type Restrictions } from "../dynamic/targets.ts";
import { GraphStore } from "../dynamic/graph.ts";
import { runPocChecks } from "../dynamic/executor.ts";
import { DynamicProofService } from "../dynamic/proof.ts";
import { TokenService } from "../auth/tokens.ts";

type ApiDeps = {
  config: Config;
  store: Store;
  auth: AuthService;
  events: EventLog;
  manager: HarnessManager;
  engine: AuditEngine;
  evidence: EvidenceStore;
  reports: ReportService;
  catalog?: LocalCatalog;
};

type AuthUser = AuthContext["user"];

export function createApi(deps: ApiDeps): (request: Request, peerAddress?: string) => Promise<Response> {
  const catalog = deps.catalog ?? new LocalCatalog(deps.store);
  const targets = new TargetService(deps.store);
  const tokens = new TokenService(deps.store);
  return async (request: Request, peerAddress?: string): Promise<Response> => {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return json({ error: "not_found" }, 404);
    try {
      const path = url.pathname;
      const method = request.method.toUpperCase();
      const publicRoute = path === "/api/health" || (path === "/api/auth/login" && method === "POST");
      const bearer = request.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim() ?? null;
      const tokenAuth = !publicRoute && bearer ? tokens.verify(bearer) : null;
      if (!publicRoute && bearer && !tokenAuth) {
        return json({ error: { code: "unauthorized", message: "Invalid or expired token" } }, 401);
      }
      const authContext = publicRoute || bearer ? null : deps.auth.authenticate(request);
      if (!publicRoute && !authContext && !tokenAuth) {
        return json({ error: { code: "unauthorized", message: "Authentication required" } }, 401);
      }
      if (authContext && !["GET", "HEAD", "OPTIONS"].includes(method)) {
        const csrf = request.headers.get("x-csrf-token");
        if (!deps.auth.verifyCsrf(authContext.session, csrf)) {
          return json({ error: { code: "csrf_invalid", message: "Missing or invalid CSRF token" } }, 403);
        }
      }
      const ip = clientIp(peerAddress);
      const tokenUser: AuthUser | null = tokenAuth
        ? {
            id: tokenAuth.user.id,
            email: tokenAuth.user.email,
            name: tokenAuth.user.name,
            role: tokenAuth.user.role as User["role"],
            disabled: 0,
            created_at: "",
          }
        : null;
      const user = tokenUser ?? authContext?.user ?? null;
      const requireUser = (): AuthUser => {
        if (!user) throw new AppError(401, "unauthorized", "Authentication required");
        return user;
      };
      const requireRole = (role: User["role"]): AuthUser => {
        const current = requireUser();
        if (!roleAtLeast(current, role)) throw new AppError(403, "forbidden", `Requires ${role} role`);
        return current;
      };
      const requireScope = (scope: string): void => {
        if (tokenAuth && !tokens.hasScope(tokenAuth.token, scope)) {
          throw new AppError(403, "forbidden", `Token requires ${scope}`);
        }
      };
      const requireProjectScope = (projectId: string): void => {
        if (tokenAuth && !tokens.allowsProject(tokenAuth.token, projectId)) {
          throw new AppError(403, "forbidden", "Token is scoped to another project");
        }
      };
      const requireAuditScope = (auditId: string): void => {
        if (tokenAuth && !tokens.allowsAudit(tokenAuth.token, auditId)) {
          throw new AppError(403, "forbidden", "Token is scoped to another audit");
        }
      };

      if (path === "/api/health" && method === "GET") {
        return json({ status: "ok", name: APP_NAME, version: APP_VERSION, time: now() });
      }

      if (path === "/api/auth/login" && method === "POST") {
        const body = await readJson(request);
        const email = requireString(body, "email", 320);
        const password = requireString(body, "password", 512, false);
        try {
          const result = await deps.auth.login(
            email,
            password,
            ip,
            request.headers.get("user-agent") ?? "unknown",
          );
          deps.auth.logAction(result.user.email, "auth.login", result.user.id, { success: true }, ip);
          return json(
            { user: result.user, csrf: result.csrf, expires_at: result.expiresAt },
            200,
            { "set-cookie": deps.auth.sessionCookie(result.token) },
          );
        } catch (error) {
          deps.auth.logAction(email, "auth.login_failed", null, { error: String(error) }, ip);
          throw new AppError(401, "invalid_credentials", error instanceof Error ? error.message : "Sign-in failed");
        }
      }

      if (path === "/api/auth/me" && method === "GET") {
        const current = requireUser();
        return json({ user: current, csrf: authContext!.session.csrf_token });
      }

      if (path === "/api/auth/logout" && method === "POST") {
        const current = requireUser();
        deps.auth.logout(authContext!.session.id);
        deps.auth.logAction(current.email, "auth.logout", current.id, {}, ip);
        return json({ ok: true }, 200, { "set-cookie": deps.auth.clearCookie() });
      }

      if (path === "/api/auth/password" && method === "POST") {
        const current = requireUser();
        const body = await readJson(request);
        const currentPassword = requireString(body, "current_password", 512, false);
        const newPassword = requireString(body, "new_password", 512, false);
        try {
          await deps.auth.changePassword(current, currentPassword, newPassword, authContext!.session.id);
        } catch (error) {
          throw new AppError(400, "password_change_failed", error instanceof Error ? error.message : String(error));
        }
        deps.auth.logAction(current.email, "auth.password_changed", current.id, {}, ip);
        return json({ ok: true });
      }

      if (/^\/api\/(skills|mcp)(?:\/|$)/.test(path)) {
        return await localResourceRoutes(request, { catalog, auth: deps.auth, user: requireUser(), ip });
      }

      if (path === "/api/overview" && method === "GET") {
        requireUser();
        const recentAudits = deps.store.all(
          `SELECT a.id, a.status, a.current_phase, a.created_at, a.started_at, a.finished_at,
                  p.name AS project_name, r.commit_sha
           FROM audits a JOIN projects p ON p.id = a.project_id LEFT JOIN repositories r ON r.id = a.repository_id
           ORDER BY a.created_at DESC LIMIT 8`,
        );
        const recentEvents = deps.store.all(
          "SELECT * FROM execution_events WHERE audit_id IS NOT NULL ORDER BY id DESC LIMIT 25",
        );
        const findingCounts = deps.store.all<{ status: string; count: number }>(
          "SELECT status, COUNT(*) AS count FROM findings GROUP BY status",
        );
        const severityCounts = deps.store.all<{ severity: string; count: number }>(
          "SELECT severity, COUNT(*) AS count FROM findings WHERE status = 'reverified' GROUP BY severity",
        );
        const coverageCounts = deps.store.all<{ status: string; count: number }>(
          "SELECT status, COUNT(*) AS count FROM coverage GROUP BY status",
        );
        const totals = deps.store.get<{
          projects: number;
          audits: number;
          running_audits: number;
          tasks_running: number;
          tasks_queued: number;
          tasks_failed: number;
          active_sessions: number;
          sessions: number;
          pending_approvals: number;
        }>(
          `SELECT
             (SELECT COUNT(*) FROM projects) AS projects,
             (SELECT COUNT(*) FROM audits) AS audits,
             (SELECT COUNT(*) FROM audits WHERE status = 'running') AS running_audits,
             (SELECT COUNT(*) FROM tasks WHERE status = 'running') AS tasks_running,
             (SELECT COUNT(*) FROM tasks WHERE status IN ('queued','waiting_approval')) AS tasks_queued,
             (SELECT COUNT(*) FROM tasks WHERE status = 'failed') AS tasks_failed,
             (SELECT COUNT(*) FROM agent_sessions WHERE status IN ('starting','running')) AS active_sessions,
             (SELECT COUNT(*) FROM agent_sessions) AS sessions,
             (SELECT COUNT(*) FROM approvals WHERE status = 'pending') AS pending_approvals`,
        );
        return json({
          projects: totals?.projects ?? 0,
          audits: totals?.audits ?? 0,
          running_audits: totals?.running_audits ?? 0,
          tasks: {
            running: totals?.tasks_running ?? 0,
            queued: totals?.tasks_queued ?? 0,
            failed: totals?.tasks_failed ?? 0,
          },
          agents: {
            active_sessions: totals?.active_sessions ?? 0,
            sessions: totals?.sessions ?? 0,
          },
          findings: {
            by_status: Object.fromEntries(findingCounts.map((row) => [row.status, row.count])),
            by_severity: Object.fromEntries(severityCounts.map((row) => [row.severity, row.count])),
            total: findingCounts.reduce((sum, row) => sum + row.count, 0),
          },
          coverage: Object.fromEntries(coverageCounts.map((row) => [row.status, row.count])),
          harnesses: deps.manager.detections(),
          recent_audits: recentAudits,
          recent_events: recentEvents.map((row) => {
            const record = row as Record<string, unknown>;
            return {
              ...record,
              payload: parseJson<Record<string, unknown>>(String(record.payload ?? "{}"), {}),
            };
          }),
          pending_approvals: totals?.pending_approvals ?? 0,
        });
      }

      if (path === "/api/repository-folders" && method === "GET") {
        requireRole("auditor");
        return json(await listRepositoryFolders(deps.config.allowedRoots, {
          path: url.searchParams.get("path") ?? undefined,
          search: url.searchParams.get("search") ?? undefined,
          offset: url.searchParams.get("offset") ?? undefined,
        }));
      }

      if (path === "/api/projects" && method === "GET") {
        requireUser();
        const rows = deps.store.all(
          `SELECT p.*,
             (SELECT COUNT(*) FROM repositories r WHERE r.project_id = p.id) AS repository_count,
             (SELECT COUNT(*) FROM audits a WHERE a.project_id = p.id) AS audit_count,
             (SELECT MAX(created_at) FROM audits a WHERE a.project_id = p.id) AS last_audit_at
           FROM projects p ORDER BY p.created_at DESC`,
        );
        return json({ projects: rows.map(projectJson) });
      }

      if (path === "/api/projects" && method === "POST") {
        const current = requireRole("auditor");
        const body = await readJson(request);
        const name = requireString(body, "name", 200);
        const sourcePath = requireString(body, "source_path", 2_000);
        const authorizedBy = optionalString(body, "authorized_by", 300) ?? "";
        const authorizationRef = optionalString(body, "authorization_ref", 500) ?? "";
        const maximumAgents = body.max_concurrent_agents;
        if (maximumAgents !== undefined && maximumAgents !== null &&
            (typeof maximumAgents !== "number" || !Number.isInteger(maximumAgents) || maximumAgents < 1 || maximumAgents > 16)) {
          throw badRequest("max_concurrent_agents must be an integer between 1 and 16 or null");
        }
        const include = requireStringArray(body, "scope_include", ["**/*"]);
        const exclude = requireStringArray(body, "scope_exclude", DEFAULT_EXCLUDES);
        validateScopeGlobs(include);
        validateScopeGlobs(exclude);
        const realPath = await assertAuthorizedRoot(resolve(sourcePath), deps.config.allowedRoots);
        const id = uid();
        const timestamp = now();
        deps.store.run(
          `INSERT INTO projects (id, name, description, source_path, default_branch, scope_include, scope_exclude, authorized_by, authorization_ref, max_concurrent_agents, status, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
          id,
          name,
          optionalString(body, "description", 4_000) ?? "",
          realPath,
          optionalString(body, "default_branch", 200),
          toJson(include),
          toJson(exclude),
          authorizedBy,
          authorizationRef,
          maximumAgents ?? null,
          current.id,
          timestamp,
          timestamp,
        );
        deps.auth.logAction(current.email, "project.created", id, { name, source_path: realPath }, ip);
        return json({ project: projectJson(deps.store.get("SELECT * FROM projects WHERE id = ?", id)) }, 201);
      }

      const projectMatch = path.match(/^\/api\/projects\/([^/]+)$/);
      if (projectMatch) {
        const projectId = projectMatch[1]!;
        const notFoundProject = () => {
          throw notFound("Project not found");
        };
        if (method === "GET") {
          requireUser();
          const project = deps.store.get("SELECT * FROM projects WHERE id = ?", projectId);
          if (!project) throw notFound("Project not found");
          const repositories = deps.store.all(
            "SELECT id, project_id, path, commit_sha, branch, file_count, total_bytes, imported_at FROM repositories WHERE project_id = ? ORDER BY imported_at DESC",
            projectId,
          );
          const audits = deps.store.all(
            "SELECT id, status, current_phase, created_at, started_at, finished_at FROM audits WHERE project_id = ? ORDER BY created_at DESC",
            projectId,
          );
          return json({ project: projectJson(project), repositories, audits });
        }
        if (method === "PUT") {
          const current = requireRole("auditor");
          const project = deps.store.get<{ id: string; status: string }>(
            "SELECT id, status FROM projects WHERE id = ?",
            projectId,
          );
          if (!project) throw notFound("Project not found");
          const body = await readJson(request);
          const name = body.name === undefined ? undefined : requireString(body, "name", 200);
          const description = body.description === undefined
            ? undefined
            : optionalString(body, "description", 4_000) ?? "";
          const scopeInclude = body.scope_include === undefined
            ? undefined
            : requireStringArray(body, "scope_include");
          const scopeExclude = body.scope_exclude === undefined
            ? undefined
            : requireStringArray(body, "scope_exclude");
          if (scopeInclude) validateScopeGlobs(scopeInclude);
          if (scopeExclude) validateScopeGlobs(scopeExclude);
          const status = body.status === undefined ? undefined : requireString(body, "status", 20);
          if (status && !["active", "archived"].includes(status)) throw badRequest("status must be active or archived");
          if (body.name !== undefined) {
            deps.store.run("UPDATE projects SET name = ? WHERE id = ?", name, project.id);
          }
          if (body.description !== undefined) {
            deps.store.run(
              "UPDATE projects SET description = ? WHERE id = ?",
              description,
              project.id,
            );
          }
          if (body.scope_include !== undefined) {
            deps.store.run(
              "UPDATE projects SET scope_include = ? WHERE id = ?",
              toJson(scopeInclude),
              project.id,
            );
          }
          if (body.scope_exclude !== undefined) {
            deps.store.run(
              "UPDATE projects SET scope_exclude = ? WHERE id = ?",
              toJson(scopeExclude),
              project.id,
            );
          }
          if (body.status !== undefined) {
            deps.store.run("UPDATE projects SET status = ? WHERE id = ?", status, project.id);
          }
          deps.store.run("UPDATE projects SET updated_at = ? WHERE id = ?", now(), project.id);
          deps.auth.logAction(current.email, "project.updated", project.id, body, ip);
          return json({ project: projectJson(deps.store.get("SELECT * FROM projects WHERE id = ?", project.id)) });
        }
        if (method === "DELETE") {
          const current = requireRole("admin");
          const audits = deps.store.get<{ count: number }>(
            "SELECT COUNT(*) AS count FROM audits WHERE project_id = ?",
            projectId,
          )?.count ?? 0;
          if (audits > 0) throw conflict("Projects with audits cannot be deleted; archive the project instead");
          const result = deps.store.changes("DELETE FROM projects WHERE id = ?", projectId);
          if (result === 0) notFoundProject();
          deps.auth.logAction(current.email, "project.deleted", projectId, {}, ip);
          return json({ ok: true });
        }
      }

      const importMatch = path.match(/^\/api\/projects\/([^/]+)\/import$/);
      if (importMatch && method === "POST") {
        const current = requireRole("auditor");
        const project = deps.store.get<{
          id: string;
          name: string;
          source_path: string;
          scope_include: string;
          scope_exclude: string;
        }>("SELECT * FROM projects WHERE id = ?", importMatch[1]);
        if (!project) throw notFound("Project not found");
        const body = request.body === null ? {} : await readJson(request);
        const ref = optionalString(body, "ref", 200);
        const imported = await importRepository(deps, project, ref, current.email);
        deps.auth.logAction(current.email, "repository.imported", imported.id, {
          project_id: project.id,
          commit: imported.commit_sha,
          files: imported.file_count,
        }, ip);
        return json({ repository: repositorySummary(imported) }, 201);
      }

      const projectTargetsMatch = path.match(/^\/api\/projects\/([^/]+)\/targets$/);
      if (projectTargetsMatch) {
        const projectId = projectTargetsMatch[1]!;
        if (!deps.store.get("SELECT id FROM projects WHERE id = ?", projectId)) throw notFound("Project not found");
        if (method === "GET") {
          requireUser();
          requireScope("target:read");
          requireProjectScope(projectId);
          return json({ targets: targets.listTargets(projectId) });
        }
        if (method === "POST") {
          const current = requireRole("auditor");
          requireScope("target:manage");
          requireProjectScope(projectId);
          const body = await readJson(request);
          const repositoryId = optionalString(body, "repository_id", 100);
          if (repositoryId && !deps.store.get("SELECT id FROM repositories WHERE id = ? AND project_id = ?", repositoryId, projectId)) {
            throw badRequest("repository_id must belong to this project");
          }
          const created = targets.createTarget({
            projectId,
            label: requireString(body, "label", 200),
            baseUrl: requireString(body, "base_url", 2_000),
            environment: requireString(body, "environment", 100),
            repositoryId,
            allowedHosts: requireStringArray(body, "allowed_hosts"),
            allowedCidrs: body.allowed_cidrs === undefined ? [] : requireStringArray(body, "allowed_cidrs"),
            allowedMethods: body.allowed_methods === undefined ? undefined : requireStringArray(body, "allowed_methods"),
            maxRps: typeof body.max_rps === "number" ? body.max_rps : undefined,
            tlsRequired: body.tls_required === undefined ? undefined : body.tls_required === true,
            createdBy: current.id,
          });
          deps.auth.logAction(current.email, "target.created", created.id, { project_id: projectId }, ip);
          return json({ target: created }, 201);
        }
      }

      const targetAuthorizationsMatch = path.match(/^\/api\/targets\/([^/]+)\/authorizations$/);
      if (targetAuthorizationsMatch) {
        const targetId = targetAuthorizationsMatch[1]!;
        if (!targets.getTarget(targetId)) throw notFound("Target not found");
        const targetProject = deps.store.get<{ project_id: string }>(
          "SELECT project_id FROM project_targets WHERE id = ?",
          targetId,
        );
        if (targetProject) requireProjectScope(targetProject.project_id);
        if (method === "GET") {
          requireUser();
          requireScope("target:read");
          return json({ authorizations: targets.listAuthorizations(targetId) });
        }
        if (method === "POST") {
          const current = requireRole("auditor");
          requireScope("target:manage");
          const body = await readJson(request);
          const actions = body.authorized_actions;
          if (!actions || typeof actions !== "object" || Array.isArray(actions)) {
            throw badRequest("authorized_actions must be an object");
          }
          const restrictions = body.restrictions ?? {};
          if (!restrictions || typeof restrictions !== "object" || Array.isArray(restrictions)) {
            throw badRequest("restrictions must be an object");
          }
          const created = targets.createAuthorization({
            targetId,
            authorizedBy: requireString(body, "authorized_by", 300),
            reference: requireString(body, "authorization_ref", 500),
            validFrom: requireString(body, "valid_from", 100),
            validUntil: requireString(body, "valid_until", 100),
            authorizedActions: actions as AuthorizedActions,
            restrictions: restrictions as Restrictions,
            createdBy: current.id,
          });
          deps.auth.logAction(current.email, "target.authorization_created", created.id, { target_id: targetId }, ip);
          return json({ authorization: created }, 201);
        }
      }

      const targetIdentitiesMatch = path.match(/^\/api\/targets\/([^/]+)\/identities$/);
      if (targetIdentitiesMatch) {
        const targetId = targetIdentitiesMatch[1]!;
        if (!targets.getTarget(targetId)) throw notFound("Target not found");
        const identityProject = deps.store.get<{ project_id: string }>(
          "SELECT project_id FROM project_targets WHERE id = ?",
          targetId,
        );
        if (identityProject) requireProjectScope(identityProject.project_id);
        if (method === "GET") {
          requireUser();
          requireScope("target:read");
          return json({ identities: targets.listIdentities(targetId) });
        }
        if (method === "POST") {
          const current = requireRole("auditor");
          requireScope("target:manage");
          const body = await readJson(request);
          const authKind = requireString(body, "auth_kind", 20);
          if (!["none", "header", "cookie", "basic"].includes(authKind)) {
            throw badRequest("auth_kind must be none, header, cookie, or basic");
          }
          const created = targets.createIdentity({
            targetId,
            label: requireString(body, "label", 200),
            role: requireString(body, "role", 100),
            authKind: authKind as "none" | "header" | "cookie" | "basic",
            secretRef: optionalString(body, "secret_ref", 200),
          });
          deps.auth.logAction(current.email, "target.identity_created", created.id, { target_id: targetId, role: created.role }, ip);
          return json({ identity: created }, 201);
        }
      }

      if (path === "/api/repositories" && method === "GET") {
        requireUser();
        const repositories = deps.store.all(
          `SELECT r.id, r.project_id, r.path, r.commit_sha, r.branch, r.file_count, r.total_bytes, r.imported_at,
                  p.name AS project_name
           FROM repositories r JOIN projects p ON p.id = r.project_id
           ORDER BY r.imported_at DESC LIMIT 200`,
        );
        return json({ repositories });
      }

      const repositoryMatch = path.match(/^\/api\/repositories\/([^/]+)$/);
      if (repositoryMatch && method === "GET") {        requireUser();
        const repository = deps.store.get<Record<string, unknown>>(
          "SELECT * FROM repositories WHERE id = ?",
          repositoryMatch[1],
        );
        if (!repository) throw notFound("Repository not found");
        const project = deps.store.get<Record<string, unknown>>(
          "SELECT * FROM projects WHERE id = ?",
          repository.project_id,
        )!;
        const inventory = parseJson<Record<string, unknown>>(String(repository.inventory), {});
        const mapTask = deps.store.get<{ result: string }>(
          `SELECT result FROM tasks WHERE audit_id IN (SELECT id FROM audits WHERE repository_id = ?)
           AND kind = 'phase1.map' AND status = 'completed' ORDER BY finished_at DESC LIMIT 1`,
          String(repository.id),
        );
        const map = mapTask ? parseJson<{ data?: unknown }>(mapTask.result, {}).data ?? null : null;
        return json({
          repository: {
            ...repositorySummary(repository as never),
            inventory_summary: inventorySummaryFromStored(inventory),
            inventory: {
              files: inventory.files ?? [],
              skipped: inventory.skipped ?? [],
              languages: inventory.languages ?? {},
              frameworks: inventory.frameworks ?? [],
              endpoints: inventory.endpoints ?? [],
              auth_boundaries: inventory.auth_boundaries ?? [],
              dependency_graph: inventory.dependency_graph ?? [],
              entrypoints: inventory.entrypoints ?? [],
              truncated: inventory.truncated ?? false,
            },
          },
          project: projectJson(project),
          map,
        });
      }

      const treeMatch = path.match(/^\/api\/repositories\/([^/]+)\/tree$/);
      if (treeMatch && method === "GET") {
        requireUser();
        const repository = deps.store.get<{ inventory: string; project_id: string }>(
          "SELECT inventory, project_id FROM repositories WHERE id = ?",
          treeMatch[1],
        );
        if (!repository) throw notFound("Repository not found");
        const inventory = parseJson<{ files?: Array<{ path: string; size: number; lines: number; language: string }> }>(
          repository.inventory,
          {},
        );
        const prefix = normalizePath(url.searchParams.get("path") ?? "").replace(/\/+$/, "");
        const entries = new Map<string, { name: string; path: string; type: "file" | "directory"; size?: number; lines?: number; language?: string }>();
        for (const file of inventory.files ?? []) {
          if (prefix && !file.path.startsWith(`${prefix}/`)) continue;
          const relative = prefix ? file.path.slice(prefix.length + 1) : file.path;
          const [first, ...rest] = relative.split("/");
          if (!first) continue;
          const childPath = prefix ? `${prefix}/${first}` : first;
          if (rest.length > 0) {
            entries.set(childPath, { name: first, path: childPath, type: "directory" });
          } else {
            entries.set(childPath, {
              name: first,
              path: childPath,
              type: "file",
              size: file.size,
              lines: file.lines,
              language: file.language,
            });
          }
        }
        return json({
          path: prefix,
          entries: [...entries.values()].sort((a, b) => {
            if (a.type !== b.type) return a.type === "directory" ? -1 : 1;
            return a.name.localeCompare(b.name);
          }),
        });
      }

      const fileMatch = path.match(/^\/api\/repositories\/([^/]+)\/file$/);
      if (fileMatch && method === "GET") {
        requireUser();
        const repository = deps.store.get<{ path: string; project_id: string }>(
          "SELECT path, project_id FROM repositories WHERE id = ?",
          fileMatch[1],
        );
        if (!repository) throw notFound("Repository not found");
        const project = deps.store.get<{ scope_include: string; scope_exclude: string }>(
          "SELECT scope_include, scope_exclude FROM projects WHERE id = ?",
          repository.project_id,
        )!;
        const scope = {
          include: parseJson<string[]>(project.scope_include, ["**/*"]),
          exclude: parseJson<string[]>(project.scope_exclude, []),
        };
        const relative = url.searchParams.get("path");
        if (!relative) throw badRequest("path is required");
        const root = await assertAuthorizedRoot(repository.path, deps.config.allowedRoots);
        const file = await readScopedFile(root, relative, scope);
        return json({ ...file, lines: file.content.split("\n").length });
      }

      if (path === "/api/audits" && method === "GET") {
        requireUser();
        const projectId = url.searchParams.get("project_id");
        const rows = deps.store.all(
          `SELECT a.*, p.name AS project_name, r.commit_sha,
             (SELECT COUNT(*) FROM findings f WHERE f.audit_id = a.id) AS finding_count,
             (SELECT COUNT(*) FROM tasks t WHERE t.audit_id = a.id AND t.status IN ('running','queued')) AS active_tasks
           FROM audits a JOIN projects p ON p.id = a.project_id LEFT JOIN repositories r ON r.id = a.repository_id
           ${projectId ? "WHERE a.project_id = ?" : ""} ORDER BY a.created_at DESC LIMIT 100`,
          ...(projectId ? [projectId] : []),
        );
        return json({ audits: rows });
      }

      if (path === "/api/audits" && method === "POST") {
        const current = requireRole("auditor");
        const body = await readJson(request);
        const projectId = requireString(body, "project_id", 100);
        const repositoryId = optionalString(body, "repository_id", 100);
        const mode = optionalString(body, "mode", 20);
        if (mode && !["static", "dynamic", "hybrid"].includes(mode)) {
          throw badRequest("mode must be static, dynamic, or hybrid");
        }
        const targetId = optionalString(body, "target_id", 100);
        requireScope(mode === "dynamic" || mode === "hybrid" ? "audit:launch_dynamic" : "audit:launch_static");
        requireProjectScope(projectId);
        if (targetId) {
          const target = deps.store.get<{ project_id: string }>(
            "SELECT project_id FROM project_targets WHERE id = ?",
            targetId,
          );
          if (!target || target.project_id !== projectId) throw badRequest("target_id must belong to this project");
        }
        const overrides = (body.overrides ?? {}) as Record<string, unknown>;
        if (overrides && typeof overrides !== "object") throw badRequest("overrides must be an object");
        const id = deps.engine.createAudit({
          projectId,
          repositoryId: repositoryId ?? undefined,
          userId: current.id,
          overrides,
          mode: (mode as "static" | "dynamic" | "hybrid" | null) ?? undefined,
          targetId: targetId ?? undefined,
        });
        deps.auth.logAction(current.email, "audit.created", id, { projectId, repositoryId, mode, targetId, overrides }, ip);
        return json({ audit: deps.store.get("SELECT * FROM audits WHERE id = ?", id) }, 201);
      }

      const auditMatch = path.match(/^\/api\/audits\/([^/]+)$/);
      if (auditMatch) {
        const auditId = auditMatch[1]!;
        const audit = deps.store.get<Record<string, unknown>>("SELECT * FROM audits WHERE id = ?", auditId);
        if (!audit) throw notFound("Audit not found");
        if (method === "GET") {
          requireUser();
          requireScope("audit:read");
          requireAuditScope(auditId);
          const auditProject = deps.store.get<{ project_id: string }>(
            "SELECT project_id FROM audits WHERE id = ?",
            auditId,
          );
          if (auditProject) requireProjectScope(auditProject.project_id);
          return json(await auditDetail(deps, auditId));
        }
        if (method === "POST") {
          const current = requireRole("auditor");
          deps.auth.logAction(current.email, "audit.action_denied", auditId, { method }, ip);
          throw badRequest("Use /start or /cancel");
        }
      }

      const auditActionMatch = path.match(/^\/api\/audits\/([^/]+)\/(start|cancel|tasks|findings|events|stream|evidence|reports|sessions|exploration)$/);
      if (auditActionMatch) {
        const auditId = auditActionMatch[1]!;
        const action = auditActionMatch[2]!;
        if (action === "stream" && method === "GET") {
          requireUser();
          return streamEvents(deps, request, auditId, eventCursor(url));
        }
        if (action === "start" && method === "POST") {
          const current = requireRole("auditor");
          const audit = deps.store.get<{ mode: string; project_id: string }>(
            "SELECT mode, project_id FROM audits WHERE id = ?",
            auditId,
          );
          if (!audit) throw notFound("Audit not found");
          requireScope(audit.mode === "static" ? "audit:launch_static" : "audit:launch_dynamic");
          requireAuditScope(auditId);
          requireProjectScope(audit.project_id);
          await deps.engine.startAudit(auditId, current.id);
          deps.auth.logAction(current.email, "audit.started", auditId, {}, ip);
          return json({ ok: true, audit: deps.store.get("SELECT * FROM audits WHERE id = ?", auditId) });
        }
        if (action === "cancel" && method === "POST") {
          const current = requireRole("auditor");
          await deps.engine.cancelAudit(auditId, current.id);
          deps.auth.logAction(current.email, "audit.cancelled", auditId, {}, ip);
          return json({ ok: true, audit: deps.store.get("SELECT * FROM audits WHERE id = ?", auditId) });
        }
        if (action === "sessions" && method === "GET") {
          requireUser();
          requireScope("audit:read");
          requireAuditScope(auditId);
          const sessions = deps.store.all(
            "SELECT id, task_id, role, harness, model, status, sandbox_mode, harness_session_ref, started_at, ended_at, usage, error FROM agent_sessions WHERE audit_id = ? ORDER BY started_at DESC",
            auditId,
          );
          return json({ sessions });
        }
        if (action === "tasks" && method === "GET") {
          requireUser();
          requireScope("audit:read");
          requireAuditScope(auditId);
          const tasks = deps.store.all(
            `SELECT t.id, t.phase, t.kind, t.task_key, t.title, t.status, t.priority, t.error, t.failure_kind,
                    t.agent_role, t.harness, t.model, t.attempts, t.max_attempts, t.requires_approval,
                    t.approval_id, t.agent_session_id, t.deadline_at, t.created_at, t.started_at, t.finished_at,
                    (SELECT COUNT(*) FROM task_dependencies d WHERE d.task_id = t.id) AS dependency_count
             FROM tasks t WHERE t.audit_id = ? ORDER BY t.phase, t.created_at`,
            auditId,
          );
          return json({ tasks });
        }
        if (action === "tasks" && method === "POST") {
          const current = requireRole("auditor");
          requireScope("task:create");
          const audit = deps.store.get<{ id: string; project_id: string; mode: string; status: string }>(
            "SELECT id, project_id, mode, status FROM audits WHERE id = ?",
            auditId,
          );
          if (!audit) throw notFound("Audit not found");
          requireAuditScope(auditId);
          requireProjectScope(audit.project_id);
          if (audit.status !== "running") throw conflict("Tasks can be created only while the audit is running");
          const body = await readJson(request);
          const kind = requireString(body, "kind", 100);
          if (kind === "explore" || kind.startsWith("explore.")) {
            requireScope("audit:launch_dynamic");
            if (!["dynamic", "hybrid"].includes(audit.mode)) throw conflict("Audit is not dynamic");
          }
          const phase = typeof body.phase === "number" ? body.phase : 2;
          if (!Number.isInteger(phase) || phase < 1 || phase > 6) throw badRequest("phase must be 1..6");
          const agentRole = optionalString(body, "agent_role", 100)
            ?? (kind.startsWith("explore") ? "security_researcher" : null);
          if (agentRole && !deps.store.get("SELECT role FROM agent_defs WHERE role = ?", agentRole)) {
            throw badRequest("Unknown agent role");
          }
          if (!agentRole) throw badRequest("agent_role is required for this task kind");
          const payload = body.payload && typeof body.payload === "object" && !Array.isArray(body.payload)
            ? (body.payload as Record<string, unknown>)
            : {};
          const taskId = deps.engine.createTask({
            auditId,
            phase,
            kind,
            taskKey: `adapter:${kind}:${uid()}`,
            title: optionalString(body, "title", 300) ?? `${kind} task`,
            payload,
            agentRole,
            priority: 50,
          });
          deps.auth.logAction(current.email, "task.created", taskId, { audit_id: auditId, kind }, ip);
          return json({ task: deps.store.get("SELECT * FROM tasks WHERE id = ?", taskId) }, 201);
        }
        if (action === "findings" && method === "GET") {
          requireUser();
          requireScope("finding:read");
          requireAuditScope(auditId);
          const findings = deps.store.all(
            `SELECT f.*, (SELECT COUNT(*) FROM verifications v WHERE v.finding_id = f.id) AS verification_count
             FROM findings f WHERE f.audit_id = ? ORDER BY f.code`,
            auditId,
          );
          return json({ findings: findings.map(findingJson) });
        }
        if (action === "events" && method === "GET") {
          requireUser();
          const after = eventCursor(url);
          return json({ events: deps.events.list(auditId, after, 500) });
        }
        if (action === "evidence" && method === "GET") {
          requireUser();
          requireScope("audit:read");
          requireAuditScope(auditId);
          const rows = deps.store.all<EvidenceRow>(
            "SELECT * FROM evidence WHERE audit_id = ? ORDER BY rowid",
            auditId,
          );
          return json({
            evidence: rows.map(evidenceJson),
            chain: await deps.evidence.verifyChain(auditId),
          });
        }
        if (action === "exploration" && method === "GET") {
          requireUser();
          requireScope("audit:read");
          requireAuditScope(auditId);
          const audit = deps.store.get<{ project_id: string }>(
            "SELECT project_id FROM audits WHERE id = ?",
            auditId,
          );
          if (!audit) throw notFound("Audit not found");
          const graph = new GraphStore(deps.store);
          return json({
            assets: graph.listAssets(audit.project_id),
            nodes: graph.listNodes(auditId),
            edges: graph.listEdges(auditId),
            anchors: graph.listAnchors(auditId),
            coverage: graph.coverage(auditId),
          });
        }
        if (action === "reports") {
          if (method === "GET") {
            requireUser();
            return json({ reports: deps.store.all("SELECT * FROM reports WHERE audit_id = ? ORDER BY generated_at DESC", auditId) });
          }
          if (method === "POST") {
            const current = requireRole("auditor");
            const audit = deps.store.get<{ status: string }>("SELECT status FROM audits WHERE id = ?", auditId);
            if (!audit) throw notFound("Audit not found");
            const assessmentPhases = deps.store.all<{ status: string }>(
              "SELECT status FROM audit_phases WHERE audit_id = ? AND phase BETWEEN 1 AND 5",
              auditId,
            );
            const assessmentComplete =
              assessmentPhases.length === 5 &&
              assessmentPhases.every((phase) => ["completed", "skipped"].includes(phase.status));
            if (!assessmentComplete && !["completed", "completed_with_errors"].includes(audit.status)) {
              throw conflict("Reports can be generated only after mapping, discovery, confirmation, findings, and reverification are complete");
            }
            const body = request.body === null ? {} : await readJson(request);
            const formats = body.formats === undefined ? REPORT_FORMATS : requireStringArray(body, "formats");
            for (const format of formats) {
              if (!REPORT_FORMATS.includes(format as ReportFormat)) throw badRequest(`Unsupported report format: ${format}`);
            }
            const generated = await deps.reports.generate(auditId, formats as ReportFormat[], current.email);
            deps.auth.logAction(current.email, "reports.generated", auditId, { formats }, ip);
            return json({ reports: generated }, 201);
          }
        }
      }

      if (path === "/api/events/stream" && method === "GET") {
        requireUser();
        return streamGlobalEvents(deps, request);
      }

      if (path === "/api/tasks" && method === "GET") {
        requireUser();
        const auditId = url.searchParams.get("audit_id");
        const status = url.searchParams.get("status");
        const clauses: string[] = [];
        const params: string[] = [];
        if (auditId) {
          clauses.push("t.audit_id = ?");
          params.push(auditId);
        }
        if (status) {
          const allowed = ["queued", "waiting_approval", "running", "completed", "failed", "cancelled", "blocked"];
          if (!allowed.includes(status)) throw badRequest("Invalid task status filter");
          clauses.push("t.status = ?");
          params.push(status);
        }
        const tasks = deps.store.all(
          `SELECT t.id, t.audit_id, t.phase, t.kind, t.title, t.status, t.agent_role, t.harness, t.model,
                  t.attempts, t.max_attempts, t.error, t.failure_kind, t.created_at, t.started_at, t.finished_at,
                  p.name AS project_name
           FROM tasks t JOIN audits a ON a.id = t.audit_id JOIN projects p ON p.id = a.project_id
           ${clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""}
           ORDER BY t.created_at DESC LIMIT 300`,
          ...params,
        );
        return json({ tasks });
      }

      const taskMatch = path.match(/^\/api\/tasks\/([^/]+)$/);
      if (taskMatch && method === "GET") {
        requireUser();
        const task = deps.store.get<Record<string, unknown>>("SELECT * FROM tasks WHERE id = ?", taskMatch[1]);
        if (!task) throw notFound("Task not found");
        const dependencies = deps.store.all<{ depends_on_task_id: string; status: string; title: string }>(
          `SELECT d.depends_on_task_id, t.status, t.title FROM task_dependencies d JOIN tasks t ON t.id = d.depends_on_task_id WHERE d.task_id = ?`,
          taskMatch[1],
        );
        const events = deps.store.all(
          "SELECT * FROM execution_events WHERE task_id = ? ORDER BY seq LIMIT 500",
          taskMatch[1],
        );
        const session = task.agent_session_id
          ? deps.store.get("SELECT * FROM agent_sessions WHERE id = ?", String(task.agent_session_id))
          : null;
        const evidence = deps.store.all<EvidenceRow>("SELECT * FROM evidence WHERE task_id = ? ORDER BY rowid", taskMatch[1]);
        return json({
          task: {
            ...task,
            payload: parseJson(String(task.payload ?? "{}"), {}),
            result: parseJson(String(task.result ?? "null"), null),
          },
          dependencies,
          events: events.map((event) => ({
            ...(event as Record<string, unknown>),
            payload: parseJson(String((event as Record<string, unknown>).payload ?? "{}"), {}),
          })),
          session,
          evidence: evidence.map(evidenceJson),
        });
      }

      const taskAction = path.match(/^\/api\/tasks\/([^/]+)\/(retry|cancel)$/);
      if (taskAction && method === "POST") {
        const current = requireRole("auditor");
        const task = deps.store.get<{ id: string; audit_id: string; status: string; attempts: number; max_attempts: number }>(
          "SELECT id, audit_id, status, attempts, max_attempts FROM tasks WHERE id = ?",
          taskAction[1],
        );
        if (!task) throw notFound("Task not found");
        if (tokenAuth) {
          requireScope("task:control");
          requireAuditScope(task.audit_id);
          const project = deps.store.get<{ project_id: string }>(
            "SELECT project_id FROM audits WHERE id = ?",
            task.audit_id,
          );
          if (project) requireProjectScope(project.project_id);
        }
        if (taskAction[2] === "retry") {
          await deps.engine.retryTask(task.id, current.email);
          deps.auth.logAction(current.email, "task.retried", task.id, {}, ip);
          return json({ ok: true });
        }
        if (taskAction[2] === "cancel") {
          if (!["queued", "waiting_approval", "running"].includes(task.status)) {
            throw conflict("Task is already terminal");
          }
          deps.engine.cancelTask(task.id, current.email);
          deps.auth.logAction(current.email, "task.cancelled", task.id, {}, ip);
          return json({ ok: true });
        }
      }

      const auditCandidatesMatch = path.match(/^\/api\/audits\/([^/]+)\/candidates$/);
      if (auditCandidatesMatch) {
        const auditId = auditCandidatesMatch[1]!;
        const audit = deps.store.get<{ id: string; project_id: string; mode: string; status: string }>(
          "SELECT id, project_id, mode, status FROM audits WHERE id = ?",
          auditId,
        );
        if (!audit) throw notFound("Audit not found");
        if (audit.mode === "static") throw conflict("Static audits do not accept dynamic candidates");
        if (audit.status !== "running") throw conflict("Candidates can be proposed only while the audit is running");
        requireScope("audit:propose_candidate");
        requireAuditScope(auditId);
        requireProjectScope(audit.project_id);
        const current = requireRole("auditor");
        if (method !== "POST") throw badRequest("Use POST to propose a dynamic candidate");
        const body = await readJson(request);
        const manifest = body.manifest;
        if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
          throw badRequest("manifest must be an object");
        }
        const service = new DynamicProofService(deps.store, deps.evidence, (id, poc) =>
          runPocChecks(deps.config, deps.store, id, poc),
        );
        const proposed = await service.propose({
          auditId,
          assetId: requireString(body, "asset_id", 100),
          title: requireString(body, "title", 300),
          category: requireString(body, "category", 100),
          severity: requireString(body, "severity", 20) as never,
          manifest: manifest as never,
          script: requireString(body, "script", 100_000),
          impact: optionalString(body, "impact", 2_000) ?? undefined,
          remediation: optionalString(body, "remediation", 2_000) ?? undefined,
          intentNodeId: optionalString(body, "intent_node_id", 100),
          source: (body.source ?? null) as never,
          proposedBy: optionalString(body, "proposed_by", 200) ?? current.id,
        });
        deps.auth.logAction(current.email, "candidate.proposed", proposed.candidateId, { audit_id: auditId }, ip);
        return json(proposed, 201);
      }

      const candidateConfirmMatch = path.match(/^\/api\/candidates\/([^/]+)\/confirm$/);
      if (candidateConfirmMatch && method === "POST") {
        const current = requireRole("auditor");
        requireScope("audit:confirm_candidate");
        const candidate = deps.store.get<{ audit_id: string }>(
          "SELECT audit_id FROM candidates WHERE id = ?",
          candidateConfirmMatch[1]!,
        );
        if (!candidate) throw notFound("Candidate not found");
        const audit = deps.store.get<{ project_id: string }>(
          "SELECT project_id FROM audits WHERE id = ?",
          candidate.audit_id,
        );
        requireAuditScope(candidate.audit_id);
        if (audit) requireProjectScope(audit.project_id);
        const body = request.body === null ? {} : await readJson(request);
        const service = new DynamicProofService(deps.store, deps.evidence, (id, poc) =>
          runPocChecks(deps.config, deps.store, id, poc),
        );
        const result = await service.confirm(
          candidateConfirmMatch[1]!,
          optionalString(body, "confirmed_by", 200) ?? current.id,
        );
        deps.auth.logAction(current.email, `candidate.${result.verdict.toLowerCase()}`, result.candidateId, {
          audit_id: candidate.audit_id,
          finding_id: result.findingId,
        }, ip);
        return json(result);
      }

      if (path === "/api/findings" && method === "GET") {
        requireUser();
        requireScope("finding:read");
        const auditId = url.searchParams.get("audit_id");
        const status = url.searchParams.get("status");
        const clauses: string[] = [];
        const params: string[] = [];
        if (auditId) {
          clauses.push("audit_id = ?");
          params.push(auditId);
        }
        if (status) {
          clauses.push("status = ?");
          params.push(status);
        }
        const findings = deps.store.all(
          `SELECT * FROM findings ${clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""} ORDER BY created_at DESC LIMIT 500`,
          ...params,
        );
        return json({ findings: findings.map(findingJson) });
      }

      const findingMatch = path.match(/^\/api\/findings\/([^/]+)$/);
      if (findingMatch && method === "GET") {
        requireUser();
        requireScope("finding:read");
        const finding = deps.store.get<Record<string, unknown>>("SELECT * FROM findings WHERE id = ?", findingMatch[1]);
        if (!finding) throw notFound("Finding not found");
        requireAuditScope(String(finding.audit_id ?? ""));
        const findingProject = deps.store.get<{ project_id: string }>(
          "SELECT project_id FROM audits WHERE id = ?",
          String(finding.audit_id ?? ""),
        );
        if (findingProject) requireProjectScope(findingProject.project_id);
        const candidate = finding.candidate_id
          ? deps.store.get("SELECT * FROM candidates WHERE id = ?", String(finding.candidate_id))
          : null;
        const verifications = deps.store.all(
          "SELECT * FROM verifications WHERE finding_id = ? OR (candidate_id IS NOT NULL AND candidate_id = ?) ORDER BY created_at",
          finding.id,
          finding.candidate_id ?? "",
        );
        const evidence = deps.store.all<EvidenceRow>("SELECT * FROM evidence WHERE finding_id = ? ORDER BY rowid", finding.id);
        const retests = deps.store.all<Record<string, unknown>>(
          "SELECT * FROM retests WHERE finding_id = ? ORDER BY created_at DESC",
          finding.id,
        );
        const sessions = deps.store.all(
          `SELECT * FROM agent_sessions WHERE id IN (?, ?, ?)`,
          finding.discovery_session_id ?? "",
          finding.verification_session_id ?? "",
          finding.retest_session_id ?? "",
        );
        return json({
          finding: findingJson(finding),
          candidate: candidate
            ? { ...(candidate as Record<string, unknown>), payload: parseJson(String((candidate as Record<string, unknown>).payload ?? "{}"), {}) }
            : null,
          verifications: verifications.map((row) => {
            const record = row as Record<string, unknown>;
            return {
              ...record,
              payload: parseJson(String(record.payload ?? "{}"), {}),
              evidence_check: parseJson(String(record.evidence_check ?? "{}"), {}),
            };
          }),
          evidence: evidence.map(evidenceJson),
          retests: retests.map((row) => ({
            ...row,
            evidence_refs: parseJson(String(row.evidence_refs ?? "[]"), []),
          })),
          sessions,
        });
      }

      const retestMatch = path.match(/^\/api\/findings\/([^/]+)\/retest$/);
      if (retestMatch && method === "POST") {
        const current = requireRole("auditor");
        const taskId = await deps.engine.requestRetest(retestMatch[1]!, current.email);
        deps.auth.logAction(current.email, "finding.retest_requested", retestMatch[1]!, { task_id: taskId }, ip);
        return json({ ok: true, task_id: taskId }, 201);
      }

      if (path === "/api/harnesses" && method === "GET") {
        requireUser();
        const detections = await deps.manager.detectAll();
        const rows = deps.store.all<Record<string, unknown>>("SELECT * FROM harnesses ORDER BY kind");
        return json({
          harnesses: rows.map((row) => {
            const detection = detections.find((entry) => entry.kind === row.kind);
            return {
              ...row,
              detail: redactSecrets(String(row.detail ?? "")).text,
              capabilities: parseJson(String(row.capabilities ?? "{}"), {}),
              config: redactHarnessConfig(parseJson<HarnessConfig>(String(row.config ?? "{}"), {} as HarnessConfig)),
              models: detection?.models ?? [],
              auth: detection?.auth ?? { ready: false, detail: "" },
            };
          }),
        });
      }

      const harnessMatch = path.match(/^\/api\/harnesses\/(pi|claude-code)(?:\/(check|test|models|assign))?$/);
      if (harnessMatch) {
        const kind = harnessMatch[1] as HarnessKind;
        const action = harnessMatch[2];
        if (method === "POST" && action === "assign") {
          const current = requireRole("admin");
          const config = harnessConfig(deps.store, kind);
          const roles = ["codebase_mapper", "security_researcher", "independent_validator", "retest_auditor"];
          deps.store.transaction(() => {
            for (const role of roles) {
              deps.store.run(
                "UPDATE agent_defs SET harness = ?, model = NULL, allowed_tools = ?, inherit_tools = 1, allow_shell = 0, enabled = 1, updated_at = ? WHERE role = ?",
                kind, toJson(config.allowed_tools), now(), role,
              );
            }
            setSetting(deps.store, "audit.require_distinct_harness_for_retest", false, current.id);
          });
          deps.auth.logAction(current.email, "harness.assigned", kind, { roles }, ip);
          return json({ ok: true, harness: kind, roles });
        }
        if (method === "GET" && !action) {
          requireUser();
          const detection = await deps.manager.adapter(kind).detect();
          return json({ harness: redactObject(detection), config: redactHarnessConfig(harnessConfig(deps.store, kind)) });
        }
        if (method === "PUT" && !action) {
          const current = requireRole("admin");
          const body = await readJson(request);
          const config = validateHarnessConfig(body, deps.store);
          saveHarnessConfig(deps.store, kind, { ...harnessConfig(deps.store, kind), ...config } as HarnessConfig);
          deps.manager.invalidate(kind);
          deps.auth.logAction(current.email, "harness.configured", kind, redactHarnessConfig(config), ip);
          return json({ ok: true, config: redactHarnessConfig(harnessConfig(deps.store, kind)) });
        }
        if (method === "POST" && action === "check") {
          requireRole("auditor");
          const detection = await deps.manager.health(kind, true);
          return json({ harness: redactObject(detection) });
        }
        if (method === "POST" && action === "test") {
          const current = requireRole("admin");
          const result = await deps.manager.testConnection(kind);
          deps.auth.logAction(current.email, "harness.tested", kind, { status: result.result?.status }, ip);
          return json(redactObject({
            detection: result.detection,
            result: result.result
              ? {
                  status: result.result.status,
                  structured: result.result.structured ?? null,
                  usage: result.result.usage,
                  error: result.result.error ?? null,
                  sandbox: result.result.metadata.sandbox,
                  duration_ms: result.result.usage.duration_ms,
                }
              : null,
          }));
        }
        if (method === "GET" && action === "models") {
          requireUser();
          const detection = await deps.manager.adapter(kind).detect();
          return json({ models: detection.models });
        }
      }

      if (path === "/api/agents" && method === "GET") {
        requireUser();
        return json({ agents: listAgents(deps.store) });
      }

      const agentMatch = path.match(/^\/api\/agents\/([a-z_]+)$/);
      if (agentMatch && method === "PUT") {
        const current = requireRole("admin");
        const body = await readJson(request);
        const role = agentMatch[1]!;
        const existing = deps.store.get("SELECT * FROM agent_defs WHERE role = ?", role);
        if (!existing) throw notFound("Agent role not found");
        const harness = body.harness === undefined ? null : requireString(body, "harness", 30);
        if (harness && !["pi", "claude-code"].includes(harness)) throw badRequest("harness must be pi or claude-code");
        const model = body.model === undefined ? undefined : optionalString(body, "model", 300);
        const allowedTools =
          body.allowed_tools === undefined
            ? null
            : requireStringArray(body, "allowed_tools");
        if (body.inherit_tools !== undefined && typeof body.inherit_tools !== "boolean") throw badRequest("inherit_tools must be a boolean");
        const inheritTools = typeof body.inherit_tools === "boolean" ? Number(body.inherit_tools) : allowedTools !== null ? 0 : null;
        if (inheritTools !== 1 && allowedTools && allowedTools.some((tool) => /^(bash|Bash)(?:$|\()/.test(tool))) {
          if (!getSetting(deps.store, "security.allow_shell_tools", false)) {
            throw badRequest("Shell tools are disabled globally. Enable them in Settings and require approval first.");
          }
        }
        const enabled = typeof body.enabled === "boolean" ? (body.enabled ? 1 : 0) : null;
        const budget = body.budget_usd === undefined ? undefined : body.budget_usd === null ? null : Number(body.budget_usd);
        const duration = body.max_duration_ms === undefined ? undefined : Number(body.max_duration_ms);
        const retries = body.max_retries === undefined ? undefined : Number(body.max_retries);
        const systemInstructions = body.system_instructions === undefined ? null : requireString(body, "system_instructions", 100_000);
        if (budget !== undefined && budget !== null && (!Number.isFinite(budget) || budget < 0)) throw badRequest("budget_usd invalid");
        if (duration !== undefined && (!Number.isFinite(duration) || duration < 10_000 || duration > 3_600_000)) {
          throw badRequest("max_duration_ms must be between 10 seconds and 1 hour");
        }
        if (retries !== undefined && (!Number.isInteger(retries) || retries < 0 || retries > 5)) {
          throw badRequest("max_retries must be an integer between 0 and 5");
        }
        deps.store.run(
          `UPDATE agent_defs SET harness = COALESCE(?, harness), model = CASE WHEN ? THEN ? ELSE model END,
             allowed_tools = COALESCE(?, allowed_tools), inherit_tools = COALESCE(?, inherit_tools),
             allow_shell = CASE WHEN ? THEN 0 ELSE allow_shell END, enabled = COALESCE(?, enabled),
             system_instructions = COALESCE(?, system_instructions), max_retries = COALESCE(?, max_retries),
             budget_usd = CASE WHEN ? THEN ? ELSE budget_usd END,
             max_duration_ms = COALESCE(?, max_duration_ms), updated_at = ?
           WHERE role = ?`,
          typeof harness === "string" ? harness : null,
          body.model !== undefined ? 1 : 0,
          model ?? null,
          allowedTools ? toJson(allowedTools) : null,
          inheritTools,
          inheritTools !== null ? 1 : 0,
          enabled,
          systemInstructions,
          retries ?? null,
          body.budget_usd !== undefined ? 1 : 0,
          budget ?? null,
          duration ?? null,
          now(),
          role,
        );
        deps.auth.logAction(current.email, "agent.configured", role, body, ip);
        return json({ agent: agentDefinition(deps.store, role) });
      }

      if (path === "/api/settings" && method === "GET") {
        const current = requireUser();
        const isAdmin = roleAtLeast(current, "admin");
        const credentials = isAdmin
          ? deps.store.all<StoredCredential>(
              "SELECT id, provider, env_var, last4, created_at, updated_at FROM provider_credentials ORDER BY provider, env_var",
            )
          : [];
        return json({
          settings: listSettings(deps.store),
          credentials,
          sandbox: deps.config.sandboxMode,
          allowed_roots: deps.config.allowedRoots,
          data_dir: deps.config.dataDir,
          version: APP_VERSION,
        });
      }

      if (path === "/api/settings" && method === "PUT") {
        const current = requireRole("admin");
        const body = await readJson(request);
        const updates = body.settings;
        if (!updates || typeof updates !== "object" || Array.isArray(updates)) throw badRequest("settings object required");
        const entries = Object.entries(updates as Record<string, unknown>);
        for (const [key, value] of entries) {
          if (!(key in DEFAULT_SETTINGS)) throw badRequest(`Unknown setting: ${key}`);
          if (key === "security.allow_shell_tools" && value === true && !getSetting(deps.store, key, false) && body.confirm_shell !== true) {
            throw badRequest("Enabling shell tools requires confirm_shell: true and task-level approval");
          }
          if (key === "security.allow_writable_workspace" && value === true && !getSetting(deps.store, key, false) && body.confirm_writable_workspace !== true) {
            throw badRequest(
              "Enabling writable audit workspaces requires confirm_writable_workspace: true, a per-audit request, and per-task approval",
            );
          }
          const validationError = validateSettingValue(key, value);
          if (validationError) throw badRequest(validationError);
        }
        for (const [key, value] of entries) {
          setSetting(deps.store, key, value, current.id);
          if (key === "security.sandbox_mode" && (value === "auto" || value === "bwrap" || value === "none")) {
            deps.config.sandboxMode = value;
          }
        }
        deps.auth.logAction(current.email, "settings.updated", null, { keys: entries.map(([key]) => key) }, ip);
        return json({ settings: listSettings(deps.store) });
      }

      if (path === "/api/credentials" && method === "GET") {
        requireRole("admin");
        return json({
          credentials: deps.store.all(
            "SELECT id, provider, env_var, last4, created_at, updated_at FROM provider_credentials ORDER BY provider, env_var",
          ),
        });
      }

      if (path === "/api/credentials" && method === "PUT") {
        const current = requireRole("admin");
        const body = await readJson(request);
        const provider = requireString(body, "provider", 80).toLowerCase();
        const envVar = requireString(body, "env_var", 100).toUpperCase();
        const value = requireString(body, "value", 8_000);
        if (!/^[A-Z][A-Z0-9_]{1,99}$/.test(envVar)) throw badRequest("env_var must be an uppercase environment variable name");
        const encrypted = encryptSecret(deps.config, value);
        const id = uid();
        deps.store.run(
          `INSERT INTO provider_credentials (id, provider, env_var, ciphertext, iv, tag, last4, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(provider, env_var) DO UPDATE SET ciphertext = excluded.ciphertext, iv = excluded.iv, tag = excluded.tag,
             last4 = excluded.last4, updated_at = excluded.updated_at`,
          id,
          provider,
          envVar,
          encrypted.ciphertext,
          encrypted.iv,
          encrypted.tag,
          encrypted.last4,
          now(),
          now(),
        );
        deps.manager.invalidate();
        deps.auth.logAction(current.email, "credential.stored", `${provider}:${envVar}`, { last4: encrypted.last4 }, ip);
        return json({ ok: true });
      }

      const credentialMatch = path.match(/^\/api\/credentials\/([^/]+)$/);
      if (credentialMatch && method === "DELETE") {
        const credentialId = credentialMatch[1]!;
        const current = requireRole("admin");
        const deleted = deps.store.changes("DELETE FROM provider_credentials WHERE id = ?", credentialId);
        if (deleted === 0) throw notFound("Credential not found");
        deps.manager.invalidate();
        deps.auth.logAction(current.email, "credential.deleted", credentialId, {}, ip);
        return json({ ok: true });
      }

      if (path === "/api/users" && method === "GET") {
        requireRole("admin");
        return json({ users: deps.auth.listUsers() });
      }

      if (path === "/api/users" && method === "POST") {
        const current = requireRole("admin");
        const body = await readJson(request);
        const email = requireString(body, "email", 320);
        const name = optionalString(body, "name", 200) ?? email;
        const password = requireString(body, "password", 512, false);
        const role = requireString(body, "role", 20) as User["role"];
        try {
          const user = await deps.auth.createUser(email, name, password, role);
          deps.auth.logAction(current.email, "user.created", user.id, { email, role }, ip);
          return json({ user }, 201);
        } catch (error) {
          throw badRequest(error instanceof Error ? error.message : String(error));
        }
      }

      const userMatch = path.match(/^\/api\/users\/([^/]+)$/);
      if (userMatch && method === "PATCH") {
        const current = requireRole("admin");
        const body = await readJson(request);
        const target = deps.auth.listUsers().find((entry) => entry.id === userMatch[1]);
        if (!target) throw notFound("User not found");
        if (body.role !== undefined && !["admin", "auditor", "viewer"].includes(String(body.role))) {
          throw badRequest("role must be admin, auditor, or viewer");
        }
        if (body.disabled !== undefined && typeof body.disabled !== "boolean") {
          throw badRequest("disabled must be a boolean");
        }
        if (body.name !== undefined && (typeof body.name !== "string" || body.name.length > 200)) {
          throw badRequest("name must be a string of at most 200 characters");
        }
        const admins = deps.auth.listUsers().filter((entry) => entry.role === "admin" && entry.disabled === 0);
        const disablingSelf = target.id === current.id && body.disabled === true;
        const removingLastAdmin =
          target.role === "admin" &&
          admins.length <= 1 &&
          (body.role !== undefined && body.role !== "admin" || body.disabled === true);
        if (disablingSelf) throw badRequest("You cannot disable your own account");
        if (removingLastAdmin) throw badRequest("The last active administrator cannot be demoted or disabled");
        try {
          deps.auth.updateUser(target.id, {
            role: body.role as User["role"] | undefined,
            disabled: typeof body.disabled === "boolean" ? body.disabled : undefined,
            name: typeof body.name === "string" ? body.name : undefined,
          });
        } catch (error) {
          throw badRequest(error instanceof Error ? error.message : String(error));
        }
        deps.auth.logAction(current.email, "user.updated", target.id, body, ip);
        return json({ ok: true });
      }

      if (path === "/api/approvals" && method === "GET") {
        requireUser();
        const status = url.searchParams.get("status");
        const approvals = deps.store.all(
          `SELECT * FROM approvals ${status ? "WHERE status = ?" : ""} ORDER BY created_at DESC LIMIT 200`,
          ...(status ? [status] : []),
        );
        return json({ approvals });
      }

      const approvalMatch = path.match(/^\/api\/approvals\/([^/]+)\/decide$/);
      if (approvalMatch && method === "POST") {
        const current = requireRole("admin");
        const body = await readJson(request);
        if (typeof body.approved !== "boolean") throw badRequest("approved boolean required");
        const reason = optionalString(body, "reason", 2_000) ?? "";
        deps.engine.decideApproval(approvalMatch[1]!, body.approved, current.email, reason);
        deps.auth.logAction(current.email, "approval.decided", approvalMatch[1]!, { approved: body.approved, reason }, ip);
        return json({ ok: true });
      }

      if (path === "/api/reports" && method === "GET") {
        requireUser();
        const auditId = url.searchParams.get("audit_id");
        const reports = deps.store.all(
          `SELECT * FROM reports ${auditId ? "WHERE audit_id = ?" : ""} ORDER BY generated_at DESC LIMIT 200`,
          ...(auditId ? [auditId] : []),
        );
        return json({ reports });
      }

      const reportDownload = path.match(/^\/api\/reports\/([^/]+)\/download$/);
      if (reportDownload && method === "GET") {
        const current = requireUser();
        const report = deps.store.get<{
          id: string;
          audit_id: string;
          format: string;
          status: string;
          path: string | null;
          sha256: string | null;
          size: number | null;
        }>("SELECT * FROM reports WHERE id = ?", reportDownload[1]);
        if (!report) throw notFound("Report not found");
        if (report.status !== "generated" || !report.path) {
          throw notFound("Report file is not available");
        }
        const expectedSize = report.size;
        if (typeof expectedSize !== "number" || !Number.isSafeInteger(expectedSize) || expectedSize < 0) {
          throw conflict("Report file is missing or unreadable");
        }
        const bytes = await readRegularFile(report.path, expectedSize);
        if (!report.sha256 || sha256(bytes) !== report.sha256) {
          throw conflict("Report integrity check failed; the stored file does not match its recorded hash");
        }
        deps.auth.logAction(current.email, "report.downloaded", report.id, { audit_id: report.audit_id }, ip);
        const extension = report.format === "markdown" ? "md" : report.format;
        const mime =
          report.format === "html"
            ? "text/html"
            : report.format === "json"
              ? "application/json"
              : report.format === "pdf"
                ? "application/pdf"
                : "text/markdown";
        return new Response(bytes, {
          headers: {
            "content-type": mime,
            "content-disposition": `attachment; filename="argus-${report.audit_id}-${report.id}.${extension}"`,
            "cache-control": "no-store",
          },
        });
      }

      const evidenceMatch = path.match(/^\/api\/evidence\/([^/]+)$/);
      if (evidenceMatch && method === "GET") {
        requireRole("auditor");
        const result = await deps.evidence.content(evidenceMatch[1]!);
        if (!result) throw notFound("Evidence not found");
        return json({ evidence: evidenceJson(result.row), content: result.content });
      }

      if (path === "/api/audit-log" && method === "GET") {
        requireRole("admin");
        const entries = deps.store.all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500");
        return json({
          entries: entries.map((row) => {
            const record = row as Record<string, unknown>;
            return { ...record, detail: parseJson(String(record.detail ?? "null"), null) };
          }),
        });
      }

      return json({ error: { code: "not_found", message: `No route for ${method} ${path}` } }, 404);
    } catch (error) {
      return errorResponse(error);
    }
  };
}

async function auditDetail(deps: ApiDeps, auditId: string): Promise<Record<string, unknown>> {
  const audit = deps.store.get<Record<string, unknown>>("SELECT * FROM audits WHERE id = ?", auditId);
  if (!audit) throw notFound("Audit not found");
  const project = deps.store.get<Record<string, unknown>>(
    "SELECT id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref FROM projects WHERE id = ?",
    String(audit.project_id),
  );
  const repository = deps.store.get<Record<string, unknown>>(
    "SELECT id, commit_sha, branch, file_count, total_bytes, languages, frameworks, imported_at FROM repositories WHERE id = ?",
    String(audit.repository_id),
  );
  const phases = deps.store.all("SELECT * FROM audit_phases WHERE audit_id = ? ORDER BY phase", auditId);
  const coverage = deps.store.all<{ files: string }>("SELECT * FROM coverage WHERE audit_id = ? ORDER BY area_id", auditId);
  const taskCounts = deps.store.all<{ status: string; count: number }>(
    "SELECT status, COUNT(*) AS count FROM tasks WHERE audit_id = ? GROUP BY status",
    auditId,
  );
  const findingCounts = deps.store.all<{ status: string; severity: string; count: number }>(
    "SELECT status, severity, COUNT(*) AS count FROM findings WHERE audit_id = ? GROUP BY status, severity",
    auditId,
  );
  const sessions = deps.store.all(
    `SELECT id, role, harness, model, status, sandbox_mode, started_at, ended_at FROM agent_sessions WHERE audit_id = ? ORDER BY started_at DESC LIMIT 50`,
    auditId,
  );
  const reports = deps.store.all("SELECT * FROM reports WHERE audit_id = ? ORDER BY generated_at DESC", auditId);
  const evidenceCount = deps.store.get<{ count: number }>(
    "SELECT COUNT(*) AS count FROM evidence WHERE audit_id = ?",
    auditId,
  )?.count ?? 0;
  return {
    audit: {
      ...audit,
      config: parseJson(String(audit.config ?? "{}"), {}),
      phase_name: PHASE_NAMES[Number(audit.current_phase ?? 1) - 1] ?? null,
    },
    project,
    repository,
    phases,
    coverage: coverage.map((row) => ({ ...row, files: parseJson(row.files, []) })),
    task_counts: Object.fromEntries(taskCounts.map((row) => [row.status, row.count])),
    finding_counts: findingCounts,
    sessions,
    reports,
    evidence: {
      count: evidenceCount,
      chain: await deps.evidence.verifyChain(auditId),
    },
  };
}

function streamEvents(deps: ApiDeps, request: Request, auditId: string, after: number): Response {
  return sseResponse({
    request,
    replay: deps.events.list(auditId, after, 500),
    subscribe: (send) =>
      deps.events.bus.subscribe((event) => {
        if (event.auditId === auditId) send(event);
      }),
    includeEventId: true,
  });
}

function eventCursor(url: URL): number {
  const raw = url.searchParams.get("after");
  if (raw === null) return 0;
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
    throw badRequest("after must be a non-negative integer");
  }
  return Number(raw);
}

function streamGlobalEvents(deps: ApiDeps, request: Request): Response {
  const recent = deps.store.all<Record<string, unknown>>(
    "SELECT * FROM execution_events WHERE audit_id IS NOT NULL ORDER BY id DESC LIMIT 25",
  );
  const replay = recent.reverse().map((row) => ({
    id: Number(row.id),
    auditId: String(row.audit_id),
    taskId: row.task_id ? String(row.task_id) : null,
    sessionId: row.agent_session_id ? String(row.agent_session_id) : null,
    seq: Number(row.seq),
    type: String(row.type),
    payload: parseJson<Record<string, unknown>>(String(row.payload ?? "{}"), {}),
    createdAt: String(row.created_at),
  }));
  return sseResponse({
    request,
    replay,
    subscribe: (send) => deps.events.bus.subscribe(send),
    includeEventId: false,
  });
}

function fsErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  const code = error.code;
  return typeof code === "string" ? code : undefined;
}

async function readRegularFile(path: string, expectedSize: number): Promise<Uint8Array<ArrayBuffer>> {
  // Both flags are required for the open below to fail closed. A missing flag
  // is `undefined`, and `number | undefined` becomes `number | 0`.
  const noFollow = constants.O_NOFOLLOW;
  const nonBlock = constants.O_NONBLOCK;
  if (typeof noFollow !== "number" || typeof nonBlock !== "number" || noFollow === 0 || nonBlock === 0) {
    throw conflict("Report file is missing or unreadable");
  }
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    // O_NOFOLLOW binds the size check and the read to one inode. O_NONBLOCK
    // makes a replaced pipe return immediately; opening it for read would
    // otherwise wait until another process connects a writer.
    handle = await open(path, constants.O_RDONLY | noFollow | nonBlock);
    const info = await handle.stat();
    if (!info.isFile()) throw conflict("Report file is missing or unreadable");
    if (info.size !== expectedSize) {
      throw conflict("Report integrity check failed; the stored file does not match its recorded size");
    }
    // Cap the read at the size just observed. readFile() stats again and would
    // load a file that grew past the bound after this check.
    const buffer = Buffer.alloc(expectedSize);
    let offset = 0;
    while (offset < expectedSize) {
      const { bytesRead } = await handle.read(buffer, offset, expectedSize - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== expectedSize) {
      throw conflict("Report integrity check failed; the stored file does not match its recorded size");
    }
    return new Uint8Array(buffer);
  } catch (error) {
    if (error instanceof AppError) throw error;
    if (fsErrorCode(error) === "ENOENT") throw notFound("Report file is not available");
    throw conflict("Report file is missing or unreadable");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function projectJson(row: unknown): Record<string, unknown> {
  const record = row as Record<string, unknown>;
  return {
    ...record,
    scope_include: parseJson(String(record.scope_include ?? "[]"), []),
    scope_exclude: parseJson(String(record.scope_exclude ?? "[]"), []),
  };
}

function repositorySummary(row: {
  id: string;
  project_id: string;
  path: string;
  commit_sha: string | null;
  branch: string | null;
  file_count: number;
  total_bytes: number;
  imported_at: string;
  [key: string]: unknown;
}): Record<string, unknown> {
  return {
    id: row.id,
    project_id: row.project_id,
    path: row.path,
    commit_sha: row.commit_sha,
    branch: row.branch,
    file_count: row.file_count,
    total_bytes: row.total_bytes,
    imported_at: row.imported_at,
  };
}

function inventorySummaryFromStored(inventory: Record<string, unknown>): string {
  const files = Array.isArray(inventory.files) ? inventory.files : [];
  const languages = (inventory.languages ?? {}) as Record<string, number>;
  const frameworks = (inventory.frameworks ?? []) as string[];
  const endpoints = Array.isArray(inventory.endpoints) ? inventory.endpoints : [];
  return `${files.length} files; languages: ${
    Object.entries(languages).map(([language, count]) => `${language} (${count})`).join(", ") || "none"
  }; frameworks: ${frameworks.join(", ") || "none"}; ${endpoints.length} endpoint signals`;
}

function findingJson(row: unknown): Record<string, unknown> {
  const record = row as Record<string, unknown>;
  return {
    ...record,
    files: parseJson(String(record.files ?? "[]"), []),
    preconditions: parseJson(String(record.preconditions ?? "[]"), []),
    reproduction: parseJson(String(record.reproduction ?? "[]"), []),
  };
}

function evidenceJson(row: EvidenceRow): Record<string, unknown> {
  return {
    id: row.id,
    audit_id: row.audit_id,
    task_id: row.task_id,
    agent_session_id: row.agent_session_id,
    finding_id: row.finding_id,
    kind: row.kind,
    title: row.title,
    sha256: row.sha256,
    prev_hash: row.prev_hash,
    chain_hash: row.chain_hash,
    size: row.size,
    redacted: row.redacted === 1,
    created_at: row.created_at,
  };
}

function redactHarnessConfig(config: Partial<HarnessConfig>): Record<string, unknown> {
  const envKeys = Object.keys(config.env ?? {});
  return {
    ...config,
    env: Object.fromEntries(envKeys.map((key) => [key, "[redacted]"])),
  };
}

function validateHarnessConfig(body: Record<string, unknown>, store: Store): Partial<HarnessConfig> {
  const config: Partial<HarnessConfig> = {};
  if (body.executable !== undefined) {
    const executable = requireString(body, "executable", 500);
    if (executable.includes("..") || executable.includes("\0")) throw badRequest("Invalid executable path");
    config.executable = executable;
  }
  if (body.provider !== undefined) config.provider = optionalString(body, "provider", 100);
  if (body.model !== undefined) config.model = optionalString(body, "model", 300);
  if (body.permission_mode !== undefined) {
    const mode = requireString(body, "permission_mode", 50);
    if (!["plan", "acceptEdits", "dontAsk", "manual"].includes(mode)) {
      throw badRequest("permission_mode must be plan, acceptEdits, dontAsk, or manual; bypassPermissions is forbidden");
    }
    config.permission_mode = mode;
  }
  if (body.allowed_tools !== undefined) {
    const tools = requireStringArray(body, "allowed_tools");
    if (tools.some((tool) => /^(bash|Bash)(?:$|\()/.test(tool)) && !getSetting(store, "security.allow_shell_tools", false)) {
      throw badRequest("Shell tools are disabled. Enable security.allow_shell_tools with explicit confirmation first.");
    }
    config.allowed_tools = tools;
  }
  if (body.extra_args !== undefined) {
    const args = requireStringArray(body, "extra_args");
    if (args.some((arg) => /dangerously-skip-permissions|bypassPermissions/i.test(arg))) {
      throw badRequest("Arguments that bypass harness permissions are forbidden");
    }
    config.extra_args = args;
  }
  if (body.env !== undefined) {
    if (!body.env || typeof body.env !== "object" || Array.isArray(body.env)) throw badRequest("env must be an object");
    const env: Record<string, string> = {};
    for (const [key, value] of Object.entries(body.env as Record<string, unknown>)) {
      if (!/^[A-Z][A-Z0-9_]{1,99}$/.test(key)) throw badRequest(`Invalid environment variable name: ${key}`);
      if (typeof value !== "string") throw badRequest(`Environment value for ${key} must be a string`);
      if (/KEY|TOKEN|SECRET|PASSWORD/i.test(key) && value && value !== "[redacted]") {
        throw badRequest(`Store secret ${key} in Credentials, not harness environment configuration`);
      }
      env[key] = value;
    }
    config.env = env;
  }
  return config;
}

function validateSettingValue(key: string, value: unknown): string | null {
  const numberRules: Record<string, [number, number]> = {
    "audit.max_areas": [1, 8],
    "audit.max_candidates_per_area": [1, 8],
    "audit.max_confirmations": [0, 30],
    "audit.max_reverifications": [0, 30],
    "audit.max_concurrent_agents": [1, 16],
    "audit.task_timeout_ms": [10_000, 3_600_000],
  };
  if (key in numberRules) {
    const [min, max] = numberRules[key]!;
    if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
      return `${key} must be an integer between ${min} and ${max}`;
    }
    return null;
  }
  if (
    [
      "audit.require_distinct_harness_for_retest",
      "security.allow_shell_tools",
      "security.allow_writable_workspace",
      "security.require_approval_for_shell",
    ].includes(key)
  ) {
    return typeof value === "boolean" ? null : `${key} must be a boolean`;
  }
  if (key === "security.sandbox_mode") {
    return value === "auto" || value === "bwrap" || value === "none" ? null : "security.sandbox_mode must be auto, bwrap, or none";
  }
  if (typeof value !== "string") return `${key} must be a string`;
  if (value.length > 400) return `${key} is too long`;
  return null;
}
