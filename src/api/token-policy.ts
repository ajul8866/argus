import type { ApiToken, TokenService } from "../auth/tokens.ts";
import { AppError } from "../util.ts";

// A null scope is resolved from the audit mode by the endpoint itself.
const TOKEN_ROUTES: Array<{ method: string; path: RegExp; scope: string | null }> = [
  { method: "GET", path: /^\/api\/audits$/, scope: "audit:read" },
  { method: "POST", path: /^\/api\/audits$/, scope: null },
  { method: "GET", path: /^\/api\/audits\/[^/]+$/, scope: "audit:read" },
  { method: "POST", path: /^\/api\/audits\/[^/]+\/start$/, scope: null },
  { method: "GET", path: /^\/api\/audits\/[^/]+\/(tasks|sessions|exploration|events|stream|evidence|reports)$/, scope: "audit:read" },
  { method: "GET", path: /^\/api\/audits\/[^/]+\/findings$/, scope: "finding:read" },
  { method: "POST", path: /^\/api\/audits\/[^/]+\/tasks$/, scope: "task:create" },
  { method: "POST", path: /^\/api\/audits\/[^/]+\/candidates$/, scope: "audit:propose_candidate" },
  { method: "POST", path: /^\/api\/candidates\/[^/]+\/confirm$/, scope: "audit:confirm_candidate" },
  { method: "GET", path: /^\/api\/tasks\/[^/]+$/, scope: "audit:read" },
  { method: "POST", path: /^\/api\/tasks\/[^/]+\/(retry|cancel)$/, scope: "task:control" },
  { method: "GET", path: /^\/api\/findings(?:\/[^/]+)?$/, scope: "finding:read" },
  { method: "POST", path: /^\/api\/findings\/[^/]+\/retest$/, scope: "audit:retest" },
  { method: "GET", path: /^\/api\/projects\/[^/]+\/targets$/, scope: "target:read" },
  { method: "POST", path: /^\/api\/projects\/[^/]+\/targets$/, scope: "target:manage" },
  { method: "GET", path: /^\/api\/targets\/[^/]+\/(authorizations|identities)$/, scope: "target:read" },
  { method: "POST", path: /^\/api\/targets\/[^/]+\/(authorizations|identities)$/, scope: "target:manage" },
];

export function authorizeTokenRoute(tokens: TokenService, token: ApiToken, method: string, path: string): void {
  const route = TOKEN_ROUTES.find((route) => route.method === method && route.path.test(path));
  if (!route) throw new AppError(403, "forbidden", "This endpoint requires a cookie session");
  if (route.scope && !tokens.hasScope(token, route.scope)) {
    throw new AppError(403, "forbidden", `Token requires ${route.scope}`);
  }
  if (method === "POST" && path === "/api/audits" && token.auditId !== null) {
    throw new AppError(403, "forbidden", "An audit-scoped token cannot create another audit");
  }
}
