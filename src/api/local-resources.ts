import type { User, AuthService } from "../auth.ts";
import type { LocalCatalog } from "../local/catalog.ts";
import { AppError, badRequest } from "../util.ts";
import { json, readJson, requireStringArray } from "./http.ts";

export async function localResourceRoutes(
  request: Request,
  deps: { catalog: LocalCatalog; auth: AuthService; user: User; ip: string },
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();
  const { catalog } = deps;
  const admin = () => {
    if (deps.user.role !== "admin") throw new AppError(403, "forbidden", "Requires admin role");
  };
  if (["/api/skills/rescan", "/api/mcp/rescan"].includes(path) && method === "POST") {
    admin();
    const result = await catalog.refresh(true);
    deps.auth.logAction(deps.user.email, "local_resources.rescanned", null, { skills: result.skills.length, servers: result.servers.length }, deps.ip);
    return json(result);
  }
  if (["/api/skills", "/api/mcp"].includes(path) && method === "GET") return json(await catalog.refresh());
  const match = path.match(/^\/api\/(skills|mcp)\/([a-f0-9]{24})(?:\/(file|usage))?$/);
  if (!match) throw new AppError(404, "not_found", "Local resource endpoint not found");
  const kind = match[1] === "skills" ? "skill" : "mcp";
  const id = match[2]!;
  const action = match[3];
  if (method === "GET") {
    await catalog.refresh();
    if (action === "usage") return json(catalog.usage(kind, id));
    if (kind === "skill") {
      if (action === "file") {
        try { return json(await catalog.readSkillFile(id, url.searchParams.get("path") ?? "SKILL.md")); }
        catch (error) {
          if (error instanceof AppError) throw error;
          throw badRequest("Skill file is not a readable text file under 256 KB");
        }
      }
      return json({ ...await catalog.skillDetail(id), usage: catalog.usage("skill", id) });
    }
    const server = catalog.list().servers.find((item) => item.id === id);
    if (!server) throw new AppError(404, "resource_not_found", "Local MCP server not found");
    return json({ server, usage: catalog.usage("mcp", id), skills: catalog.list().skills.filter((skill) => skill.mcp_ids.includes(id)) });
  }
  if (method === "PUT" && !action) {
    admin();
    const body = await readJson(request);
    if (Object.keys(body).some((key) => !["enabled", ...(kind === "skill" ? ["roles", "mcp_ids"] : [])].includes(key))) {
      throw badRequest("Only local access settings may be changed; resource definitions come from local configuration");
    }
    if (typeof body.enabled !== "boolean") throw badRequest("enabled must be a boolean");
    const result = kind === "skill"
      ? catalog.setSkillAccess(id, { enabled: body.enabled, roles: requireStringArray(body, "roles"), mcp_ids: requireStringArray(body, "mcp_ids") })
      : catalog.setServerEnabled(id, body.enabled);
    deps.auth.logAction(deps.user.email, `${kind}.access_updated`, id, body, deps.ip);
    return json({ [kind === "skill" ? "skill" : "server"]: result });
  }
  throw new AppError(405, "method_not_allowed", "Method not allowed");
}
