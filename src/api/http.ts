import { AppError, badRequest } from "../util.ts";

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

export function errorResponse(error: unknown): Response {
  if (error instanceof AppError) {
    return json({ error: { code: error.code, message: error.message, details: error.details } }, error.status);
  }
  if (error instanceof SyntaxError) {
    return json({ error: { code: "invalid_json", message: "Request body is not valid JSON" } }, 400);
  }
  console.error("[argus] Unhandled API error:", error);
  return json({ error: { code: "internal_error", message: "Internal server error" } }, 500);
}

export async function readJson(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 2_000_000) throw new AppError(413, "body_too_large", "Request body exceeds 2 MB");
  if (!request.headers.get("content-type")?.includes("application/json")) {
    throw badRequest("Expected application/json");
  }
  const body = (await request.json()) as unknown;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw badRequest("Expected a JSON object");
  }
  return body as Record<string, unknown>;
}

export function requireString(body: Record<string, unknown>, key: string, max = 20_000): string {
  const value = body[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw badRequest(`${key} is required`);
  }
  if (value.length > max) throw badRequest(`${key} exceeds ${max} characters`);
  return value.trim();
}

export function optionalString(body: Record<string, unknown>, key: string, max = 20_000): string | null {
  const value = body[key];
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") throw badRequest(`${key} must be a string`);
  if (value.length > max) throw badRequest(`${key} exceeds ${max} characters`);
  return value.trim();
}

export function requireStringArray(body: Record<string, unknown>, key: string, fallback?: string[]): string[] {
  const value = body[key];
  if (value === undefined) {
    if (fallback) return fallback;
    throw badRequest(`${key} is required`);
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw badRequest(`${key} must be an array of strings`);
  }
  return [...new Set(value.map((entry) => String(entry).trim()).filter(Boolean))];
}

export function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0]!.trim();
  return request.headers.get("x-real-ip") ?? "local";
}
