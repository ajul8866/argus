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
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let size = 0;
  if (request.body) {
    const reader = request.body.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 2_000_000) {
          await reader.cancel();
          throw new AppError(413, "body_too_large", "Request body exceeds 2 MB");
        }
        chunks.push(decoder.decode(value, { stream: true }));
      }
    } finally {
      reader.releaseLock();
    }
  }
  chunks.push(decoder.decode());
  const body: unknown = JSON.parse(chunks.join(""));
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw badRequest("Expected a JSON object");
  }
  return body as Record<string, unknown>;
}

export function requireString(body: Record<string, unknown>, key: string, max = 20_000, trim = true): string {
  const value = body[key];
  if (typeof value !== "string" || (trim ? value.trim() : value).length === 0) {
    throw badRequest(`${key} is required`);
  }
  if (value.length > max) throw badRequest(`${key} exceeds ${max} characters`);
  return trim ? value.trim() : value;
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

export function clientIp(peerAddress?: string): string {
  return peerAddress ?? "local";
}
