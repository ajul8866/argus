import { BROKER_DEADLINE_HEADER, BROKER_FORWARD_PATH, BROKER_TARGET_HEADER } from "./broker.ts";

const SUPPORTED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]);

export async function requestThroughBroker(
  port: number,
  target: string,
  method: string,
  identityId: string | null,
  limits: { timeoutMs?: number; maxBytes?: number } = {},
): Promise<{ status: number; body: string }> {
  const normalizedMethod = method.trim().toUpperCase();
  // Bun may silently send GET for unknown method tokens.
  if (!SUPPORTED_METHODS.has(normalizedMethod)) throw new Error(`Unsupported broker request method: ${normalizedMethod}`);
  const timeoutMs = limits.timeoutMs ?? 35_000;
  const headers: Record<string, string> = { [BROKER_TARGET_HEADER]: target, [BROKER_DEADLINE_HEADER]: String(Date.now() + timeoutMs) };
  if (identityId) headers["x-argus-identity"] = identityId;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("The broker request timed out")), timeoutMs);
  try {
    // An ordinary request keeps target TLS and policy inside the broker. The
    // deadline bounds upstream work even if Bun misses a client disconnect.
    const response = await fetch(`http://127.0.0.1:${port}${BROKER_FORWARD_PATH}`, {
      method: normalizedMethod, headers, signal: controller.signal, redirect: "manual",
    });
    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = response.body?.getReader();
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > (limits.maxBytes ?? 5_000_000)) {
          const error = new Error("The broker response exceeded the size limit");
          controller.abort(error);
          throw error;
        }
        chunks.push(value);
      }
    }
    return { status: response.status, body: Buffer.concat(chunks).toString("utf8") };
  } catch (error) {
    if (controller.signal.aborted) throw controller.signal.reason;
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
