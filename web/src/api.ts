export type User = {
  id: string;
  email: string;
  name: string;
  role: "admin" | "auditor" | "viewer";
  created_at: string;
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export const session = {
  user: null as User | null,
  csrf: "",
  live: false,
};

const listeners = new Set<(event: Record<string, unknown>) => void>();
let source: EventSource | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

function readApiError(payload: Record<string, unknown> | string): { code?: string; message?: string; details?: unknown } | undefined {
  if (typeof payload !== "object" || payload === null || !("error" in payload)) return undefined;
  const error = payload.error;
  if (typeof error !== "object" || error === null) return undefined;
  const result: { code?: string; message?: string; details?: unknown } = {};
  if ("code" in error && typeof error.code === "string") result.code = error.code;
  if ("message" in error && typeof error.message === "string") result.message = error.message;
  if ("details" in error) result.details = error.details;
  return result;
}

export async function api<T>(
  path: string,
  options: { method?: string; body?: unknown; raw?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.method && options.method !== "GET" && options.method !== "HEAD") {
    headers["x-csrf-token"] = session.csrf;
  }
  const response = await fetch(path, {
    method: options.method ?? "GET",
    headers,
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? ((await response.json()) as Record<string, unknown>)
    : await response.text();
  if (!response.ok) {
    const error = readApiError(payload);
    const authProbe = path === "/api/auth/login" || path === "/api/auth/me" || path === "/api/auth/logout";
    if (response.status === 401 && !authProbe) {
      session.user = null;
      window.dispatchEvent(new CustomEvent("argus:unauthorized"));
    }
    throw new ApiError(
      response.status,
      error?.code ?? "request_failed",
      error?.message ?? `Request failed with status ${response.status}`,
      error?.details,
    );
  }
  return payload as T;
}

export async function loadSession(): Promise<boolean> {
  try {
    const result = await api<{ user: User; csrf: string }>("/api/auth/me");
    session.user = result.user;
    session.csrf = result.csrf;
    return true;
  } catch {
    return false;
  }
}

export function connectEvents(onEvent?: (event: Record<string, unknown>) => void): void {
  if (onEvent) listeners.add(onEvent);
  if (source) return;
  source = new EventSource("/api/events/stream");
  source.onopen = () => {
    session.live = true;
    window.dispatchEvent(new CustomEvent("argus:live", { detail: true }));
  };
  source.onerror = () => {
    session.live = false;
    window.dispatchEvent(new CustomEvent("argus:live", { detail: false }));
    if (source) {
      source.close();
      source = null;
    }
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(() => {
      if (session.user) connectEvents();
    }, 4_000);
  };
  source.onmessage = (message) => {
    try {
      const event = JSON.parse(message.data) as Record<string, unknown>;
      for (const listener of listeners) listener(event);
    } catch {
      // ignore malformed live event
    }
  };
}

export function disconnectEvents(): void {
  source?.close();
  source = null;
  session.live = false;
  listeners.clear();
}

export function clearCsrf(): void {
  session.csrf = "";
}
