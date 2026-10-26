import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { ApiError, api, loadSession, session } from "../web/src/api.ts";
import { classifyExplorerPath } from "../web/src/pages/explorer.ts";
import { shouldRefreshOnReturn } from "../web/src/refresh-policy.ts";

type Dispatched = { type: string };

const originalFetch = globalThis.fetch;
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
let dispatched: Dispatched[] = [];
let requestedUrl = "";

function response(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(contentType === "application/json" ? JSON.stringify(body) : String(body), {
    status,
    headers: { "content-type": contentType },
  });
}

function mockFetch(status: number, body: unknown, contentType = "application/json"): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    requestedUrl = String(input);
    return response(status, body, contentType);
  }) as typeof fetch;
}

async function failure(): Promise<ApiError> {
  try {
    await api("/api/projects");
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("Expected api() to reject");
}

beforeEach(() => {
  dispatched = [];
  requestedUrl = "";
  session.user = null;
  session.csrf = "";
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    writable: true,
    value: {
      dispatchEvent(event: Event): boolean {
        dispatched.push({ type: event.type });
        return true;
      },
    },
  });
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
});

describe("web API unauthorized handling", () => {
  test("a login 401 stays on the form without dispatching an app-level unauthorized event", async () => {
    mockFetch(401, { error: { code: "invalid_credentials", message: "Invalid email or password" } });
    let caught: unknown;
    try {
      await api("/api/auth/login", { method: "POST", body: { email: "admin@argus.local", password: "wrong" } });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).code).toBe("invalid_credentials");
    expect(dispatched).toHaveLength(0);
    expect(requestedUrl).toBe("/api/auth/login");
  });

  test("a session probe 401 does not dispatch an app-level unauthorized event", async () => {
    mockFetch(401, { error: { code: "unauthorized", message: "Authentication required" } });
    expect(await loadSession()).toBe(false);
    expect(dispatched).toHaveLength(0);
    expect(requestedUrl).toBe("/api/auth/me");
  });

  test("a logout 401 does not dispatch a second unauthorized event", async () => {
    mockFetch(401, { error: { code: "unauthorized", message: "Authentication required" } });
    let caught: unknown;
    try {
      await api("/api/auth/logout", { method: "POST", body: {} });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect(dispatched).toHaveLength(0);
  });

  test("a protected-route 401 clears the user and dispatches exactly one unauthorized event", async () => {
    session.user = {
      id: "user-1",
      email: "admin@argus.local",
      name: "Administrator",
      role: "admin",
      created_at: "2026-01-01T00:00:00.000Z",
    };
    mockFetch(401, { error: { code: "unauthorized", message: "Authentication required" } });
    const error = await failure();
    expect(error.code).toBe("unauthorized");
    expect(session.user).toBeNull();
    expect(dispatched).toEqual([{ type: "argus:unauthorized" }]);
  });

  test("a protected-route 401 with a non-JSON body still dispatches and keeps a useful message", async () => {
    mockFetch(401, "Authentication required", "text/plain");
    const error = await failure();
    expect(error.message).toBe("Request failed with status 401");
    expect(dispatched).toEqual([{ type: "argus:unauthorized" }]);
  });

  test("a non-401 failure surfaces the API error without dispatching an unauthorized event", async () => {
    mockFetch(500, { error: { code: "internal_error", message: "Internal server error" } });
    const error = await failure();
    expect(error.status).toBe(500);
    expect(error.code).toBe("internal_error");
    expect(dispatched).toHaveLength(0);
  });
});

describe("explorer path classification", () => {
  const files = new Set(["README.md", "src/a.js", "src/routes/invoices.js"]);

  test("separates file, directory, and unknown paths from the snapshot inventory", () => {
    expect(classifyExplorerPath(files, "")).toEqual({ isFile: false, isDirectory: false, directory: "" });
    expect(classifyExplorerPath(files, "README.md")).toEqual({ isFile: true, isDirectory: false, directory: "" });
    expect(classifyExplorerPath(files, "src")).toEqual({ isFile: false, isDirectory: true, directory: "src" });
    expect(classifyExplorerPath(files, "src/routes")).toEqual({ isFile: false, isDirectory: true, directory: "src/routes" });
    expect(classifyExplorerPath(files, "src/a.js")).toEqual({ isFile: true, isDirectory: false, directory: "src" });
    expect(classifyExplorerPath(files, "missing")).toEqual({ isFile: false, isDirectory: false, directory: "" });
  });
});

describe("dashboard refresh policy", () => {
  test("preserves local form and filter routes on visibility return", () => {
    expect(shouldRefreshOnReturn("settings", false)).toBe(false);
    expect(shouldRefreshOnReturn("skills", false)).toBe(false);
    expect(shouldRefreshOnReturn("explorer", false)).toBe(false);
    expect(shouldRefreshOnReturn("mcp", false)).toBe(false);
  });

  test("refreshes live data routes but never behind an open overlay", () => {
    expect(shouldRefreshOnReturn("dashboard", false)).toBe(true);
    expect(shouldRefreshOnReturn("audits", false)).toBe(true);
    expect(shouldRefreshOnReturn("dashboard", true)).toBe(false);
    expect(shouldRefreshOnReturn("settings", true)).toBe(false);
  });
});
