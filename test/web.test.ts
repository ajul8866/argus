import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { ApiError, api, loadSession, session } from "../web/src/api.ts";
import { classifyExplorerPath } from "../web/src/pages/explorer.ts";
import { createLiveRefresh, LIVE_REFRESH_DEBOUNCE_MS } from "../web/src/live-refresh.ts";
import { shouldDeferRefresh, shouldRefreshOnReturn } from "../web/src/refresh-policy.ts";

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

  test("defers a missed refresh on live routes and never on local form routes", () => {
    for (const route of ["dashboard", "projects", "audits", "tasks", "findings", "reports", "approvals"]) {
      expect(shouldDeferRefresh(route, true)).toBe(true);
      expect(shouldDeferRefresh(route, false)).toBe(false);
      expect(shouldRefreshOnReturn(route, true)).toBe(false);
    }
    for (const route of ["settings", "skills", "explorer", "mcp", "harnesses", "agents"]) {
      expect(shouldDeferRefresh(route, true)).toBe(false);
      expect(shouldRefreshOnReturn(route, false)).toBe(false);
    }
  });
});

describe("deferred refresh while a dialog is open", () => {
  type Clock = {
    schedule: (run: () => void, delayMs: number) => { cancel: () => void };
    fire: () => void;
    readonly scheduled: boolean;
    readonly delayMs: number | null;
  };

  function clock(): Clock {
    let queued: { run: () => void; delayMs: number } | null = null;
    return {
      schedule(run, delayMs) {
        const entry = { run, delayMs };
        queued = entry;
        return { cancel: () => { if (queued === entry) queued = null; } };
      },
      fire() {
        const entry = queued;
        queued = null;
        entry?.run();
      },
      get scheduled() { return queued !== null; },
      get delayMs() { return queued?.delayMs ?? null; },
    };
  }

  function harness(initial: { route?: string; overlayOpen?: boolean; visible?: boolean; active?: boolean } = {}) {
    let route = initial.route ?? "audits";
    let overlayOpen = initial.overlayOpen ?? false;
    let visible = initial.visible ?? true;
    let active = initial.active ?? true;
    let renders = 0;
    const timer = clock();
    const refresh = createLiveRefresh({
      getRoute: () => route,
      isOverlayOpen: () => overlayOpen,
      isVisible: () => visible,
      isActive: () => active,
      render: () => { renders += 1; },
      schedule: timer.schedule,
    });
    return {
      refresh,
      timer,
      renders: () => renders,
      setRoute: (value: string) => { route = value; },
      setOverlayOpen: (value: boolean) => { overlayOpen = value; },
      setVisible: (value: boolean) => { visible = value; },
      setActive: (value: boolean) => { active = value; },
    };
  }

  test("events that arrive while a task drawer is open refresh the audit when it closes", () => {
    const page = harness({ overlayOpen: true });
    page.refresh.request();
    page.refresh.request();
    page.timer.fire();
    expect(page.renders()).toBe(0);
    expect(page.timer.scheduled).toBe(false);
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(true);
    expect(page.renders()).toBe(1);
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(1);
  });

  test("a refresh already waiting is replayed when a dialog opens before it fires", () => {
    const page = harness();
    page.refresh.request();
    expect(page.timer.delayMs).toBe(LIVE_REFRESH_DEBOUNCE_MS);
    page.setOverlayOpen(true);
    page.timer.fire();
    expect(page.renders()).toBe(0);
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(true);
    expect(page.renders()).toBe(1);
  });

  test("a later event during the dialog cancels the waiting refresh and keeps a single catch-up", () => {
    const page = harness();
    page.refresh.request();
    page.setOverlayOpen(true);
    page.refresh.request();
    expect(page.timer.scheduled).toBe(false);
    page.timer.fire();
    expect(page.renders()).toBe(0);
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(true);
    expect(page.renders()).toBe(1);
  });

  test("an event while the tab is hidden and a dialog is open refreshes after both clear", () => {
    const page = harness({ overlayOpen: true, visible: false });
    page.refresh.request();
    page.setVisible(true);
    page.refresh.onVisible();
    expect(page.renders()).toBe(0);
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(true);
    expect(page.renders()).toBe(1);
  });

  test("a visibility return behind an open dialog waits until the dialog closes", () => {
    const page = harness({ overlayOpen: true });
    page.refresh.onVisible();
    expect(page.renders()).toBe(0);
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(true);
    expect(page.renders()).toBe(1);
  });

  test("returning to a visible live route still refreshes immediately when nothing is open", () => {
    const page = harness();
    page.refresh.request();
    expect(page.timer.scheduled).toBe(true);
    page.refresh.onVisible();
    expect(page.renders()).toBe(1);
    expect(page.timer.scheduled).toBe(false);
    page.timer.fire();
    expect(page.renders()).toBe(1);
  });

  test("a settings dialog does not defer a refresh onto local drafts", () => {
    const page = harness({ route: "settings", overlayOpen: true });
    page.refresh.request();
    page.refresh.onVisible();
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(0);
  });

  test("visibility on a form route does not become a catch-up after navigation", () => {
    const page = harness({ route: "settings", overlayOpen: true });
    page.refresh.onVisible();
    page.setRoute("audits");
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(0);
  });

  test("a deferred refresh waits if the dialog closes while the tab is hidden", () => {
    const page = harness({ overlayOpen: true });
    page.refresh.request();
    page.setVisible(false);
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(0);
    page.setVisible(true);
    page.refresh.onVisible();
    expect(page.renders()).toBe(1);
  });

  test("a debounced refresh that elapses in a hidden tab runs when the tab returns", () => {
    const page = harness();
    page.refresh.request();
    page.setVisible(false);
    page.timer.fire();
    expect(page.renders()).toBe(0);
    page.setVisible(true);
    page.refresh.onVisible();
    expect(page.renders()).toBe(1);
  });

  test("live events on an open route collapse into one debounced refresh", () => {
    const page = harness();
    page.refresh.request();
    page.refresh.request();
    expect(page.timer.scheduled).toBe(true);
    expect(page.timer.delayMs).toBe(LIVE_REFRESH_DEBOUNCE_MS);
    page.timer.fire();
    expect(page.renders()).toBe(1);
    page.timer.fire();
    expect(page.renders()).toBe(1);
  });

  test("a debounced refresh does not rewrite a local form route", () => {
    const page = harness();
    page.refresh.request();
    page.setRoute("explorer");
    page.timer.fire();
    expect(page.renders()).toBe(0);
  });

  test("closing a dialog does not refresh when no live update was missed", () => {
    const page = harness({ overlayOpen: true });
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(0);
  });

  test("a catch-up does not run while another dialog is still open", () => {
    const page = harness({ overlayOpen: true });
    page.refresh.request();
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(0);
  });

  test("a route render consumes a deferred refresh so closing the dialog does not render twice", () => {
    const page = harness({ overlayOpen: true });
    page.refresh.request();
    page.refresh.onRendered();
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(0);
  });

  test("a deferred refresh does not render after sign-out", () => {
    const page = harness({ overlayOpen: true });
    page.refresh.request();
    page.setActive(false);
    page.setOverlayOpen(false);
    expect(page.refresh.onOverlaysClosed()).toBe(false);
    expect(page.renders()).toBe(0);
  });

  test("dispose cancels a debounced refresh", () => {
    const page = harness();
    page.refresh.request();
    page.refresh.dispose();
    page.timer.fire();
    expect(page.renders()).toBe(0);
  });
});
