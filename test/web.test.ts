import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { ApiError, api, loadSession, session } from "../web/src/api.ts";
import { classifyExplorerPath } from "../web/src/pages/explorer.ts";
import { createLiveRefresh, LIVE_REFRESH_DEBOUNCE_MS } from "../web/src/live-refresh.ts";
import { shouldDeferRefresh, shouldRefreshOnReturn } from "../web/src/refresh-policy.ts";
import { createAuditWithSnapshot, createProjectWithSnapshot } from "../web/src/components/audit-setup.ts";
import { coverageRows, type ExplorationPayload } from "../web/src/pages/coverage.ts";
import { explorationRows } from "../web/src/pages/exploration.ts";

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

describe("project and audit setup", () => {
  function script(results: Array<{ status?: number; body: unknown }>) {
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ path: String(input), body: init?.body ? JSON.parse(String(init.body)) : {} });
      const next = results.shift();
      if (!next) throw new Error("Unexpected extra request");
      return response(next.status ?? 200, next.body);
    }) as typeof fetch;
    return calls;
  }

  test("adding a project imports its files without a second user action", async () => {
    const calls = script([{ body: { project: { id: "p1" } } }, { body: { repository: { id: "r1" } } }]);
    expect(await createProjectWithSnapshot({ name: "App", source_path: "/host/app" })).toEqual({ id: "p1", importError: null });
    expect(calls.map((call) => call.path)).toEqual(["/api/projects", "/api/projects/p1/import"]);
  });

  test("an import failure retains the newly created project for recovery", async () => {
    const calls = script([{ body: { project: { id: "p1" } } }, { status: 400, body: { error: { message: "No source files" } } }]);
    expect(await createProjectWithSnapshot({ name: "App", source_path: "/host/app" })).toEqual({ id: "p1", importError: "No source files" });
    expect(calls.filter((call) => call.path === "/api/projects")).toHaveLength(1);
  });

  test("a project creation failure never attempts to import files", async () => {
    const calls = script([{ status: 403, body: { error: { message: "Access denied" } } }]);
    await expect(createProjectWithSnapshot({ name: "App", source_path: "/host/app" })).rejects.toThrow("Access denied");
    expect(calls).toHaveLength(1);
  });

  test("starting an audit automatically imports missing files and keeps server defaults", async () => {
    const calls = script([{ body: { repository: { id: "r1" } } }, { body: { audit: { id: "a1" } } }, { body: { ok: true } }]);
    expect(await createAuditWithSnapshot({ projectId: "p1", startNow: true })).toEqual({ id: "a1", startError: null });
    expect(calls.map((call) => call.path)).toEqual(["/api/projects/p1/import", "/api/audits", "/api/audits/a1/start"]);
    expect(calls[1]?.body).toEqual({ project_id: "p1", repository_id: "r1", overrides: {} });
  });

  test("an existing snapshot is used without an unnecessary import", async () => {
    const calls = script([{ body: { audit: { id: "a1" } } }, { body: { ok: true } }]);
    await createAuditWithSnapshot({ projectId: "p1", repositoryId: "r1", startNow: true });
    expect(calls.map((call) => call.path)).toEqual(["/api/audits", "/api/audits/a1/start"]);
  });

  test("a failed automatic import never creates an unusable audit", async () => {
    const calls = script([{ status: 400, body: { error: { message: "No source files" } } }]);
    await expect(createAuditWithSnapshot({ projectId: "p1", startNow: true })).rejects.toThrow("No source files");
    expect(calls.map((call) => call.path)).toEqual(["/api/projects/p1/import"]);
  });

  test("a start failure returns the saved audit instead of creating a duplicate", async () => {
    const calls = script([{ body: { audit: { id: "a1" } } }, { status: 409, body: { error: { message: "Cannot start yet" } } }]);
    expect(await createAuditWithSnapshot({ projectId: "p1", repositoryId: "r1", startNow: true })).toEqual({ id: "a1", startError: "Cannot start yet" });
    expect(calls.filter((call) => call.path === "/api/audits")).toHaveLength(1);
  });

  test("saving for later preserves overrides without starting model work", async () => {
    const calls = script([{ body: { audit: { id: "a1" } } }]);
    await createAuditWithSnapshot({ projectId: "p1", repositoryId: "r1", startNow: false, overrides: { max_cost_usd: 5 } });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.body.overrides).toEqual({ max_cost_usd: 5 });
  });
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
    advance: (ms: number) => void;
    readonly scheduled: boolean;
    readonly scheduleCount: number;
    readonly delayMs: number | null;
    readonly deadline: number | null;
  };

  function clock(): Clock {
    type Entry = { run: () => void; delayMs: number; deadline: number };
    let now = 0;
    let nextId = 1;
    let scheduleCount = 0;
    const queued = new Map<number, Entry>();
    return {
      schedule(run, delayMs) {
        scheduleCount += 1;
        const id = nextId;
        nextId += 1;
        queued.set(id, { run, delayMs, deadline: now + delayMs });
        return { cancel: () => { queued.delete(id); } };
      },
      fire() {
        const first = queued.entries().next();
        if (first.done) return;
        queued.delete(first.value[0]);
        first.value[1].run();
      },
      advance(ms) {
        now += ms;
        for (;;) {
          const due = [...queued.entries()].find(([, entry]) => entry.deadline <= now);
          if (!due) return;
          queued.delete(due[0]);
          due[1].run();
        }
      },
      get scheduled() { return queued.size > 0; },
      get scheduleCount() { return scheduleCount; },
      get delayMs() {
        const first = queued.values().next();
        return first.done ? null : first.value.delayMs;
      },
      get deadline() {
        const first = queued.values().next();
        return first.done ? null : first.value.deadline;
      },
    };
  }

  function harness(initial: {
    route?: string;
    overlayOpen?: boolean;
    visible?: boolean;
    active?: boolean;
    deferRender?: boolean;
  } = {}) {
    let route = initial.route ?? "audits";
    let overlayOpen = initial.overlayOpen ?? false;
    let visible = initial.visible ?? true;
    let active = initial.active ?? true;
    let renders = 0;
    const completions: Array<() => void> = [];
    const timer = clock();
    const refresh = createLiveRefresh({
      getRoute: () => route,
      isOverlayOpen: () => overlayOpen,
      isVisible: () => visible,
      isActive: () => active,
      render: () => {
        renders += 1;
        if (!initial.deferRender) return;
        const gate = Promise.withResolvers<void>();
        completions.push(() => gate.resolve());
        return gate.promise;
      },
      schedule: timer.schedule,
    });
    return {
      refresh,
      timer,
      renders: () => renders,
      pendingRenders: () => completions.length,
      async completeRender() {
        const resolve = completions.shift();
        if (!resolve) throw new Error("no render is pending");
        resolve();
        await flushMicrotasks();
      },
      setRoute: (value: string) => { route = value; },
      setOverlayOpen: (value: boolean) => { overlayOpen = value; },
      setVisible: (value: boolean) => { visible = value; },
      setActive: (value: boolean) => { active = value; },
    };
  }

  async function flushMicrotasks(): Promise<void> {
    for (let i = 0; i < 25; i += 1) await Promise.resolve();
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

  test("a stream of live events cannot postpone the first scheduled refresh", () => {
    const page = harness();
    page.refresh.request();
    page.timer.advance(500);
    page.refresh.request();
    page.timer.advance(500);
    page.refresh.request();
    expect(page.timer.scheduleCount).toBe(1);
    expect(page.timer.scheduled).toBe(true);
    expect(page.timer.deadline).toBe(LIVE_REFRESH_DEBOUNCE_MS);

    const remaining = LIVE_REFRESH_DEBOUNCE_MS - 1_000;
    page.timer.advance(remaining - 1);
    expect(page.renders()).toBe(0);
    page.timer.advance(1);
    expect(page.renders()).toBe(1);
    page.timer.advance(60_000);
    expect(page.renders()).toBe(1);
  });

  test("an async render stays single-flight and runs one catch-up for signals it missed", async () => {
    const page = harness({ deferRender: true });
    page.refresh.request();
    page.timer.fire();
    expect(page.renders()).toBe(1);
    expect(page.pendingRenders()).toBe(1);

    page.refresh.request();
    page.refresh.request();

    page.timer.fire();
    await flushMicrotasks();
    expect(page.renders()).toBe(1);
    expect(page.pendingRenders()).toBe(1);

    await page.completeRender();
    page.timer.fire();
    await flushMicrotasks();
    expect(page.renders()).toBe(2);
    expect(page.pendingRenders()).toBe(1);

    await page.completeRender();
    page.timer.fire();
    await flushMicrotasks();
    expect(page.renders()).toBe(2);
    expect(page.pendingRenders()).toBe(0);
    expect(page.timer.scheduled).toBe(false);
  });

  test("onRendered cancels a scheduled live refresh so navigation is not refreshed twice", () => {
    const page = harness();
    page.refresh.request();
    expect(page.timer.scheduled).toBe(true);
    page.refresh.onRendered();
    expect(page.timer.scheduled).toBe(false);
    page.timer.fire();
    expect(page.renders()).toBe(0);
  });

  test("a route navigation during a pending async render suppresses the stale catch-up", async () => {
    const page = harness({ deferRender: true });
    page.refresh.request();
    page.timer.fire();
    expect(page.renders()).toBe(1);

    page.refresh.request();
    page.refresh.request();
    page.refresh.onRendered();
    expect(page.timer.scheduled).toBe(false);

    await page.completeRender();
    page.timer.fire();
    await flushMicrotasks();
    expect(page.renders()).toBe(1);
    expect(page.pendingRenders()).toBe(0);
  });

  test("live events after navigation still catch up when the old render settles", async () => {
    const page = harness({ deferRender: true });
    page.refresh.request();
    page.timer.fire();
    expect(page.renders()).toBe(1);

    page.refresh.onRendered();
    page.refresh.request();
    await page.completeRender();
    page.timer.fire();
    await flushMicrotasks();
    expect(page.renders()).toBe(2);
    expect(page.pendingRenders()).toBe(1);

    await page.completeRender();
    page.timer.fire();
    await flushMicrotasks();
    expect(page.renders()).toBe(2);
    expect(page.pendingRenders()).toBe(0);
  });

  test("dispose during a pending async render suppresses the stale catch-up", async () => {
    const page = harness({ deferRender: true });
    page.refresh.request();
    page.timer.fire();
    expect(page.renders()).toBe(1);

    page.refresh.request();
    page.refresh.dispose();
    expect(page.timer.scheduled).toBe(false);

    await page.completeRender();
    page.timer.fire();
    await flushMicrotasks();
    expect(page.renders()).toBe(1);
    expect(page.pendingRenders()).toBe(0);
  });
});

describe("dynamic exploration views", () => {
  const payload: ExplorationPayload = {
    assets: [
      { id: "a1", kind: "app", assetKey: "https://app.test" },
      { id: "a2", kind: "endpoint", assetKey: "/api/invoices/inv-1" },
    ],
    nodes: [
      { id: "n1", kind: "goal", status: "completed", payload: { text: "Find access control issues" }, taskId: null, sessionId: null },
      { id: "n2", kind: "intent", status: "completed", payload: { title: "Cross-tenant invoice read" }, taskId: "t1", sessionId: "s1" },
      { id: "n3", kind: "finding", status: "completed", payload: { finding_id: "f1", title: "IDOR" }, taskId: null, sessionId: null },
      { id: "n4", kind: "fact", status: "completed", payload: { summary: "200" }, taskId: null, sessionId: null },
    ],
    edges: [
      { fromNodeId: "n1", toNodeId: "n2", kind: "spawns" },
      { fromNodeId: "n2", toNodeId: "n3", kind: "proves" },
    ],
    anchors: [
      { nodeId: "n1", assetId: "a1" },
      { nodeId: "n2", assetId: "a1" },
      { nodeId: "n3", assetId: "a1" },
      { nodeId: "n4", assetId: "a2" },
    ],
    coverage: [
      { assetId: "a1", kind: "app", assetKey: "https://app.test", tested: true },
      { assetId: "a2", kind: "endpoint", assetKey: "/api/invoices/inv-1", tested: false },
    ],
  };

  test("coverage counts anchored nodes and findings, untested assets first", () => {
    expect(coverageRows(payload)).toEqual([
      { assetId: "a2", kind: "endpoint", assetKey: "/api/invoices/inv-1", tested: false, nodes: 1, findings: 0 },
      { assetId: "a1", kind: "app", assetKey: "https://app.test", tested: true, nodes: 3, findings: 1 },
    ]);
  });

  test("exploration rows expose the hypothesis, assets, and finding link", () => {
    const rows = explorationRows(payload);
    expect(rows).toHaveLength(4);
    expect(rows.find((row) => row.id === "n2")).toMatchObject({
      label: "Cross-tenant invoice read",
      taskId: "t1",
      sessionId: "s1",
      assets: ["https://app.test"],
    });
    expect(rows.find((row) => row.id === "n3")?.findingId).toBe("f1");
    expect(rows.find((row) => row.id === "n1")?.label).toBe("Find access control issues");
  });
});

describe("dynamic audit setup", () => {
  function script(results: Array<{ status?: number; body: unknown }>) {
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ path: String(input), body: init?.body ? JSON.parse(String(init.body)) : {} });
      const next = results.shift();
      if (!next) throw new Error("Unexpected extra request");
      return response(next.status ?? 200, next.body);
    }) as typeof fetch;
    return calls;
  }

  test("a dynamic audit is created without importing a repository", async () => {
    const calls = script([{ body: { audit: { id: "a1" } } }]);
    const result = await createAuditWithSnapshot({
      projectId: "p1",
      startNow: false,
      mode: "dynamic",
      targetId: "t1",
    });
    expect(result).toEqual({ id: "a1", startError: null });
    expect(calls.map((call) => call.path)).toEqual(["/api/audits"]);
    expect(calls[0]!.body).toMatchObject({ project_id: "p1", mode: "dynamic", target_id: "t1" });
    expect(calls[0]!.body.repository_id).toBeUndefined();
  });

  test("a dynamic audit without a target is refused before any request", async () => {
    const calls = script([]);
    await expect(
      createAuditWithSnapshot({ projectId: "p1", startNow: false, mode: "dynamic" }),
    ).rejects.toThrow(/target/i);
    expect(calls).toHaveLength(0);
  });

  test("a hybrid audit still imports the repository when none is selected", async () => {
    const calls = script([
      { body: { repository: { id: "r1" } } },
      { body: { audit: { id: "a2" } } },
    ]);
    const result = await createAuditWithSnapshot({
      projectId: "p1",
      startNow: false,
      mode: "hybrid",
      targetId: "t1",
    });
    expect(result.id).toBe("a2");
    expect(calls.map((call) => call.path)).toEqual(["/api/projects/p1/import", "/api/audits"]);
    expect(calls[1]!.body).toMatchObject({ repository_id: "r1", mode: "hybrid", target_id: "t1" });
  });
});
