import "./styles.css";
import { api, clearCsrf, connectEvents, disconnectEvents, loadSession, session } from "./api.ts";
import { createLiveRefresh } from "./live-refresh.ts";
import {
  button,
  closeOverlays,
  h,
  input,
  loading,
  toast,
} from "./ui.ts";
import { renderDashboard } from "./pages/dashboard.ts";
import { renderProjects, renderProjectDetail } from "./pages/projects.ts";
import { renderAudits, renderAuditDetail } from "./pages/audits.ts";
import { renderExplorer } from "./pages/explorer.ts";
import { renderHarnesses } from "./pages/harnesses.ts";
import { renderAgents } from "./pages/agents.ts";
import { renderTasks } from "./pages/tasks.ts";
import { renderFindings } from "./pages/findings.ts";
import { renderReports } from "./pages/reports.ts";
import { renderSettings } from "./pages/settings.ts";
import { renderApprovals } from "./pages/approvals.ts";
import { renderSkills } from "./pages/skills.ts";
import { renderMcp } from "./pages/mcp.ts";
import { openAuditCreate } from "./components/audit-create.ts";

const NAV_GROUPS: Array<{ label: string; items: Array<{ route: string; label: string }> }> = [
  {
    label: "Operate",
    items: [
      { route: "dashboard", label: "Overview" },
      { route: "projects", label: "Projects" },
      { route: "audits", label: "Audits" },
      { route: "explorer", label: "Explorer" },
    ],
  },
  {
    label: "Execution",
    items: [
      { route: "harnesses", label: "Harnesses" },
      { route: "agents", label: "Agents" },
      { route: "skills", label: "Skills" },
      { route: "mcp", label: "MCP servers" },
      { route: "tasks", label: "Tasks" },
      { route: "approvals", label: "Approvals" },
    ],
  },
  {
    label: "Assurance",
    items: [
      { route: "findings", label: "Findings" },
      { route: "reports", label: "Reports" },
      { route: "settings", label: "Settings" },
    ],
  },
];

const app = document.getElementById("app")!;
let currentRoute = "dashboard";
let currentParams = new URLSearchParams();
let renderToken = 0;
let liveConnected = false;
let focusRestore: (() => void) | null = null;
const mobileNav = window.matchMedia("(max-width: 900px)");
let navListenersInstalled = false;
let loggingOut = false;

function parseRoute(): { route: string; id: string | null; params: URLSearchParams } {
  const raw = location.hash.replace(/^#\/?/, "");
  const [pathPart = "", queryPart = ""] = raw.split("?");
  const params = new URLSearchParams(queryPart);
  const segments = pathPart.split("/").filter(Boolean);
  const route = segments[0] ?? "dashboard";
  const id = segments[1] ?? null;
  return { route, id: id ? decodeURIComponent(id) : null, params };
}

function routeLabel(route: string): string {
  return (
    NAV_GROUPS.flatMap((group) => group.items).find((item) => item.route === route)?.label ??
    (route === "dashboard" ? "Overview" : route)
  );
}

function setNavOpen(open: boolean, moveFocus = false): void {
  const next = mobileNav.matches && open;
  document.body.classList.toggle("nav-open", next);
  const toggle = document.getElementById("nav-toggle") as HTMLButtonElement | null;
  toggle?.setAttribute("aria-expanded", String(next));
  toggle?.setAttribute("aria-label", next ? "Close navigation" : "Open navigation");
  const sidebar = document.getElementById("sidebar");
  if (sidebar) sidebar.inert = mobileNav.matches && !next;
  if (moveFocus) {
    if (next) sidebar?.querySelector<HTMLElement>(".nav a")?.focus();
    else toggle?.focus();
  }
}

function installNavListeners(): void {
  if (navListenersInstalled) return;
  navListenersInstalled = true;
  mobileNav.addEventListener("change", () => {
    setNavOpen(mobileNav.matches ? document.body.classList.contains("nav-open") : false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && document.body.classList.contains("nav-open")) {
      event.preventDefault();
      setNavOpen(false, true);
    }
  });
}

function shell(): void {
  const nav = NAV_GROUPS.map((group) =>
    h(
      "div",
      { class: "nav" },
      h("div", { class: "nav-label" }, group.label),
      ...group.items.map((item) =>
        h("a", { href: `#/${item.route}`, "data-route": item.route, class: item.route === currentRoute ? "active" : "" },
          h("span", {}, item.label),
        ),
      ),
    ),
  );

  const sidebar = h(
    "aside",
    { class: "sidebar", id: "sidebar" },
    h("a", { class: "brand", href: "#/dashboard", style: { textDecoration: "none" } },
      h("div", { class: "brand-mark" }, "A"),
      h("div", {}, h("div", { class: "brand-name" }, "Argus"), h("div", { class: "brand-sub" }, "autonomous audit")),
    ),
    h("nav", { "aria-label": "Main navigation" }, ...nav),
    h("div", { class: "sidebar-foot" },
      h("div", { class: "live-indicator", id: "live-indicator", role: "status", "aria-live": "polite", "aria-atomic": "true" },
        h("span", { id: "live-label" }, liveConnected ? "Live" : "Offline"),
      ),
      h("div", { class: "user-chip" },
        h("div", { class: "avatar" }, (session.user?.name ?? "?").slice(0, 2).toUpperCase()),
        h("div", { class: "user-meta" },
          h("div", { class: "user-name" }, session.user?.name ?? ""),
          h("div", { class: "user-role" }, session.user?.role ?? ""),
        ),
      ),
      h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: logout }, "Sign out"),
    ),
  );

  const main = h("main", { class: "main" },
    h("div", { class: "topbar" },
      h("div", { class: "topbar-left" },
        h("button", {
          class: "btn btn-ghost btn-sm mobile-toggle",
          id: "nav-toggle",
          type: "button",
          "aria-expanded": "false",
          "aria-controls": "sidebar",
          "aria-label": "Open navigation",
          onclick: () => setNavOpen(!document.body.classList.contains("nav-open"), true),
        }, "Menu"),
        h("nav", { class: "breadcrumbs", "aria-label": "Breadcrumb" },
          h("a", { href: "#/dashboard" }, "Argus"),
          h("span", { class: "sep" }, "/"),
          h("span", { id: "breadcrumb-label" }, routeLabel(currentRoute)),
        ),
      ),
      h("div", { class: "topbar-right" },
        h("a", { class: "btn btn-secondary btn-sm", href: "#/findings" }, "Findings"),
        button("New audit", () => void openAuditCreate(), "secondary", { class: "btn-sm" }),
      ),
    ),
    h("div", { id: "view", tabindex: "-1" }),
  );

  const skipLink = h("a", {
    class: "skip-link",
    href: "#view",
    onclick: (event: Event) => {
      event.preventDefault();
      document.getElementById("view")?.focus();
    },
  }, "Skip to content");
  const navBackdrop = h("div", {
    class: "nav-backdrop",
    "aria-hidden": "true",
    onclick: () => setNavOpen(false, true),
  });
  app.replaceChildren(skipLink, h("div", { class: "shell" }, sidebar, main), navBackdrop);
  installNavListeners();
  setNavOpen(false);
  updateLiveIndicator();
  syncNav();
}

function syncNav(): void {
  for (const link of document.querySelectorAll<HTMLAnchorElement>(".nav a[data-route]")) {
    const active = link.dataset.route === currentRoute;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  const label = document.getElementById("breadcrumb-label");
  if (label) label.textContent = routeLabel(currentRoute);
}

function updateLiveIndicator(): void {
  const indicator = document.getElementById("live-indicator");
  const label = document.getElementById("live-label");
  indicator?.classList.toggle("on", liveConnected);
  if (label) label.textContent = liveConnected ? "Live" : "Offline";
}

function captureViewFocus(): () => void {
  const view = document.getElementById("view");
  const active = document.activeElement;
  if (!(active instanceof HTMLElement) || !view?.contains(active) || active === view) return () => {};
  const label = active.getAttribute("aria-label");
  const id = active.id;
  const text = (active.textContent ?? "").trim();
  const tag = active.tagName;
  return () => {
    if (hasOpenOverlay()) return;
    const root = document.getElementById("view");
    if (!root) return;
    const current = document.activeElement;
    if (
      current instanceof HTMLElement &&
      current !== document.body &&
      current !== document.documentElement &&
      current !== root
    ) return;
    if (id) {
      const byId = root.querySelector<HTMLElement>(`#${CSS.escape(id)}`);
      if (byId) {
        byId.focus();
        return;
      }
    }
    if (label) {
      const match = [...root.querySelectorAll<HTMLElement>("[aria-label]")]
        .find((element) => element.getAttribute("aria-label") === label);
      if (match) {
        match.focus();
        return;
      }
    }
    if (!text) return;
    const matches = [...root.querySelectorAll<HTMLElement>(tag)].filter((element) => (element.textContent ?? "").trim() === text);
    const only = matches.length === 1 ? matches[0] : undefined;
    only?.focus();
  };
}

async function renderRoute(): Promise<void> {
  const parsed = parseRoute();
  currentRoute = parsed.route;
  currentParams = parsed.params;
  const token = ++renderToken;
  const restoreFocus = focusRestore;
  focusRestore = null;
  const view = document.getElementById("view");
  if (!view) return;
  liveRefresh.onRendered();
  const target = document.createElement("div");
  target.style.display = "contents";
  view.replaceChildren(target);
  setNavOpen(false);
  syncNav();
  document.title = `${routeLabel(parsed.route)} | Argus`;
  try {
    switch (parsed.route) {
      case "dashboard":
        await renderDashboard(target);
        break;
      case "projects":
        if (parsed.id) await renderProjectDetail(target, parsed.id);
        else await renderProjects(target);
        break;
      case "audits":
        if (parsed.id) await renderAuditDetail(target, parsed.id, parsed.params);
        else await renderAudits(target);
        break;
      case "explorer":
        await renderExplorer(target, parsed.params);
        break;
      case "harnesses":
        await renderHarnesses(target);
        break;
      case "agents":
        await renderAgents(target);
        break;
      case "skills":
        await renderSkills(target, parsed.params);
        break;
      case "mcp":
        await renderMcp(target, parsed.params);
        break;
      case "tasks":
        await renderTasks(target, parsed.params);
        break;
      case "findings":
        await renderFindings(target, parsed.params);
        break;
      case "reports":
        await renderReports(target, parsed.params);
        break;
      case "settings":
        await renderSettings(target);
        break;
      case "approvals":
        await renderApprovals(target);
        break;
      default:
        target.replaceChildren(
          h("div", { class: "empty-state" },
            h("div", { class: "empty-mark" }, "?"),
            h("h3", {}, "Page not found"),
            h("p", {}, `No dashboard route matches "${parsed.route}".`),
            h("a", { class: "btn btn-primary", href: "#/dashboard" }, "Back to overview"),
          ),
        );
    }
    if (token !== renderToken) {
      target.remove();
      return;
    }
    restoreFocus?.();
  } catch (error) {
    if (token !== renderToken) {
      target.remove();
      return;
    }
    view.replaceChildren(
      h("div", { class: "error-state" },
        h("h3", {}, "Dashboard error"),
        h("p", {}, error instanceof Error ? error.message : String(error)),
        button("Reload", () => void renderRoute(), "secondary"),
      ),
    );
  }
  setNavOpen(false);
}

function hasOpenOverlay(): boolean {
  return Boolean(document.querySelector(".modal-overlay, .drawer-overlay"));
}

const liveRefresh = createLiveRefresh({
  getRoute: () => currentRoute,
  isOverlayOpen: hasOpenOverlay,
  isVisible: () => document.visibilityState === "visible",
  isActive: () => Boolean(session.user) && !loggingOut,
  render: () => {
    void renderRoute();
  },
});

function loginView(errorMessage?: string): void {
  closeOverlays();
  setNavOpen(false);
  disconnectEvents();
  const email = input("email", { type: "email", placeholder: "admin@argus.local", autocomplete: "username", required: true });
  const password = input("password", { type: "password", placeholder: "Password", autocomplete: "current-password", required: true });
  const errorBox = h("div", { class: "login-error hidden", id: "login-error", role: "alert", tabindex: "-1" }, errorMessage ?? "");
  email.setAttribute("aria-describedby", "login-error");
  password.setAttribute("aria-describedby", "login-error");
  if (errorMessage) {
    errorBox.classList.remove("hidden");
    requestAnimationFrame(() => errorBox.focus());
  } else {
    requestAnimationFrame(() => email.focus());
  }
  const submit = h("button", { class: "btn btn-primary", type: "submit", style: { width: "100%" } }, "Sign in");
  const form = h("form", {
    class: "login-form",
    onsubmit: async (event: Event) => {
      event.preventDefault();
      errorBox.classList.add("hidden");
      submit.setAttribute("disabled", "true");
      try {
        const result = await api<{ user: typeof session.user; csrf: string }>("/api/auth/login", {
          method: "POST",
          body: { email: email.value, password: password.value },
        });
        session.user = result.user;
        session.csrf = result.csrf;
        await enterApp();
      } catch (error) {
        errorBox.textContent = error instanceof Error ? error.message : "Sign-in failed";
        errorBox.classList.remove("hidden");
        errorBox.focus();
      } finally {
        submit.removeAttribute("disabled");
      }
    },
  },
    h("h2", {}, "Sign in to Argus"),
    h("span", { class: "hint" }, "Local operator authentication. Sessions are HttpOnly and CSRF-protected."),
    errorBox,
    h("label", { class: "field", style: { marginBottom: "12px" } }, h("span", { class: "field-label" }, "Email"), email),
    h("label", { class: "field", style: { marginBottom: "18px" } }, h("span", { class: "field-label" }, "Password"), password),
    submit,
    h("div", { class: "login-foot" }, "Self-hosted autonomous security audit platform"),
  );

  app.replaceChildren(
    h("div", { class: "login-layout" },
      h("aside", { class: "login-aside" },
        h("div", { class: "login-brand" },
          h("div", { class: "brand-mark" }, "A"),
          h("div", {}, h("div", { class: "brand-name" }, "Argus"), h("div", { class: "brand-sub" }, "autonomous audit")),
        ),
        h("div", { class: "login-headline" },
          h("h1", {}, "Security review at agent speed, with evidence you can defend."),
          h("p", {}, "Six orchestrated phases. Real Pi and Claude Code execution. Independent confirmation, exact-source evidence gates, immutable findings, and deterministic reports."),
          h("div", { class: "login-points" },
            h("div", { class: "login-point" }, h("span", {}, "01"), h("span", {}, "Codebase map and attack-surface inventory")),
            h("div", { class: "login-point" }, h("span", {}, "02"), h("span", {}, "Concurrent source-to-sink discovery")),
            h("div", { class: "login-point" }, h("span", {}, "03"), h("span", {}, "Fresh-context confirmation and reverification")),
            h("div", { class: "login-point" }, h("span", {}, "04"), h("span", {}, "Hash-chained evidence and professional exports")),
          ),
        ),
        h("div", { class: "tiny muted" }, "Self-hosted, local-first, no simulated agents"),
      ),
      h("main", { class: "login-panel" }, form),
    ),
  );
}

async function enterApp(): Promise<void> {
  if (!session.user) {
    loginView();
    return;
  }
  loggingOut = false;
  shell();
  connectEvents((event) => {
    const type = String(event.type ?? "");
    if (type.startsWith("agent.text") || type.startsWith("agent.thinking") || type === "agent.usage") return;
    liveRefresh.request();
  });
  await renderRoute();
}

async function logout(): Promise<void> {
  loggingOut = true;
  liveRefresh.dispose();
  renderToken++;
  disconnectEvents();
  try {
    await api("/api/auth/logout", { method: "POST", body: {} });
  } catch {
    // session may already be invalid
  }
  session.user = null;
  clearCsrf();
  loginView();
}

window.addEventListener("hashchange", () => {
  setNavOpen(false);
  if (session.user) void renderRoute();
  else loginView();
});

window.addEventListener("argus:live", (event) => {
  liveConnected = Boolean((event as CustomEvent).detail);
  updateLiveIndicator();
});

window.addEventListener("argus:unauthorized", () => {
  if (loggingOut) return;
  loginView("Your session expired. Sign in again.");
});

window.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") liveRefresh.onVisible();
});

window.addEventListener("argus:overlays-closed", () => {
  focusRestore = captureViewFocus();
  if (!liveRefresh.onOverlaysClosed()) focusRestore = null;
});

document.addEventListener("click", (event) => {
  const target = event.target as HTMLElement;
  if (document.body.classList.contains("nav-open") && !target.closest("#sidebar") && !target.closest(".mobile-toggle")) {
    setNavOpen(false);
  }
});

async function bootstrap(): Promise<void> {
  app.replaceChildren(h("div", { class: "loading-state", style: { minHeight: "60vh" } }, h("span", { class: "spinner" }), "Starting Argus control plane"));
  const authenticated = await loadSession();
  if (!authenticated) {
    loginView();
    return;
  }
  await enterApp();
}

void bootstrap();
