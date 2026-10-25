type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, unknown>;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") element.className = String(value);
    else if (key === "text") element.textContent = String(value);
    else if (key === "html") element.innerHTML = String(value);
    else if (key === "dataset") {
      for (const [dataKey, dataValue] of Object.entries(value as Record<string, unknown>)) {
        element.dataset[dataKey] = String(dataValue);
      }
    } else if (key === "style" && typeof value === "object") {
      for (const [styleKey, styleValue] of Object.entries(value as Record<string, unknown>)) {
        element.style.setProperty(styleKey.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`), String(styleValue));
      }
    } else if (key.startsWith("on") && typeof value === "function") {
      element.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === "value" && element instanceof HTMLInputElement) {
      element.value = String(value);
    } else if (key === "checked" && element instanceof HTMLInputElement) {
      element.checked = Boolean(value);
    } else {
      element.setAttribute(key, String(value));
    }
  }
  append(element, children);
  return element;
}

export function append(parent: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (child instanceof Node) parent.appendChild(child);
    else parent.appendChild(document.createTextNode(String(child)));
  }
}

export function frag(...children: Child[]): DocumentFragment {
  const fragment = document.createDocumentFragment();
  append(fragment, children);
  return fragment;
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

const iconPaths: Record<string, string> = {
  dashboard: "M3 3h5v6H3z M12 3h5v3h-5z M3 13h5v4H3z M12 10h5v7h-5z",
  projects: "M2.5 5h5l2 2h8v10h-15z M2.5 5V3h5l2 2h8v2",
  audits: "M7 4H4v13h12V4h-3 M7 2h6v4H7z M7 11l2 2 4-4",
  explorer: "M7 6l-4 4 4 4 M13 6l4 4-4 4 M11.5 3l-3 14",
  harnesses: "M6 6h8v8H6z M8 2v4 M12 2v4 M8 14v4 M12 14v4 M2 8h4 M2 12h4 M14 8h4 M14 12h4",
  agents: "M9.5 5a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0 M2 17v-2a5 5 0 0 1 10 0v2 M13 3a2.5 2.5 0 0 1 0 5 M14 10a4 4 0 0 1 4 4v3",
  skills: "M10 5v12 M10 5C8 3 5 3 2.5 4v12c2.5-1 5.5-1 7.5 1 M10 5c2-2 5-2 7.5-1v12c-2.5-1-5.5-1-7.5 1",
  mcp: "M6 2v5 M14 2v5 M4 7h12v3a6 6 0 0 1-6 6v2 M4 7v3a6 6 0 0 0 6 6",
  tasks: "M8 4h9 M8 10h9 M8 16h9 M2 4l1 1 2-2 M2 10l1 1 2-2 M2 16l1 1 2-2",
  menu: "M3 5h14 M3 10h14 M3 15h14",
  findings: "M4 18V3 M4 3h12l-2 4 2 4H4",
  reports: "M4 2h8l4 4v12H4z M12 2v4h4 M7 10h6 M7 14h6",
  settings: "M3 5h8 M15 5h2 M3 15h2 M9 15h8 M11 2h4v6h-4z M5 12h4v6H5z",
  approvals: "M10 2v15 M6 18h8 M3 5h14 M5 5l-3 7h6z M15 5l-3 7h6z",
  plus: "M10 3v14 M3 10h14",
  refresh: "M16.5 7A7 7 0 1 0 17 12 M16.5 2.5V7H12",
  play: "M6 3.5l11 6.5-11 6.5z",
  stop: "M4 4h12v12H4z",
  download: "M10 2v10 M6 8l4 4 4-4 M3 13v4h14v-4",
  close: "M5 5l10 10 M15 5L5 15",
  menu: "M3 5h14 M3 10h14 M3 15h14",
  chevron: "M7 4l6 6-6 6",
  search: "M14 8a6 6 0 1 1-12 0 6 6 0 0 1 12 0 M12.5 12.5L18 18",
};

export function icon(name: string): HTMLElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 20 20");
  svg.setAttribute("width", "20");
  svg.setAttribute("height", "20");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.5");
  svg.setAttribute("stroke-linecap", "square");
  svg.setAttribute("stroke-linejoin", "miter");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", iconPaths[name] ?? iconPaths.reports!);
  svg.appendChild(path);
  return h("span", { class: "glyph", "aria-hidden": "true" }, svg);
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function formatFullDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function timeAgo(value: string | null | undefined): string {
  if (!value) return "—";
  const diff = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(diff)) return value;
  const seconds = Math.round(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function duration(ms: number | null | undefined): string {
  if (!ms) return "—";
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

export function badge(label: string, tone = "neutral"): HTMLElement {
  return h("span", { class: `badge badge-${tone}` }, label);
}

export function statusTone(status: string): string {
  const value = status.toLowerCase();
  if (["completed", "reverified", "confirmed", "ready", "approved", "generated", "reverified"].includes(value)) return "good";
  if (["running", "queued", "starting", "confirming", "reported", "pending", "waiting_approval"].includes(value)) return "warn";
  if (["failed", "rejected", "blocked", "cancelled", "missing", "error", "unauthenticated", "denied", "timeout"].includes(value)) return "bad";
  if (["needs_correction", "unresolved", "inconclusive", "refuted"].includes(value)) return "warn";
  return "neutral";
}

export function statusBadge(status: string): HTMLElement {
  return badge(status.replaceAll("_", " "), statusTone(status));
}

export function severityBadge(severity: string): HTMLElement {
  return h("span", { class: `severity severity-${severity.toLowerCase()}` }, severity.toLowerCase());
}

export function phaseLabel(phase: number): string {
  return (
    [
      "Mapping",
      "Discovery",
      "Confirmation",
      "Findings",
      "Reverification",
      "Reporting",
    ][phase - 1] ?? `Phase ${phase}`
  );
}

export function phaseName(phase: number): string {
  return (
    [
      "Codebase Mapping",
      "Systematic Vulnerability Discovery",
      "Independent Confirmation",
      "Structured Findings",
      "Independent Reverification",
      "Final Reporting",
    ][phase - 1] ?? `Phase ${phase}`
  );
}

export function progress(value: number, total: number, label?: string): HTMLElement {
  const percent = total <= 0 ? 0 : Math.min(100, Math.round((value / total) * 100));
  return h(
    "div",
    { class: "progress-wrap" },
    h("div", { class: "progress-track", role: "progressbar", "aria-valuenow": percent, "aria-valuemin": 0, "aria-valuemax": 100 },
      h("div", { class: "progress-fill", style: { width: `${percent}%` } }),
    ),
    h("div", { class: "progress-label" }, label ?? `${value} / ${total}, ${percent}%`),
  );
}

export function statCard(label: string, value: string | number, detail?: string, tone = "accent"): HTMLElement {
  return h(
    "div",
    { class: `stat-card stat-${tone}` },
    h("div", { class: "stat-label" }, label),
    h("div", { class: "stat-value" }, String(value)),
    detail ? h("div", { class: "stat-detail" }, detail) : null,
  );
}

export function pageHeader(title: string, subtitle: string, actions?: Child): HTMLElement {
  return h(
    "header",
    { class: "page-header" },
    h("div", { class: "page-heading" },
      h("h1", {}, title),
      h("p", {}, subtitle),
    ),
    actions ? h("div", { class: "page-actions" }, actions) : null,
  );
}

export function section(title: string, content: Child, actions?: Child): HTMLElement {
  return h(
    "section",
    { class: "panel" },
    h("div", { class: "panel-head" },
      h("h2", {}, title),
      actions ? h("div", { class: "panel-actions" }, actions) : null,
    ),
    content,
  );
}

export function emptyState(title: string, detail: string, action?: Child): HTMLElement {
  return h(
    "div",
    { class: "empty-state" },
    h("div", { class: "empty-mark", "aria-hidden": "true" }, icon("projects")),
    h("h3", {}, title),
    h("p", {}, detail),
    action ?? null,
  );
}

export function loading(label = "Loading"): HTMLElement {
  return h("div", { class: "loading-state", role: "status", "aria-atomic": "true" }, h("span", { class: "spinner", "aria-hidden": "true" }), label);
}

export function errorState(message: string, retry?: () => void): HTMLElement {
  return h(
    "div",
    { class: "error-state", role: "alert" },
    h("h3", {}, "Unable to load this view"),
    h("p", {}, message),
    retry ? button("Retry", retry, "secondary") : null,
  );
}

export function button(
  label: string,
  onclick: (event: MouseEvent) => void,
  tone: "primary" | "secondary" | "danger" | "ghost" = "primary",
  extra: Attrs = {},
): HTMLButtonElement {
  const { class: extraClass, ...attrs } = extra;
  const className = `btn btn-${tone}${extraClass ? ` ${String(extraClass)}` : ""}`;
  return h("button", { class: className, type: "button", onclick, ...attrs }, label) as HTMLButtonElement;
}

export function linkButton(label: string, href: string, tone = "secondary"): HTMLElement {
  return h("a", { class: `btn btn-${tone}`, href }, label);
}

export function field(
  label: string,
  input: HTMLElement,
  hint?: string,
): HTMLElement {
  return h(
    "label",
    { class: "field" },
    h("span", { class: "field-label" }, label),
    input,
    hint ? h("span", { class: "field-hint" }, hint) : null,
  );
}

export function input(name: string, options: { type?: string; value?: string; placeholder?: string; required?: boolean; min?: number; max?: number; step?: number; autocomplete?: string } = {}): HTMLInputElement {
  return h("input", {
    class: "input",
    name,
    type: options.type ?? "text",
    value: options.value ?? "",
    placeholder: options.placeholder ?? "",
    required: options.required ?? false,
    min: options.min,
    max: options.max,
    step: options.step,
    autocomplete: options.autocomplete ?? "off",
  }) as HTMLInputElement;
}

export function textarea(name: string, value = "", placeholder = ""): HTMLTextAreaElement {
  return h("textarea", { class: "input textarea", name, placeholder, rows: 4 }, value) as HTMLTextAreaElement;
}

export function select(name: string, options: Array<{ value: string; label: string }>, value?: string): HTMLSelectElement {
  const element = h("select", { class: "input select", name }) as HTMLSelectElement;
  for (const option of options) {
    element.appendChild(h("option", { value: option.value, selected: option.value === value }, option.label));
  }
  return element;
}

const openOverlays: HTMLElement[] = [];

function containOverlayFocus(overlay: HTMLElement, close: () => void): () => void {
  const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  openOverlays.push(overlay);
  overlay.tabIndex = -1;
  const isTopOverlay = () => openOverlays[openOverlays.length - 1] === overlay;
  const focusableElements = () => Array.from(overlay.querySelectorAll<HTMLElement>(
    "a[href], area[href], button, input, select, textarea, summary, iframe, object, embed, audio[controls], video[controls], [contenteditable], [tabindex]",
  )).filter((element) => element.tabIndex >= 0 && !element.matches(":disabled") && !element.closest("[hidden], [inert]") && element.getClientRects().length > 0 && getComputedStyle(element).visibility === "visible");
  const onKey = (event: KeyboardEvent) => {
    if (!isTopOverlay() || event.defaultPrevented) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close();
    } else if (event.key === "Tab") {
      const elements = focusableElements();
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (!first || !last) {
        event.preventDefault();
        overlay.focus();
      } else if (event.shiftKey && (document.activeElement === first || document.activeElement === overlay || !overlay.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !overlay.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    }
  };
  const onFocus = (event: FocusEvent) => {
    if (isTopOverlay() && event.target instanceof Node && !overlay.contains(event.target)) {
      (focusableElements()[0] ?? overlay).focus();
    }
  };
  document.addEventListener("keydown", onKey);
  document.addEventListener("focusin", onFocus);
  return () => {
    const wasTopOverlay = isTopOverlay();
    const index = openOverlays.indexOf(overlay);
    if (index !== -1) openOverlays.splice(index, 1);
    document.removeEventListener("keydown", onKey);
    document.removeEventListener("focusin", onFocus);
    if (!wasTopOverlay) return;
    const activeOverlay = openOverlays[openOverlays.length - 1];
    if (opener?.isConnected && (!activeOverlay || activeOverlay.contains(opener))) opener.focus({ preventScroll: true });
    else activeOverlay?.focus({ preventScroll: true });
  };
}

export function modal(title: string, content: Child, actions: Child, options: { wide?: boolean; onDismiss?: () => void } = {}): { close: () => void } {
  const overlay = h("div", { class: "modal-overlay", role: "dialog", "aria-modal": "true", "aria-label": title });
  const close = () => {
    if (!overlay.isConnected) return;
    overlay.remove();
    releaseFocus();
    options.onDismiss?.();
  };
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  const panel = h(
    "div",
    { class: `modal ${options.wide ? "modal-wide" : ""}` },
    h("div", { class: "modal-head" },
      h("h2", {}, title),
      h("button", { class: "icon-btn", type: "button", "aria-label": "Close", onclick: close }, icon("close")),
    ),
    h("div", { class: "modal-body" }, content),
    actions ? h("div", { class: "modal-actions" }, actions) : null,
  );
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
  const releaseFocus = containOverlayFocus(overlay, close);
  overlay.querySelector<HTMLButtonElement>(".icon-btn")?.focus();
  return { close };
}

export function drawer(title: string, content: Child, actions?: Child): { close: () => void } {
  const overlay = h("div", { class: "drawer-overlay", role: "dialog", "aria-modal": "true", "aria-label": title });
  const close = () => {
    if (!overlay.isConnected) return;
    overlay.remove();
    releaseFocus();
  };
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  overlay.appendChild(
    h(
      "aside",
      { class: "drawer" },
      h("div", { class: "modal-head" },
        h("h2", {}, title),
        h("button", { class: "icon-btn", type: "button", "aria-label": "Close", onclick: close }, icon("close")),
      ),
      h("div", { class: "drawer-body" }, content),
      actions ? h("div", { class: "modal-actions" }, actions) : null,
    ),
  );
  document.body.appendChild(overlay);
  const releaseFocus = containOverlayFocus(overlay, close);
  overlay.querySelector<HTMLButtonElement>(".icon-btn")?.focus();
  return { close };
}

let toastTimer: ReturnType<typeof setTimeout> | null = null;
export function toast(message: string, tone: "success" | "error" | "info" = "info"): void {
  let host = document.getElementById("toast-host");
  if (!host) {
    host = document.createElement("div");
    host.id = "toast-host";
    host.className = "toast-host";
    document.body.appendChild(host);
  }
  const node = h("div", { class: `toast toast-${tone}`, role: tone === "error" ? "alert" : "status", "aria-atomic": "true" }, message);
  host.appendChild(node);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.remove(), 4_500);
}

export function confirmAction(title: string, message: string, confirmLabel: string): Promise<boolean> {
  return new Promise((resolvePromise) => {
    let settled = false;
    const settle = (result: boolean) => {
      if (settled) return;
      settled = true;
      instance.close();
      resolvePromise(result);
    };
    const instance = modal(
      title,
      h("p", { class: "modal-copy" }, message),
      h("div", { class: "action-row" },
        button("Cancel", () => settle(false), "secondary"),
        button(confirmLabel, () => settle(true), "danger"),
      ),
      { onDismiss: () => settle(false) },
    );
  });
}

export function jsonBlock(value: unknown): HTMLElement {
  return h("pre", { class: "json-block" }, JSON.stringify(value, null, 2));
}

export function relativePhaseStatus(phase: { status: string }): string {
  return phase.status === "pending" ? "not started" : phase.status;
}

export function sortBy<T>(items: T[], key: (item: T) => string | number): T[] {
  return [...items].sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0));
}

export function truncate(value: string, max = 140): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export function fill(parent: HTMLElement, children: Child[]): void {
  parent.replaceChildren();
  append(parent, children);
}
