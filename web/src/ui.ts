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

export function icon(name: string): HTMLElement {
  const glyphs: Record<string, string> = {
    dashboard: "◫",
    projects: "▤",
    audits: "◉",
    explorer: "⌘",
    harnesses: "⚙",
    agents: "◈",
    skills: "▧",
    mcp: "⛓",
    tasks: "☰",
    findings: "⚑",
    reports: "▣",
    settings: "⚒",
    approvals: "⚖",
    plus: "+",
    refresh: "↻",
    play: "▶",
    stop: "■",
    download: "↓",
    close: "×",
    chevron: "›",
    search: "⌕",
  };
  return h("span", { class: "glyph", "aria-hidden": "true" }, glyphs[name] ?? "·");
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
  return h("span", { class: `severity severity-${severity.toLowerCase()}` }, severity.toUpperCase());
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
    h("div", { class: "progress-label" }, label ?? `${value} / ${total} · ${percent}%`),
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
      h("div", { class: "eyebrow" }, "Security operations"),
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
    h("div", { class: "empty-mark" }, "◇"),
    h("h3", {}, title),
    h("p", {}, detail),
    action ?? null,
  );
}

export function loading(label = "Loading"): HTMLElement {
  return h("div", { class: "loading-state" }, h("span", { class: "spinner" }), label);
}

export function errorState(message: string, retry?: () => void): HTMLElement {
  return h(
    "div",
    { class: "error-state" },
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
  return h("button", { class: `btn btn-${tone}`, type: "button", onclick, ...extra }, label) as HTMLButtonElement;
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

export function modal(title: string, content: Child, actions: Child, options: { wide?: boolean } = {}): { close: () => void } {
  const overlay = h("div", { class: "modal-overlay", role: "dialog", "aria-modal": "true", "aria-label": title });
  const close = () => {
    overlay.remove();
    document.removeEventListener("keydown", onKey);
  };
  const onKey = (event: KeyboardEvent) => {
    if (event.key === "Escape") close();
  };
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  const panel = h(
    "div",
    { class: `modal ${options.wide ? "modal-wide" : ""}` },
    h("div", { class: "modal-head" },
      h("h2", {}, title),
      h("button", { class: "icon-btn", "aria-label": "Close", onclick: close }, "×"),
    ),
    h("div", { class: "modal-body" }, content),
    actions ? h("div", { class: "modal-actions" }, actions) : null,
  );
  overlay.appendChild(panel);
  document.body.appendChild(overlay);
  document.addEventListener("keydown", onKey);
  return { close };
}

export function drawer(title: string, content: Child, actions?: Child): { close: () => void } {
  const overlay = h("div", { class: "drawer-overlay", role: "dialog", "aria-modal": "true", "aria-label": title });
  const close = () => {
    overlay.remove();
    document.removeEventListener("keydown", onKey);
  };
  const onKey = (event: KeyboardEvent) => {
    if (event.key === "Escape") close();
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
        h("button", { class: "icon-btn", "aria-label": "Close", onclick: close }, "×"),
      ),
      h("div", { class: "drawer-body" }, content),
      actions ? h("div", { class: "modal-actions" }, actions) : null,
    ),
  );
  document.body.appendChild(overlay);
  document.addEventListener("keydown", onKey);
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
  const node = h("div", { class: `toast toast-${tone}` }, message);
  host.appendChild(node);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.remove(), 4_500);
}

export function confirmAction(title: string, message: string, confirmLabel: string): Promise<boolean> {
  return new Promise((resolvePromise) => {
    const close = () => {
      instance.close();
      resolvePromise(false);
    };
    const instance = modal(
      title,
      h("p", { class: "modal-copy" }, message),
      h("div", { class: "action-row" },
        button("Cancel", close, "secondary"),
        button(confirmLabel, () => {
          instance.close();
          resolvePromise(true);
        }, "danger"),
      ),
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
