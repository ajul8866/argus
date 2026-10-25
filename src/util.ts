import { createHash, randomUUID } from "node:crypto";
import { resolve, sep } from "node:path";

export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export const badRequest = (message: string, details?: unknown) =>
  new AppError(400, "bad_request", message, details);
export const unauthorized = (message = "Authentication required") =>
  new AppError(401, "unauthorized", message);
export const forbidden = (message = "Not permitted") => new AppError(403, "forbidden", message);
export const notFound = (message = "Not found") => new AppError(404, "not_found", message);
export const conflict = (message: string) => new AppError(409, "conflict", message);

export const now = (): string => new Date().toISOString();
export const uid = (): string => randomUUID();

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function parseJson<T>(value: string, fallback: T): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function toJson(value: unknown): string {
  return JSON.stringify(value);
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}\n… [truncated ${value.length - max} chars]`;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

export function safeJoin(root: string, relative: string): string {
  const normalized = normalizePath(relative);
  if (normalized.includes("\0")) throw badRequest("Invalid path");
  const target = resolve(root, normalized);
  const rootWithSep = root.endsWith(sep) ? root : `${root}${sep}`;
  if (target !== root && !target.startsWith(rootWithSep)) {
    throw badRequest("Path escapes the repository root");
  }
  return target;
}

export function assertInside(root: string, target: string): void {
  const rootWithSep = root.endsWith(sep) ? root : `${root}${sep}`;
  const resolved = resolve(target);
  if (resolved !== resolve(root) && !resolved.startsWith(rootWithSep)) {
    throw forbidden("Path is outside the authorized root");
  }
}

/**
 * Glob matcher used for repository scope. Supports **, *, ?, character classes
 * and {a,b} alternation. Paths are matched with POSIX separators.
 */
export function globToRegExp(glob: string): RegExp {
  const normalized = normalizePath(glob);
  let out = "^";
  let i = 0;
  while (i < normalized.length) {
    const char = normalized[i]!;
    if (char === "*") {
      if (normalized[i + 1] === "*") {
        i += 2;
        if (normalized[i] === "/") {
          out += "(?:.*/)?";
          i += 1;
        } else {
          out += ".*";
        }
        continue;
      }
      out += "[^/]*";
      i += 1;
      continue;
    }
    if (char === "?") {
      out += "[^/]";
      i += 1;
      continue;
    }
    if (char === "{") {
      const end = normalized.indexOf("}", i);
      if (end > i) {
        const parts = normalized.slice(i + 1, end).split(",");
        out += `(?:${parts.map((part) => part.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", "[^/]*")).join("|")})`;
        i = end + 1;
        continue;
      }
    }
    if (char === "[") {
      const end = normalized.indexOf("]", i);
      if (end > i) {
        out += normalized.slice(i, end + 1);
        i = end + 1;
        continue;
      }
    }
    out += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    i += 1;
  }
  out += "$";
  return new RegExp(out, globFlags(normalized));
}

// Dotenv excludes are case-insensitive. Repositories committed on Windows or
// written for Docker often use `.ENV` or `.Env.local`, and a case-sensitive
// glob would leave those files in the snapshot.
function globFlags(glob: string): string {
  return /^(?:\*\*\/)?\.env(?:$|\.|\/)/.test(glob) ? "i" : "";
}

export type Scope = { include: string[]; exclude: string[] };

export function createScopeMatcher(scope: Scope): {
  matches: (relativePath: string) => boolean;
  excludes: (relativePath: string) => boolean;
} {
  const patterns = new Map<string, RegExp>();
  const matchesAny = (globs: string[], path: string): boolean => globs.some((glob) => {
    let pattern = patterns.get(glob);
    if (!pattern) {
      // Compile on first use to preserve short-circuiting for unused patterns.
      pattern = globToRegExp(glob);
      patterns.set(glob, pattern);
    }
    return pattern.test(path);
  });
  return {
    matches(relativePath) {
      const path = normalizePath(relativePath);
      return matchesAny(scope.include, path) && !matchesAny(scope.exclude, path);
    },
    excludes: (relativePath) => matchesAny(scope.exclude, normalizePath(relativePath)),
  };
}

export function matchesScope(relativePath: string, scope: Scope): boolean {
  return createScopeMatcher(scope).matches(relativePath);
}

export class Semaphore {
  private active = 0;
  private waiters: Array<() => void> = [];

  constructor(private readonly limit: number) {}

  get inUse(): number {
    return this.active;
  }

  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) throw new AppError(499, "cancelled", "Cancelled");
    if (this.active < this.limit) {
      this.active += 1;
      return () => this.release();
    }
    await new Promise<void>((resolvePromise, rejectPromise) => {
      const waiter = () => {
        signal?.removeEventListener("abort", onAbort);
        this.active += 1;
        resolvePromise();
      };
      const onAbort = () => {
        this.waiters = this.waiters.filter((entry) => entry !== waiter);
        rejectPromise(new AppError(499, "cancelled", "Cancelled"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.push(waiter);
    });
    return () => this.release();
  }

  private release(): void {
    this.active = Math.max(0, this.active - 1);
    const next = this.waiters.shift();
    next?.();
  }
}

export function extractJson(text: string): unknown {
  const trimmed = text.trim();
  const candidates: string[] = [];
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) candidates.push(trimmed);
  const fence = /```(?:json)?\s*([\s\S]*?)```/gi;
  let match: RegExpExecArray | null;
  while ((match = fence.exec(text)) !== null) {
    if (match[1]) candidates.push(match[1].trim());
  }
  const firstBrace = text.indexOf("{");
  const lastBrace = text.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.push(text.slice(firstBrace, lastBrace + 1));
  }
  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate) as unknown;
    } catch {
      // try the next representation
    }
  }
  return null;
}

export function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}
