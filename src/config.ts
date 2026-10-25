import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import packageInfo from "../package.json";

export type Config = {
  port: number;
  hostname: string;
  dataDir: string;
  webDist: string;
  adminEmail: string;
  adminPassword: string | null;
  sessionTtlMs: number;
  maxConcurrentAgents: number;
  sandboxMode: "auto" | "bwrap" | "none";
  piBin: string;
  claudeBin: string;
  allowedRoots: string[];
  masterKey: string | null;
  chromeBin: string;
  secureCookies: boolean;
  logLevel: "debug" | "info" | "warn" | "error";
};

const root = resolve(import.meta.dir, "..");

function env(name: string, fallback: string): string {
  const value = process.env[name];
  return value === undefined || value === "" ? fallback : value;
}

function envInt(name: string, fallback: number): number {
  const parsed = Number.parseInt(env(name, String(fallback)), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function envList(name: string, fallback: string[]): string[] {
  const raw = process.env[name];
  if (!raw) return fallback;
  return raw
    .split(":")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function loadConfig(): Config {
  const dataDir = resolve(env("ARGUS_DATA_DIR", join(root, "data")));
  mkdirSync(dataDir, { recursive: true });
  const allowedRoots = [
    ...new Set([join(dataDir, "repos"), ...envList("ARGUS_ALLOWED_ROOTS", [root])]),
  ].map((entry) => resolve(entry));
  const masterKey = process.env.ARGUS_MASTER_KEY?.trim() || null;
  return {
    port: envInt("ARGUS_PORT", 8787),
    hostname: env("ARGUS_HOST", "0.0.0.0"),
    dataDir,
    webDist: resolve(env("ARGUS_WEB_DIST", join(root, "web", "dist"))),
    adminEmail: env("ARGUS_ADMIN_EMAIL", "admin@argus.local"),
    adminPassword: process.env.ARGUS_ADMIN_PASSWORD ?? null,
    sessionTtlMs: envInt("ARGUS_SESSION_TTL_HOURS", 12) * 60 * 60 * 1000,
    maxConcurrentAgents: Math.max(1, envInt("ARGUS_MAX_AGENTS", 4)),
    sandboxMode: (env("ARGUS_SANDBOX", "auto") as Config["sandboxMode"]) ?? "auto",
    piBin: env("ARGUS_PI_BIN", "pi"),
    claudeBin: env("ARGUS_CLAUDE_BIN", "claude"),
    allowedRoots,
    masterKey,
    chromeBin: env("ARGUS_CHROME_BIN", "google-chrome"),
    secureCookies: env("ARGUS_SECURE_COOKIES", "0") === "1",
    logLevel: env("ARGUS_LOG_LEVEL", "info") as Config["logLevel"],
  };
}

export const APP_NAME = "Argus";
export const APP_VERSION = packageInfo.version;
export const ROOT_DIR = root;
export const EVIDENCE_DIR = (config: Config) => join(config.dataDir, "evidence");
export const WORKSPACE_DIR = (config: Config) => join(config.dataDir, "workspaces");
export const REPORT_DIR = (config: Config) => join(config.dataDir, "reports");
export const REPO_DIR = (config: Config) => join(config.dataDir, "repos");
export const SESSION_COOKIE = "argus_session";
export const PHASE_NAMES = [
  "Codebase Mapping",
  "Systematic Vulnerability Discovery",
  "Independent Confirmation",
  "Structured Findings",
  "Independent Reverification",
  "Final Reporting",
] as const;

export function ensureRuntimeDirs(config: Config): void {
  for (const dir of [
    config.dataDir,
    EVIDENCE_DIR(config),
    WORKSPACE_DIR(config),
    REPORT_DIR(config),
    REPO_DIR(config),
    dirname(config.webDist),
  ]) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}
