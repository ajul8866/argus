import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir, tmpdir } from "node:os";
import { detectRepositoryRoots } from "./repo/directories.ts";
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

function strictEnvInt(name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = env(name, String(fallback));
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
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
    ...new Set([join(dataDir, "repos"), ...envList("ARGUS_ALLOWED_ROOTS", detectRepositoryRoots([
      homedir(), root, "/home", "/srv", "/opt", "/workspace", "/workspaces", "/projects", "/repos", "/mnt", "/media", tmpdir(),
    ]))]),
  ].map((entry) => detectRepositoryRoots([entry])[0] ?? resolve(entry));
  const masterKey = process.env.ARGUS_MASTER_KEY?.trim() || null;
  const sandboxMode = env("ARGUS_SANDBOX", "auto");
  if (!["auto", "bwrap", "none"].includes(sandboxMode)) {
    throw new Error("ARGUS_SANDBOX must be auto, bwrap, or none");
  }
  const logLevel = env("ARGUS_LOG_LEVEL", "info");
  if (!["debug", "info", "warn", "error"].includes(logLevel)) {
    throw new Error("ARGUS_LOG_LEVEL must be debug, info, warn, or error");
  }
  const sessionTtlHours = strictEnvInt("ARGUS_SESSION_TTL_HOURS", 12, 1, 24 * 365);
  return {
    port: strictEnvInt("ARGUS_PORT", 8787, 1, 65_535),
    hostname: env("ARGUS_HOST", "0.0.0.0"),
    dataDir,
    webDist: resolve(env("ARGUS_WEB_DIST", join(root, "web", "dist"))),
    adminEmail: env("ARGUS_ADMIN_EMAIL", "admin@argus.local"),
    adminPassword: process.env.ARGUS_ADMIN_PASSWORD ?? null,
    sessionTtlMs: sessionTtlHours * 60 * 60 * 1000,
    maxConcurrentAgents: strictEnvInt("ARGUS_MAX_AGENTS", 4, 1, 16),
    sandboxMode: sandboxMode as Config["sandboxMode"],
    piBin: env("ARGUS_PI_BIN", "pi"),
    claudeBin: env("ARGUS_CLAUDE_BIN", "claude"),
    allowedRoots,
    masterKey,
    chromeBin: env("ARGUS_CHROME_BIN", "google-chrome"),
    secureCookies: env("ARGUS_SECURE_COOKIES", "0") === "1",
    logLevel: logLevel as Config["logLevel"],
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
