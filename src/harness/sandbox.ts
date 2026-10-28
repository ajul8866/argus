import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Config } from "../config.ts";
import { WORKSPACE_DIR } from "../config.ts";
import { which } from "./process.ts";
import type { HarnessConfig, HarnessKind } from "./types.ts";
import type { SessionResources } from "../local/types.ts";
import { writeSessionResources } from "./resources.ts";

export type SandboxPlan = {
  command: string[];
  env: Record<string, string>;
  cwd: string;
  home: string;
  mode: "bwrap" | "workspace-copy";
  cleanup: () => void;
  warnings: string[];
};

const SAFE_ENV_KEYS = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "LANG",
  "LC_ALL",
  "TERM",
  "TZ",
  "TMPDIR",
  "NO_COLOR",
  "FORCE_COLOR",
  "CI",
  "XDG_CACHE_HOME",
];

let bwrapChecked: boolean | null = null;

export async function bwrapAvailable(): Promise<boolean> {
  if (bwrapChecked !== null) return bwrapChecked;
  bwrapChecked = Boolean(await which("bwrap"));
  return bwrapChecked;
}

function readHostClaudeEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  const home = process.env.HOME ?? "/root";
  const settingsPath = join(home, ".claude", "settings.json");
  if (existsSync(settingsPath)) {
    try {
      const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as { env?: Record<string, unknown> };
      for (const [key, value] of Object.entries(settings.env ?? {})) {
        if (typeof value !== "string") continue;
        if (!/^(ANTHROPIC_|CLAUDE_CODE_|MCP_TOOL_TIMEOUT$|IS_SANDBOX$)/.test(key)) continue;
        env[key] = value;
      }
    } catch {
      // A malformed host settings file is reported by health checks.
    }
  }
  for (const key of Object.keys(process.env)) {
    if (!/^(ANTHROPIC_|CLAUDE_CODE_)/.test(key)) continue;
    const value = process.env[key];
    if (value) env[key] = value;
  }
  return env;
}

export function baseHarnessEnv(kind: HarnessKind, extra: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of SAFE_ENV_KEYS) {
    const value = process.env[key];
    if (value) env[key] = value;
  }
  env.PATH = env.PATH ?? "/usr/local/bin:/usr/bin:/bin";
  env.NO_COLOR = "1";
  if (kind === "claude-code") Object.assign(env, readHostClaudeEnv());
  env.CI = "1";
  Object.assign(env, extra);
  return env;
}

export function prepareHarnessHome(
  config: Config,
  kind: HarnessKind,
  runId: string,
  harnessConfig: HarnessConfig,
): string {
  const home = join(config.dataDir, "harness-homes", runId);
  mkdirSync(home, { recursive: true, mode: 0o700 });
  if (kind === "pi") {
    const agentDir = join(home, ".pi", "agent");
    mkdirSync(agentDir, { recursive: true, mode: 0o700 });
    const hostModels = process.env.HOME ? join(process.env.HOME, ".pi", "agent", "models.json") : null;
    if (hostModels && existsSync(hostModels)) {
      writeFileSync(join(agentDir, "models.json"), readFileSync(hostModels), { mode: 0o600 });
    }
    writeFileSync(
      join(agentDir, "settings.json"),
      `${JSON.stringify(
        {
          defaultProvider: harnessConfig.provider ?? "magpie",
          defaultModel: harnessConfig.model ?? undefined,
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );
  } else {
    mkdirSync(join(home, ".claude"), { recursive: true, mode: 0o700 });
    writeFileSync(
      join(home, ".claude", "settings.json"),
      `${JSON.stringify({ hasCompletedOnboarding: true, theme: "dark", skipDangerousModePermissionPrompt: false }, null, 2)}\n`,
      { mode: 0o600 },
    );
  }
  chmodSync(home, 0o700);
  return home;
}

export function cleanupHarnessHome(home: string): void {
  try {
    rmSync(home, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }
}

export async function buildSandboxPlan(options: {
  config: Config;
  kind: HarnessKind;
  runId: string;
  executable: string;
  args: string[];
  workspacePath: string;
  harnessConfig: HarnessConfig;
  credentialEnv: Record<string, string>;
  resources?: SessionResources;
}): Promise<SandboxPlan> {
  const { config, kind, runId, workspacePath, harnessConfig } = options;
  const workspaceWritable = true;
  const home = prepareHarnessHome(config, kind, runId, harnessConfig);
  try {
    writeSessionResources(home, kind, options.resources ?? { skills: [], servers: [] });
  } catch (error) {
    cleanupHarnessHome(home);
    throw error;
  }
  const env = baseHarnessEnv(kind, { ...harnessConfig.env, ...options.credentialEnv, HOME: home, TMPDIR: "/tmp" });
  const forceNone = config.sandboxMode === "none";
  const available = forceNone ? false : await bwrapAvailable();
  if (config.sandboxMode === "bwrap" && !available) {
    cleanupHarnessHome(home);
    throw new Error("ARGUS_SANDBOX=bwrap was explicitly required, but bubblewrap is unavailable. Refusing to fall back.");
  }
  const mode: SandboxPlan["mode"] = available ? "bwrap" : "workspace-copy";
  const warnings: string[] = [];
  if (!available) {
    warnings.push(
      config.sandboxMode === "auto"
        ? "bubblewrap is unavailable; execution used workspace-copy isolation (scrubbed environment, no mount namespace)."
        : "ARGUS_SANDBOX=none explicitly disabled bubblewrap; execution is not namespace-isolated.",
    );
  }

  warnings.push(
    available
      ? "Each task runs in an isolated writable workspace copy."
      : "Each task runs in an isolated writable workspace copy; without bubblewrap the host remains the isolation boundary.",
  );
  if (mode === "workspace-copy") {
    return {
      command: [options.executable, ...options.args],
      env,
      cwd: workspacePath,
      home,
      mode,
      cleanup: () => cleanupHarnessHome(home),
      warnings,
    };
  }

  const executable = (await which(options.executable)) ?? options.executable;
  const resolvedExecutable = await realpath(executable).catch(() => executable);
  const bwrap = (await which("bwrap"))!;
  const node = await which("node");
  const bindings: string[][] = [];
  const bind = (source: string, target: string, readOnly = true) => {
    if (!existsSync(source)) return;
    bindings.push([readOnly ? "--ro-bind" : "--bind", source, target]);
  };

  for (const path of ["/usr", "/bin", "/lib", "/lib64", "/sbin", "/opt"]) bind(path, path);
  for (const path of [
    "/etc/resolv.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
  ]) {
    bind(path, path);
  }
  bind(workspacePath, workspacePath, !workspaceWritable);
  bind(home, home, false);

  if (kind === "pi") {
    const piAgentRoot = join(process.env.HOME ?? "/root", ".pi", "agent");
    bind(join(piAgentRoot, "bin"), join(piAgentRoot, "bin"));
    bind(join(piAgentRoot, "install"), join(piAgentRoot, "install"));
    if (node) bind(dirname(dirname(node)), dirname(dirname(node)));
    bind(resolvedExecutable, resolvedExecutable);
  } else {
    bind(dirname(resolvedExecutable), dirname(resolvedExecutable));
    bind("/root/.local/share/claude", "/root/.local/share/claude");
    bind("/root/.local/bin/claude", "/root/.local/bin/claude");
  }

  const command = [
    bwrap,
    "--die-with-parent",
    "--new-session",
    "--clearenv",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup-try",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    ...bindings.flat(),
    "--setenv",
    "HOME",
    home,
    "--setenv",
    "TMPDIR",
    "/tmp",
    "--setenv",
    "PATH",
    env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
    "--setenv",
    "LANG",
    env.LANG ?? "C.UTF-8",
    "--setenv",
    "NO_COLOR",
    "1",
    "--setenv",
    "CI",
    "1",
  ];
  for (const [key, value] of Object.entries(env)) {
    if (["HOME", "TMPDIR", "PATH", "LANG", "NO_COLOR", "CI"].includes(key)) continue;
    command.push("--setenv", key, value);
  }
  command.push("--chdir", workspacePath, resolvedExecutable, ...options.args);

  return {
    command,
    env,
    cwd: workspacePath,
    home,
    mode,
    cleanup: () => cleanupHarnessHome(home),
    warnings,
  };
}

export function workspaceFor(config: Config, auditId: string, runId: string): string {
  const path = join(WORKSPACE_DIR(config), auditId, runId);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}
