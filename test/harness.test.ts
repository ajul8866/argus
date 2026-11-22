import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { PiHarnessAdapter } from "../src/harness/pi.ts";
import { ClaudeCodeHarnessAdapter } from "../src/harness/claude.ts";
import { baseHarnessEnv, buildSandboxPlan } from "../src/harness/sandbox.ts";
import type { HarnessKind, HarnessTask } from "../src/harness/types.ts";
import { DEFAULT_HARNESS_CONFIG } from "../src/settings.ts";

let dir: string;
let config: Config;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "argus-harness-"));
  await mkdir(join(dir, "workspace"));
  config = {
    port: 0, hostname: "127.0.0.1", dataDir: dir, webDist: join(dir, "web"),
    adminEmail: "test@example.test", adminPassword: null, sessionTtlMs: 60_000,
    maxConcurrentAgents: 2, sandboxMode: "none", piBin: "pi", claudeBin: "claude",
    allowedRoots: [dir], masterKey: "harness-test-key", chromeBin: "missing-chrome", secureCookies: false, logLevel: "error",
  };
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function fakeAdapter(kind: HarnessKind, source: string) {
  const executable = join(dir, `fake-${kind}`);
  await writeFile(executable, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
  const settings = { ...DEFAULT_HARNESS_CONFIG[kind], executable };
  return kind === "pi" ? new PiHarnessAdapter(config, settings, {}) : new ClaudeCodeHarnessAdapter(config, settings, {});
}

function task(timeoutMs = 5_000): HarnessTask {
  return {
    runId: crypto.randomUUID(), auditId: "audit", taskId: "task", role: "test",
    prompt: "Return JSON", systemPrompt: "Test", workspace: join(dir, "workspace"), model: "test-model", timeoutMs,
  };
}

describe("harness termination", () => {
  for (const kind of ["pi", "claude-code"] as const) {
    test(`${kind} reports an execution deadline as a timeout rather than operator cancellation`, async () => {
      const adapter = await fakeAdapter(kind, "setInterval(() => {}, 1000);");
      const result = await adapter.run(task(50), { onEvent() {} });
      expect(result.status).toBe("timeout");
      expect(result.failureKind).toBe("timeout");
    });

    test(`${kind} preserves explicit operator cancellation`, async () => {
      const adapter = await fakeAdapter(kind, "setInterval(() => {}, 1000);");
      const controller = new AbortController();
      const result = await adapter.run(task(), {
        signal: controller.signal,
        onEvent(event) { if (event.type === "session_start") queueMicrotask(() => controller.abort()); },
      });
      expect(result.status).toBe("cancelled");
      expect(result.failureKind).toBe("cancelled");
    });

    test(`${kind} honours an abort signal that is already set before launch`, async () => {
      const adapter = await fakeAdapter(kind, "setInterval(() => {}, 1000);");
      const controller = new AbortController();
      controller.abort();
      const result = await adapter.run(task(), { signal: controller.signal, onEvent() {} });
      expect(result.status).toBe("cancelled");
      expect(result.failureKind).toBe("cancelled");
    }, 15_000);
  }
});

describe("Pi completion protocol", () => {
  for (const scenario of [
    { name: "EOF without agent_settled", settled: false, exit: 0, status: "failed" },
    { name: "a crash after an assistant message", settled: false, exit: 7, status: "failed" },
    { name: "agent_settled followed by a process failure", settled: true, exit: 7, status: "failed" },
    { name: "agent_settled followed by a clean exit", settled: true, exit: 0, status: "completed" },
  ] as const) {
    test(`Pi handles ${scenario.name}`, async () => {
      const adapter = await fakeAdapter("pi", `
let input = "";
for await (const chunk of Bun.stdin.stream()) {
  input += new TextDecoder().decode(chunk);
  if (input.includes('"type":"prompt"')) {
    console.log(JSON.stringify({type: "message_end", message: {role: "assistant", content: [{type: "text", text: '{"ok":true}'}]}}));
    ${scenario.settled ? 'console.log(JSON.stringify({type: "agent_settled"}));' : ""}
    process.exit(${scenario.exit});
  }
}
`);
      const result = await adapter.run(task(), { onEvent() {} });
      expect(result.status).toBe(scenario.status);
    });
  }

  test("Pi rejects an oversized stdout record instead of buffering it without limit", async () => {
    const adapter = await fakeAdapter("pi", `
let input = "";
for await (const chunk of Bun.stdin.stream()) {
  input += new TextDecoder().decode(chunk);
  if (input.includes('"type":"prompt"')) {
    console.log("x".repeat(2_100_000));
    process.exit(0);
  }
}
`);
    const result = await adapter.run(task(), { onEvent() {} });
    expect(result.status).toBe("failed");
    expect(result.error).toContain("exceeded");
  }, 15_000);
});

test("Pi accumulates usage across every assistant turn", async () => {
  const adapter = await fakeAdapter("pi", `
let input = "";
for await (const chunk of Bun.stdin.stream()) {
  input += new TextDecoder().decode(chunk);
  if (input.includes('"type":"prompt"')) {
    for (const usage of [
      {input:100, output:10, totalTokens:130, cacheRead:20, cost:{total:0.4}},
      {input:200, output:30, totalTokens:270, cacheRead:40, cost:{total:0.2}},
    ]) console.log(JSON.stringify({type:"message_end", message:{role:"assistant", content:[{type:"text",text:'{"ok":true}'}], usage}}));
    console.log(JSON.stringify({type:"agent_settled"}));
    process.exit(0);
  }
}
`);
  const result = await adapter.run(task(), { onEvent() {} });
  expect(result.status).toBe("completed");
  expect(result.usage).toMatchObject({ input_tokens: 300, output_tokens: 40, total_tokens: 400, cache_read_tokens: 60 });
  expect(result.usage.cost_usd).toBeCloseTo(0.6);
});

describe("sandbox environment isolation", () => {
  const HOST_SECRETS: Record<string, string> = {
    AWS_SECRET_ACCESS_KEY: "host-aws-secret",
    GITHUB_TOKEN: "ghp_hosttokenvalue",
    GIT_ASKPASS: "/tmp/evil-askpass",
    SSH_AUTH_SOCK: "/tmp/evil-ssh",
    GIT_CONFIG_PARAMETERS: "'filter.evil.smudge=id'",
    ANTHROPIC_API_KEY: "sk-ant-host-process-key",
    CLAUDE_CODE_ENTRYPOINT: "host-claude-entrypoint",
  };
  const originalEnv: Record<string, string | undefined> = {};
  let hostHome = "";
  let plans: Array<{ cleanup: () => void }> = [];

  beforeEach(async () => {
    hostHome = await mkdtemp(join(tmpdir(), "argus-host-home-"));
    originalEnv.HOME = process.env.HOME;
    process.env.HOME = hostHome;
    for (const [key, value] of Object.entries(HOST_SECRETS)) {
      originalEnv[key] = process.env[key];
      process.env[key] = value;
    }
    mkdirSync(join(hostHome, ".claude"), { recursive: true });
    mkdirSync(join(hostHome, ".pi", "agent"), { recursive: true });
    writeFileSync(
      join(hostHome, ".claude", "settings.json"),
      `${JSON.stringify({
        env: {
          ANTHROPIC_API_KEY: "sk-ant-from-host-settings",
          AWS_SECRET_ACCESS_KEY: "settings-aws-secret",
          MCP_TOOL_TIMEOUT: "120000",
          IS_SANDBOX: "1",
          PATH: "/evil/bin",
        },
      })}\n`,
    );
    writeFileSync(join(hostHome, ".pi", "agent", "models.json"), '{"models":[{"id":"host-model"}]}\n');
    writeFileSync(
      join(hostHome, ".pi", "agent", "settings.json"),
      `${JSON.stringify({ defaultProvider: "host-secret-provider", apiKey: "host-pi-key" })}\n`,
    );
  });

  afterEach(async () => {
    for (const plan of plans) plan.cleanup();
    plans = [];
    if (originalEnv.HOME === undefined) delete process.env.HOME;
    else process.env.HOME = originalEnv.HOME;
    for (const key of Object.keys(HOST_SECRETS)) {
      if (originalEnv[key] === undefined) delete process.env[key];
      else process.env[key] = originalEnv[key];
    }
    await rm(hostHome, { recursive: true, force: true });
  });

  function secretKeys(): string[] {
    return ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "GIT_ASKPASS", "SSH_AUTH_SOCK", "GIT_CONFIG_PARAMETERS"];
  }

  test("workspace-copy sessions drop host secrets and replace HOME", async () => {
    const plan = await buildSandboxPlan({
      config,
      kind: "pi",
      runId: "iso-pi",
      executable: "/bin/true",
      args: ["--version"],
      workspacePath: join(dir, "workspace"),
      harnessConfig: DEFAULT_HARNESS_CONFIG.pi,
      credentialEnv: { MAGPIE_API_KEY: "vaulted-pi-key" },
    });
    plans.push(plan);

    expect(plan.mode).toBe("workspace-copy");
    expect(plan.cwd).toBe(join(dir, "workspace"));
    expect(plan.home).toBe(join(config.dataDir, "harness-homes", "iso-pi"));
    expect(plan.env.HOME).toBe(plan.home);
    expect(plan.env.TMPDIR).toBe("/tmp");
    expect(plan.env.MAGPIE_API_KEY).toBe("vaulted-pi-key");
    expect(plan.env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(plan.env.CLAUDE_CODE_ENTRYPOINT).toBeUndefined();
    for (const key of secretKeys()) expect(plan.env[key]).toBeUndefined();
    expect(plan.home).not.toBe(hostHome);
    expect((statSync(plan.home).mode & 0o777)).toBe(0o700);
    expect(JSON.parse(readFileSync(join(plan.home, ".pi", "agent", "models.json"), "utf8"))).toEqual({
      models: [{ id: "host-model" }],
    });
    expect(JSON.parse(readFileSync(join(plan.home, ".pi", "agent", "settings.json"), "utf8"))).toEqual({
      defaultProvider: "magpie",
      defaultModel: DEFAULT_HARNESS_CONFIG.pi.model,
    });
    expect(existsSync(join(plan.home, ".claude", "settings.json"))).toBe(false);
  });

  test("Claude sessions keep allowlisted host Claude env and still drop unrelated secrets", async () => {
    const plan = await buildSandboxPlan({
      config,
      kind: "claude-code",
      runId: "iso-claude",
      executable: "/bin/true",
      args: ["--version"],
      workspacePath: join(dir, "workspace"),
      harnessConfig: {
        ...DEFAULT_HARNESS_CONFIG["claude-code"],
        env: { OPERATOR_FLAG: "from-harness-config" },
      },
      credentialEnv: { ANTHROPIC_API_KEY: "vaulted-claude-key" },
    });
    plans.push(plan);

    expect(plan.mode).toBe("workspace-copy");
    expect(plan.env.HOME).toBe(join(config.dataDir, "harness-homes", "iso-claude"));
    expect(plan.env.OPERATOR_FLAG).toBe("from-harness-config");
    expect(plan.env.ANTHROPIC_API_KEY).toBe("vaulted-claude-key");
    expect(plan.env.CLAUDE_CODE_ENTRYPOINT).toBe("host-claude-entrypoint");
    expect(plan.env.MCP_TOOL_TIMEOUT).toBe("120000");
    expect(plan.env.IS_SANDBOX).toBe("1");
    for (const key of secretKeys()) expect(plan.env[key]).toBeUndefined();
    expect(plan.env.PATH).not.toContain("/evil/bin");
    const sessionSettings = JSON.parse(readFileSync(join(plan.home, ".claude", "settings.json"), "utf8"));
    expect(sessionSettings).toEqual({
      hasCompletedOnboarding: true,
      theme: "dark",
      skipDangerousModePermissionPrompt: false,
    });
    expect(sessionSettings.env).toBeUndefined();
  });

  test("baseHarnessEnv copies host Anthropic keys only for Claude Code", () => {
    const claude = baseHarnessEnv("claude-code", {});
    const pi = baseHarnessEnv("pi", {});
    expect(claude.ANTHROPIC_API_KEY).toBe("sk-ant-host-process-key");
    expect(claude.CLAUDE_CODE_ENTRYPOINT).toBe("host-claude-entrypoint");
    expect(claude.MCP_TOOL_TIMEOUT).toBe("120000");
    expect(pi.ANTHROPIC_API_KEY).toBeUndefined();
    expect(pi.CLAUDE_CODE_ENTRYPOINT).toBeUndefined();
    expect(pi.MCP_TOOL_TIMEOUT).toBeUndefined();
    for (const key of secretKeys()) {
      expect(claude[key]).toBeUndefined();
      expect(pi[key]).toBeUndefined();
    }
  });

  test("cleanup removes the session home after the task", async () => {
    const plan = await buildSandboxPlan({
      config,
      kind: "pi",
      runId: "iso-cleanup",
      executable: "/bin/true",
      args: [],
      workspacePath: join(dir, "workspace"),
      harnessConfig: DEFAULT_HARNESS_CONFIG.pi,
      credentialEnv: {},
    });
    expect(existsSync(plan.home)).toBe(true);
    expect(plan.warnings.some((warning) => warning.includes("not namespace-isolated"))).toBe(true);
    plan.cleanup();
    expect(existsSync(plan.home)).toBe(false);
  });
});
