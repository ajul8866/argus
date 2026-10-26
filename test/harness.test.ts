import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { PiHarnessAdapter } from "../src/harness/pi.ts";
import { ClaudeCodeHarnessAdapter } from "../src/harness/claude.ts";
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
    prompt: "Return JSON", systemPrompt: "Test", workspace: join(dir, "workspace"), model: "test-model",
    allowedTools: [], timeoutMs,
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
