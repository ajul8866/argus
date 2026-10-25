import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { extractJson, now, truncate } from "../util.ts";
import { ActiveProcess, readJsonLines, runCommand, which } from "./process.ts";
import { baseHarnessEnv, buildSandboxPlan } from "./sandbox.ts";
import { sessionMcpConfigPath } from "./resources.ts";
import type {
  HarnessAdapter,
  HarnessConfig,
  HarnessDetection,
  HarnessEvent,
  HarnessRunResult,
  HarnessTask,
  HarnessUsage,
} from "./types.ts";
import { CLAUDE_CAPABILITIES, emptyUsage } from "./types.ts";

type ClaudeRun = { cancel: () => void; active: ActiveProcess };

type ClaudeContentBlock = {
  type?: string;
  text?: string;
  thinking?: string;
  id?: string;
  name?: string;
  input?: unknown;
  tool_use_id?: string;
  content?: unknown;
  is_error?: boolean;
};

type ClaudeMessage = { role?: string; content?: ClaudeContentBlock[]; model?: string };

export class ClaudeCodeHarnessAdapter implements HarnessAdapter {
  readonly kind = "claude-code" as const;
  readonly label = "Claude Code";
  private detection: HarnessDetection | null = null;
  private detectedAt = 0;
  private readonly activeRuns = new Map<string, ClaudeRun>();

  constructor(
    private readonly config: Config,
    private readonly harnessConfig: HarnessConfig,
    private readonly credentialEnv: Record<string, string>,
  ) {}

  capabilities() {
    return CLAUDE_CAPABILITIES;
  }

  async detect(force = false): Promise<HarnessDetection> {
    if (!force && this.detection && Date.now() - this.detectedAt < 30_000) return this.detection;
    const executable = (await which(this.harnessConfig.executable || this.config.claudeBin)) ?? null;
    if (!executable) {
      this.detection = {
        kind: this.kind,
        label: this.label,
        executable: this.harnessConfig.executable || this.config.claudeBin,
        version: null,
        status: "missing",
        detail: "Claude Code executable was not found on PATH.",
        auth: { ready: false, detail: "Executable missing" },
        capabilities: CLAUDE_CAPABILITIES,
        models: [],
      };
      this.detectedAt = Date.now();
      return this.detection;
    }
    const versionResult = await runCommand([executable, "--version"], {
      env: baseHarnessEnv("claude-code", this.harnessConfig.env),
      timeoutMs: 15_000,
    });
    const rawVersion = versionResult.stdout.trim() || versionResult.stderr.trim();
    const version = rawVersion.replace(/^Claude Code\s*/i, "").split("\n")[0] || null;
    this.detection = {
      kind: this.kind,
      label: this.label,
      executable,
      version,
      status: "ready",
      detail: version ? `Claude Code ${version} detected.` : "Claude Code detected; version could not be read.",
      auth: { ready: false, detail: "Run a health check to verify authentication." },
      capabilities: CLAUDE_CAPABILITIES,
      models: this.listModels(),
    };
    this.detectedAt = Date.now();
    return this.detection;
  }

  async health(force = false): Promise<HarnessDetection> {
    const detection = await this.detect(force);
    if (detection.status === "missing") return detection;
    const result = await runCommand(
      [
        detection.executable,
        "-p",
        "Reply with JSON only. This is an Argus harness health check.",
        "--output-format",
        "json",
        "--permission-mode",
        "plan",
        "--permission-prompts",
        "none",
        "--allowedTools",
        "Read",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--json-schema",
        JSON.stringify({
          type: "object",
          properties: { ok: { type: "boolean" } },
          required: ["ok"],
          additionalProperties: false,
        }),
      ],
      {
        env: baseHarnessEnv("claude-code", { ...this.harnessConfig.env, ...this.credentialEnv }),
        timeoutMs: 120_000,
      },
    );
    let ready = false;
    let detail = result.stderr.trim() || "Claude Code health check failed";
    try {
      const parsed = JSON.parse(result.stdout) as {
        is_error?: boolean;
        subtype?: string;
        structured_output?: { ok?: boolean };
        result?: string;
        total_cost_usd?: number;
      };
      ready = result.code === 0 && parsed.is_error !== true;
      detail = ready
        ? `Claude Code authentication and structured output verified${parsed.total_cost_usd ? ` ($${parsed.total_cost_usd.toFixed(4)} test call)` : ""}.`
        : parsed.result ?? detail;
    } catch {
      ready = false;
      detail = result.timedOut ? "Claude Code health check timed out" : detail;
    }
    const updated: HarnessDetection = {
      ...detection,
      status: ready ? "ready" : "unauthenticated",
      detail,
      auth: { ready, detail },
    };
    this.detection = updated;
    this.detectedAt = Date.now();
    return updated;
  }

  private listModels(): Array<{ id: string; label: string }> {
    const models = new Map<string, string>();
    for (const alias of ["fable", "opus", "sonnet", "haiku"]) models.set(alias, alias);
    const settingsPath = join(process.env.HOME ?? "/root", ".claude", "settings.json");
    if (existsSync(settingsPath)) {
      try {
        const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as {
          modelPicker?: { options?: Array<{ model?: string; label?: string }> };
        };
        for (const option of settings.modelPicker?.options ?? []) {
          if (option.model) models.set(option.model, option.label ? `${option.model} — ${option.label}` : option.model);
        }
      } catch {
        // malformed settings are reported by the health check
      }
    }
    return [...models.entries()].map(([id, label]) => ({ id, label })).slice(0, 200);
  }

  cancel(runId: string): boolean {
    const run = this.activeRuns.get(runId);
    if (!run) return false;
    run.cancel();
    return true;
  }

  async cleanup(runId: string): Promise<void> {
    const run = this.activeRuns.get(runId);
    if (!run) return;
    await run.active.terminate("SIGTERM", 2_000);
    this.activeRuns.delete(runId);
  }

  async run(task: HarnessTask, hooks: { onEvent: (event: HarnessEvent) => void; signal?: AbortSignal }): Promise<HarnessRunResult> {
    const startedAt = now();
    const usage = emptyUsage();
    const events: HarnessEvent[] = [];
    const emit = (event: Omit<HarnessEvent, "at">) => {
      const full: HarnessEvent = { ...event, at: now() };
      events.push(full);
      hooks.onEvent(full);
    };
    const executable = await which(this.harnessConfig.executable || this.config.claudeBin);
    if (!executable) {
      return this.failure(startedAt, "harness_missing", "Claude Code executable not found", usage, events, null);
    }

    const sessionId = task.resumeSessionRef ?? randomUUID();
    const args = [
      "-p",
      task.prompt,
      "--output-format",
      "stream-json",
      "--verbose",
      "--permission-mode",
      this.harnessConfig.permission_mode || "plan",
      "--permission-prompts",
      "none",
      "--strict-mcp-config",
      "--mcp-config",
      sessionMcpConfigPath(this.config, "claude-code", task.runId),
      "--disable-slash-commands",
      "--append-system-prompt",
      task.systemPrompt,
    ];
    if (task.resumeSessionRef) args.push("--resume", task.resumeSessionRef);
    else args.push("--session-id", sessionId);
    if (task.model) args.push("--model", task.model);
    else if (this.harnessConfig.model) args.push("--model", this.harnessConfig.model);
    if (task.schema) args.push("--json-schema", JSON.stringify(task.schema));
    if (task.maxBudgetUsd && task.maxBudgetUsd > 0) args.push("--max-budget-usd", String(task.maxBudgetUsd));
    const tools = [
      ...(task.allowedTools.length > 0 ? task.allowedTools : this.harnessConfig.allowed_tools),
      ...(task.resources?.servers ?? []).map((server) => `mcp__${server.key}__*`),
    ];
    if (tools.length > 0) args.push("--allowedTools", tools.join(","));
    const disallowed = ["Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"].filter(
      (tool) => !tools.some((allowed) => allowed === tool || allowed.startsWith(`${tool}(`)),
    );
    if (disallowed.length > 0) args.push("--disallowedTools", disallowed.join(","));
    if (this.harnessConfig.extra_args.length > 0) args.push(...this.harnessConfig.extra_args);

    const plan = await buildSandboxPlan({
      config: this.config,
      kind: "claude-code",
      runId: task.runId,
      executable,
      args,
      workspacePath: task.workspace,
      harnessConfig: this.harnessConfig,
      credentialEnv: this.credentialEnv,
      resources: task.resources,
    });

    let proc: ReturnType<typeof Bun.spawn>;
    try {
      proc = Bun.spawn(plan.command, {
        cwd: plan.cwd,
        env: plan.env,
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
      });
    } catch (error) {
      plan.cleanup();
      return this.failure(startedAt, "harness_error", `Failed to start Claude Code: ${String(error)}`, usage, events, null);
    }
    const active = new ActiveProcess();
    active.attach(proc);
    const stdoutStream = proc.stdout as ReadableStream<Uint8Array>;
    const stderrStream = proc.stderr as ReadableStream<Uint8Array>;
    emit({
      type: "session_start",
      meta: {
        harness: "claude-code",
        executable,
        model: task.model || this.harnessConfig.model,
        sandbox: plan.mode,
        warnings: plan.warnings,
        pid: proc.pid,
        session_id: sessionId,
      },
    });

    let settled = false;
    let timedOut = false;
    let cancelled = false;
    let resultError: string | null = null;
    let finalText = "";
    let assistantText = "";
    let structured: unknown = null;
    let sessionRef: string | null = sessionId;
    let resultReceived = false;
    let settleResolve: (() => void) | null = null;
    const settledPromise = new Promise<void>((resolvePromise) => {
      settleResolve = resolvePromise;
    });
    const finish = () => {
      if (settled) return;
      settled = true;
      settleResolve?.();
    };

    const cancelRun = () => {
      if (cancelled) return;
      cancelled = true;
      void active.terminate("SIGTERM", 1_500);
      setTimeout(() => finish(), 1_800);
    };
    this.activeRuns.set(task.runId, { cancel: cancelRun, active });
    const onAbort = () => cancelRun();
    hooks.signal?.addEventListener("abort", onAbort, { once: true });

    const timer = setTimeout(() => {
      timedOut = true;
      cancelRun();
    }, task.timeoutMs);

    const stderrChunks: string[] = [];
    const stderrPromise = (async () => {
      if (!stderrStream) return;
      const reader = stderrStream.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        stderrChunks.push(decoder.decode(value, { stream: true }));
        if (stderrChunks.join("").length > 16_000) stderrChunks.shift();
      }
    })();

    const toolNames = new Map<string, string>();
    const stdoutPromise = readJsonLines(stdoutStream, (line) => {
      let record: Record<string, unknown>;
      try {
        record = JSON.parse(line) as Record<string, unknown>;
      } catch {
        emit({ type: "log", text: truncate(line, 1_000), meta: { stream: "stdout-non-json" } });
        return;
      }
      const type = String(record.type ?? "");
      if (type === "system") {
        if (record.session_id) sessionRef = String(record.session_id);
        if (record.subtype === "init") {
          emit({ type: "log", text: "Claude Code session initialized", meta: { session_id: sessionRef } });
        }
        return;
      }
      if (type === "assistant") {
        const message = record.message as ClaudeMessage | undefined;
        for (const block of message?.content ?? []) {
          if (block.type === "text" && block.text) {
            assistantText += block.text;
            emit({ type: "text_delta", text: block.text });
          } else if (block.type === "thinking" && block.thinking) {
            emit({ type: "thinking_delta", text: block.thinking });
          } else if (block.type === "tool_use") {
            const toolId = String(block.id ?? "");
            toolNames.set(toolId, String(block.name ?? "tool"));
            emit({
              type: "tool_start",
              toolName: String(block.name ?? "tool"),
              toolCallId: toolId,
              input: block.input,
            });
          }
        }
        return;
      }
      if (type === "user") {
        const message = record.message as ClaudeMessage | undefined;
        for (const block of message?.content ?? []) {
          if (block.type !== "tool_result") continue;
          const toolId = String(block.tool_use_id ?? "");
          let output = "";
          if (typeof block.content === "string") output = block.content;
          else if (Array.isArray(block.content)) {
            output = block.content
              .map((entry) => (entry && typeof entry === "object" && "text" in entry ? String(entry.text ?? "") : ""))
              .join("\n");
          }
          emit({
            type: "tool_end",
            toolName: toolNames.get(toolId) ?? "tool",
            toolCallId: toolId,
            output: truncate(output, 4_000),
            isError: Boolean(block.is_error),
          });
        }
        return;
      }
      if (type === "result") {
        resultReceived = true;
        if (record.session_id) sessionRef = String(record.session_id);
        const usageRecord = record.usage as Record<string, unknown> | undefined;
        if (usageRecord) {
          usage.input_tokens = Number(usageRecord.input_tokens ?? 0);
          usage.output_tokens = Number(usageRecord.output_tokens ?? 0);
          usage.cache_read_tokens = Number(usageRecord.cache_read_input_tokens ?? 0);
          usage.total_tokens = usage.input_tokens + usage.output_tokens;
          usage.cost_usd = Number(record.total_cost_usd ?? 0);
          emit({ type: "usage", usage: { ...usage } });
        }
        if (typeof record.result === "string" && record.result.length > 0) finalText = record.result;
        if (record.structured_output !== undefined) structured = record.structured_output;
        const denials = record.permission_denials as unknown[] | undefined;
        if (denials && denials.length > 0) {
          emit({
            type: "log",
            text: `${denials.length} tool permission request(s) were denied by policy`,
            meta: { permission_denials: denials },
          });
        }
        if (record.is_error === true || record.subtype === "error") {
          resultError = String(record.result ?? record.subtype ?? "Claude Code returned an error result");
          emit({ type: "error", text: resultError });
        }
        finish();
        return;
      }
      if (type === "error") {
        resultError = String(record.error ?? record.message ?? "Claude Code stream error");
        emit({ type: "error", text: resultError });
        return;
      }
      if (type === "rate_limit_event") {
        emit({ type: "log", text: "Claude Code rate-limit notification", meta: { event: record } });
        return;
      }
      if (type === "stream_event") {
        const event = record.event as Record<string, unknown> | undefined;
        if (event?.type === "content_block_delta") {
          const delta = event.delta as Record<string, unknown> | undefined;
          if (delta?.type === "text_delta" && typeof delta.text === "string") {
            emit({ type: "text_delta", text: delta.text });
          }
        }
      }
    })
      .catch((error) => {
        resultError = resultError ?? `Claude Code stdout reader failed: ${String(error)}`;
      })
      .finally(() => finish());

    await Promise.race([settledPromise, proc.exited.then(() => undefined)]);
    clearTimeout(timer);
    hooks.signal?.removeEventListener("abort", onAbort);
    await Promise.race([proc.exited, new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000))]);
    await active.terminate("SIGTERM", 1_500);
    await Promise.race([stdoutPromise, new Promise((resolvePromise) => setTimeout(resolvePromise, 1_500))]);
    await stderrPromise.catch(() => undefined);
    this.activeRuns.delete(task.runId);
    plan.cleanup();

    const exitCode = await Promise.race([
      proc.exited,
      new Promise<number>((resolvePromise) => setTimeout(() => resolvePromise(-1), 1_000)),
    ]);
    const durationMs = Date.now() - new Date(startedAt).getTime();
    usage.duration_ms = durationMs;
    const stderr = truncate(stderrChunks.join(""), 6_000);
    const endedAt = now();
    emit({
      type: "session_end",
      meta: { exitCode, sandbox: plan.mode, stderr: stderr || undefined, cancelled, timedOut, session_id: sessionRef },
    });

    if (cancelled) {
      return this.result("cancelled", finalText || assistantText, structured, sessionRef, task, usage, events, startedAt, endedAt, exitCode, "Run was cancelled", "cancelled", plan.mode);
    }
    if (timedOut) {
      return this.result("timeout", finalText || assistantText, structured, sessionRef, task, usage, events, startedAt, endedAt, exitCode, `Timed out after ${task.timeoutMs}ms`, "timeout", plan.mode);
    }
    if (resultError) {
      return this.result("failed", finalText || assistantText, structured, sessionRef, task, usage, events, startedAt, endedAt, exitCode, resultError, "agent_error", plan.mode);
    }
    if (!resultReceived) {
      const error = `Claude Code exited without a result record${stderr ? `: ${truncate(stderr, 1_500)}` : ""}`;
      return this.result("failed", finalText || assistantText, structured, sessionRef, task, usage, events, startedAt, endedAt, exitCode, error, "harness_error", plan.mode);
    }
    if (exitCode !== 0 && exitCode !== null) {
      return this.result("failed", finalText || assistantText, structured, sessionRef, task, usage, events, startedAt, endedAt, exitCode, `Claude Code exited with code ${exitCode}`, "harness_error", plan.mode);
    }
    if (!structured) structured = extractJson(finalText) ?? undefined;
    return this.result("completed", finalText || assistantText, structured, sessionRef, task, usage, events, startedAt, endedAt, exitCode, undefined, undefined, plan.mode);
  }

  private failure(
    startedAt: string,
    failureKind: HarnessRunResult["failureKind"],
    error: string,
    usage: HarnessUsage,
    events: HarnessEvent[],
    sessionRef: string | null,
  ): HarnessRunResult {
    return {
      status: "failed",
      text: "",
      sessionRef,
      model: this.harnessConfig.model,
      usage,
      events,
      startedAt,
      endedAt: now(),
      exitCode: null,
      error,
      failureKind,
      metadata: { harness: "claude-code" },
    };
  }

  private result(
    status: HarnessRunResult["status"],
    text: string,
    structured: unknown,
    sessionRef: string | null,
    task: HarnessTask,
    usage: HarnessUsage,
    events: HarnessEvent[],
    startedAt: string,
    endedAt: string,
    exitCode: number | null,
    error: string | undefined,
    failureKind: HarnessRunResult["failureKind"] | undefined,
    sandbox: string,
  ): HarnessRunResult {
    return {
      status,
      text,
      structured,
      sessionRef,
      model: task.model || this.harnessConfig.model,
      usage,
      events,
      startedAt,
      endedAt,
      exitCode,
      error,
      failureKind,
      metadata: { harness: "claude-code", sandbox },
    };
  }
}
