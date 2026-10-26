import { extractJson, now, truncate } from "../util.ts";
import type { Config } from "../config.ts";
import type {
  HarnessAdapter,
  HarnessConfig,
  HarnessDetection,
  HarnessEvent,
  HarnessRunResult,
  HarnessTask,
  HarnessUsage,
} from "./types.ts";
import { PI_CAPABILITIES, emptyUsage } from "./types.ts";
import { ActiveProcess, readJsonLines, runCommand, which } from "./process.ts";
import { baseHarnessEnv, buildSandboxPlan } from "./sandbox.ts";

type PiRun = {
  cancel: () => void;
  active: ActiveProcess;
};

type PiMessage = {
  role?: string;
  content?: Array<{ type?: string; text?: string }>;
  usage?: {
    input?: number;
    output?: number;
    totalTokens?: number;
    cacheRead?: number;
    cost?: { total?: number };
  };
  stopReason?: string;
  errorMessage?: string;
};

export class PiHarnessAdapter implements HarnessAdapter {
  readonly kind = "pi" as const;
  readonly label = "Pi Coding Agent";
  private detection: HarnessDetection | null = null;
  private detectedAt = 0;
  private readonly activeRuns = new Map<string, PiRun>();

  constructor(
    private readonly config: Config,
    private readonly harnessConfig: HarnessConfig,
    private readonly credentialEnv: Record<string, string>,
  ) {}

  capabilities() {
    return PI_CAPABILITIES;
  }

  async detect(force = false): Promise<HarnessDetection> {
    if (!force && this.detection && Date.now() - this.detectedAt < 30_000) return this.detection;
    const executable = (await which(this.harnessConfig.executable || this.config.piBin)) ?? null;
    if (!executable) {
      this.detection = {
        kind: this.kind,
        label: this.label,
        executable: this.harnessConfig.executable || this.config.piBin,
        version: null,
        status: "missing",
        detail: "Pi executable was not found on PATH.",
        auth: { ready: false, detail: "Executable missing" },
        capabilities: PI_CAPABILITIES,
        models: [],
      };
      this.detectedAt = Date.now();
      return this.detection;
    }
    const versionResult = await runCommand([executable, "--version"], {
      env: baseHarnessEnv("pi", this.harnessConfig.env),
      timeoutMs: 10_000,
    });
    const version = versionResult.code === 0 ? versionResult.stdout.trim().split("\n")[0] ?? null : null;
    const models = await this.listModels(executable);
    this.detection = {
      kind: this.kind,
      label: this.label,
      executable,
      version,
      status: "ready",
      detail: version ? `Pi ${version} detected.` : "Pi detected; version could not be read.",
      auth: { ready: false, detail: "Run a health check to verify provider authentication." },
      capabilities: PI_CAPABILITIES,
      models,
    };
    this.detectedAt = Date.now();
    return this.detection;
  }

  async health(force = false): Promise<HarnessDetection> {
    const detection = await this.detect(force);
    if (detection.status === "missing" || !detection.executable) return detection;
    const provider = this.harnessConfig.provider;
    const model = this.harnessConfig.model;
    if (!provider || !model) {
      return {
        ...detection,
        status: "unauthenticated",
        detail: "Select a Pi provider and model in Settings → Harnesses.",
        auth: { ready: false, detail: "No provider/model configured" },
      };
    }
    const result = await runCommand(
      [detection.executable, "auth", "check", "--provider", provider, "--model", model, "--json", "--no-refresh"],
      {
        env: baseHarnessEnv("pi", { ...this.harnessConfig.env, ...this.credentialEnv }),
        timeoutMs: 25_000,
      },
    );
    let status: HarnessDetection["status"] = "error";
    let detail = result.stderr.trim() || result.stdout.trim() || "Pi auth check failed";
    let ready = false;
    try {
      const parsed = JSON.parse(result.stdout) as { status?: string; authType?: string; error?: string };
      ready = parsed.status === "ready";
      status = ready ? "ready" : "unauthenticated";
      detail = ready
        ? `Provider ${provider} is authenticated (${parsed.authType ?? "credential"}).`
        : parsed.error ?? "Provider credentials are not ready.";
    } catch {
      status = result.code === 0 ? "unauthenticated" : "error";
    }
    const updated: HarnessDetection = {
      ...detection,
      status,
      detail,
      auth: { ready, detail },
    };
    this.detection = updated;
    this.detectedAt = Date.now();
    return updated;
  }

  private async listModels(executable: string): Promise<Array<{ id: string; label: string }>> {
    const result = await runCommand([executable, "--list-models"], {
      env: baseHarnessEnv("pi", this.harnessConfig.env),
      timeoutMs: 20_000,
    });
    if (result.code !== 0) return [];
    const models: Array<{ id: string; label: string }> = [];
    for (const line of result.stdout.split("\n").slice(1)) {
      const match = line.trim().match(/^(\S+)\s+(\S+)\s+(.+)$/);
      if (!match) continue;
      const id = `${match[1]}/${match[2]}`;
      models.push({ id, label: `${id} — ${match[3]!.trim()}` });
      if (models.length >= 300) break;
    }
    return models;
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
    const executable = await which(this.harnessConfig.executable || this.config.piBin);
    if (!executable) {
      return this.failure(startedAt, "harness_missing", "Pi executable not found", usage, events, null);
    }
    if (hooks.signal?.aborted) {
      return this.result(
        "cancelled", "", undefined, null, task, usage, events, startedAt, now(),
        null, "Run was cancelled before launch", "cancelled", this.config.sandboxMode,
      );
    }
    if (!this.harnessConfig.provider || !this.harnessConfig.model) {
      return this.failure(
        startedAt,
        "harness_auth",
        "Pi provider/model is not configured. Configure it in Settings → Harnesses.",
        usage,
        events,
        null,
      );
    }

    const args = [
      "--mode",
      "rpc",
      ...(task.resumeSessionRef ? [] : ["--no-session"]),
      ...(task.resources?.servers.length ? ["--no-extensions", "--extension", "builtin:mcp"] : ["--no-extensions", "--no-mcp"]),
      "--no-skills",
      "--no-context-files",
      "--no-prompt-templates",
      "--no-approve",
      "--provider",
      this.harnessConfig.provider,
      "--model",
      task.model || this.harnessConfig.model,
      "--append-system-prompt",
      task.systemPrompt,
    ];
    const tools = [
      ...task.allowedTools,
      ...(task.resources?.servers ?? []).map((server) => `mcp__${server.key}__*`),
    ];
    args.push("--no-builtin-tools");
    if (tools.length > 0) args.push("--tools", tools.join(","));
    if (task.resumeSessionRef) {
      args.push("--resume", task.resumeSessionRef);
    }
    if (this.harnessConfig.extra_args.length > 0) args.push(...this.harnessConfig.extra_args);

    const plan = await buildSandboxPlan({
      config: this.config,
      kind: "pi",
      runId: task.runId,
      executable,
      args,
      workspacePath: task.workspace,
      harnessConfig: { ...this.harnessConfig, model: task.model || this.harnessConfig.model },
      credentialEnv: this.credentialEnv,
      resources: task.resources,
      workspaceWritable: task.workspaceWritable === true,
    });

    let proc: ReturnType<typeof Bun.spawn>;
    try {
      proc = Bun.spawn(plan.command, {
        cwd: plan.cwd,
        env: plan.env,
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      });
    } catch (error) {
      plan.cleanup();
      return this.failure(startedAt, "harness_error", `Failed to start Pi: ${String(error)}`, usage, events, null);
    }
    const active = new ActiveProcess();
    active.attach(proc);
    const stdin = proc.stdin as { write(data: string): unknown; flush(): Promise<number>; end(): void } | undefined;
    const stdoutStream = proc.stdout as ReadableStream<Uint8Array>;
    const stderrStream = proc.stderr as ReadableStream<Uint8Array>;
    emit({
      type: "session_start",
      meta: {
        harness: "pi",
        executable,
        model: task.model || this.harnessConfig.model,
        sandbox: plan.mode,
        warnings: plan.warnings,
        pid: proc.pid,
      },
    });

    let settled = false;
    let agentSettled = false;
    let timedOut = false;
    let cancelled = false;
    let rpcError: string | null = null;
    let finalText = "";
    let lastText = "";
    let sessionRef: string | null = null;
    let settleResolve: (() => void) | null = null;
    const settledPromise = new Promise<void>((resolvePromise) => {
      settleResolve = resolvePromise;
    });
    const finish = () => {
      if (settled) return;
      settled = true;
      settleResolve?.();
    };

    const send = async (record: Record<string, unknown>): Promise<void> => {
      if (!stdin) throw new Error("Pi stdin is closed");
      stdin.write(`${JSON.stringify(record)}\n`);
      await stdin.flush();
    };

    const cancelRun = (reason: "cancelled" | "timeout" = "cancelled") => {
      if (cancelled || timedOut) return;
      if (reason === "timeout") timedOut = true;
      else cancelled = true;
      void send({ type: "abort" }).catch(() => undefined);
      setTimeout(() => {
        void active.terminate("SIGTERM", 1_500);
        finish();
      }, 1_200);
    };
    this.activeRuns.set(task.runId, { cancel: cancelRun, active });

    const onAbort = () => cancelRun();
    hooks.signal?.addEventListener("abort", onAbort, { once: true });
    if (hooks.signal?.aborted) onAbort();

    const timer = setTimeout(() => cancelRun("timeout"), task.timeoutMs);

    const stderrChunks: string[] = [];
    const stderrPromise = (async () => {
      if (!stderrStream) return;
      const reader = stderrStream.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const text = decoder.decode(value, { stream: true });
        stderrChunks.push(text);
        if (stderrChunks.join("").length > 16_000) stderrChunks.shift();
      }
    })();

    const stdoutPromise = readJsonLines(stdoutStream, (line) => {
      let record: Record<string, unknown>;
      try {
        record = JSON.parse(line) as Record<string, unknown>;
      } catch {
        emit({ type: "log", text: truncate(line, 1_000), meta: { stream: "stdout-non-json" } });
        return;
      }
      const type = String(record.type ?? "");
      if (type === "response") {
        if (record.success === false) {
          rpcError = String(record.error ?? "Pi command failed");
          if (record.command === "prompt") finish();
        }
        const data = record.data as Record<string, unknown> | undefined;
        if (record.command === "get_state" && data?.sessionId) sessionRef = String(data.sessionId);
        if (record.command === "prompt" && data?.disposition === "handled") {
          rpcError = "Pi reported that the prompt was handled without starting a run.";
          finish();
        }
        return;
      }
      if (type === "agent_start") {
        emit({ type: "log", text: "Pi agent run started", meta: { event: type } });
        return;
      }
      if (type === "message_update") {
        const update = record.assistantMessageEvent as Record<string, unknown> | undefined;
        if (update?.type === "text_delta" && typeof update.delta === "string") {
          lastText += update.delta;
          emit({ type: "text_delta", text: update.delta });
        } else if (update?.type === "thinking_delta" && typeof update.delta === "string") {
          emit({ type: "thinking_delta", text: update.delta });
        } else if (update?.type === "error") {
          rpcError = String(update.error ?? update.reason ?? "Pi provider stream error");
          emit({ type: "error", text: rpcError });
        }
        return;
      }
      if (type === "message_end") {
        const message = record.message as PiMessage | undefined;
        if (message?.role !== "assistant") return;
        usage.turns = (usage.turns ?? 0) + 1;
        const text = (message.content ?? [])
          .filter((block) => block.type === "text")
          .map((block) => block.text ?? "")
          .join("");
        if (text) finalText = text;
        if (message.usage) {
          usage.input_tokens += message.usage.input ?? 0;
          usage.output_tokens += message.usage.output ?? 0;
          usage.total_tokens += message.usage.totalTokens ?? 0;
          usage.cache_read_tokens += message.usage.cacheRead ?? 0;
          usage.cost_usd += message.usage.cost?.total ?? 0;
          emit({ type: "usage", usage: { ...usage } });
        }
        if (message.stopReason === "error" && message.errorMessage) {
          rpcError = message.errorMessage;
          emit({ type: "error", text: message.errorMessage });
        }
        return;
      }
      if (type === "tool_execution_start") {
        emit({
          type: "tool_start",
          toolName: String(record.toolName ?? "tool"),
          toolCallId: String(record.toolCallId ?? ""),
          input: record.args,
        });
        return;
      }
      if (type === "tool_execution_end") {
        const result = record.result as { content?: Array<{ text?: string }> } | undefined;
        const output = (result?.content ?? []).map((entry) => entry.text ?? "").join("\n");
        emit({
          type: "tool_end",
          toolName: String(record.toolName ?? "tool"),
          toolCallId: String(record.toolCallId ?? ""),
          output: truncate(output, 4_000),
          isError: Boolean(record.isError),
        });
        return;
      }
      if (type === "agent_end" && record.willRetry === false) {
        emit({ type: "log", text: "Pi agent_end received; waiting for agent_settled", meta: { event: type } });
        return;
      }
      if (type === "agent_settled") {
        agentSettled = true;
        if (record.aborted === true && !timedOut) cancelled = true;
        finish();
        return;
      }
      if (type === "auto_retry_start") {
        emit({ type: "log", text: `Pi retry ${String(record.attempt ?? "?")}/${String(record.maxAttempts ?? "?")}` });
        return;
      }
      if (type === "auto_retry_end" && record.success === false) {
        rpcError = String(record.finalError ?? "Pi retries exhausted");
        return;
      }
      if (type === "extension_ui_request") {
        void send({ type: "extension_ui_response", id: record.id, cancelled: true }).catch(() => undefined);
        return;
      }
      if (type === "compaction_start" || type === "compaction_end" || type === "turn_start" || type === "turn_end") {
        emit({ type: "log", text: `Pi ${type}`, meta: { event: type } });
      }
    })
      .catch((error) => {
        rpcError = rpcError ?? `Pi stdout reader failed: ${String(error)}`;
      })
      .finally(() => finish());

    try {
      await send({ id: "state", type: "get_state" });
      await send({ id: "prompt", type: "prompt", message: task.prompt });
    } catch (error) {
      rpcError = rpcError ?? `Could not submit prompt to Pi: ${String(error)}`;
      finish();
    }

    await Promise.race([settledPromise, proc.exited.then(() => undefined)]);
    clearTimeout(timer);
    hooks.signal?.removeEventListener("abort", onAbort);
    try {
      stdin?.end();
    } catch {
      // already closed
    }
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
      meta: {
        exitCode,
        sandbox: plan.mode,
        stderr: stderr || undefined,
        cancelled,
        timedOut,
      },
    });

    if (cancelled) {
      return this.result("cancelled", finalText, undefined, sessionRef, task, usage, events, startedAt, endedAt, exitCode, "Run was cancelled", "cancelled", plan.mode);
    }
    if (timedOut) {
      return this.result("timeout", finalText, undefined, sessionRef, task, usage, events, startedAt, endedAt, exitCode, `Timed out after ${task.timeoutMs}ms`, "timeout", plan.mode);
    }
    if (rpcError && !finalText) {
      return this.result("failed", finalText, undefined, sessionRef, task, usage, events, startedAt, endedAt, exitCode, rpcError, "agent_error", plan.mode);
    }
    if (!finalText.trim()) {
      const error = rpcError ?? `Pi exited without a final assistant message${stderr ? `: ${truncate(stderr, 1_500)}` : ""}`;
      return this.result("failed", finalText, undefined, sessionRef, task, usage, events, startedAt, endedAt, exitCode, error, "agent_error", plan.mode);
    }
    if (!agentSettled || exitCode !== 0) {
      return this.result(
        "failed",
        finalText,
        extractJson(finalText) ?? undefined,
        sessionRef,
        task,
        usage,
        events,
        startedAt,
        endedAt,
        exitCode,
        `${!agentSettled ? "Pi exited without an agent_settled record" : `Pi exited with code ${exitCode}`}${stderr ? `: ${truncate(stderr, 1_500)}` : ""}`,
        "harness_error",
        plan.mode,
      );
    }
    return this.result(
      "completed",
      finalText,
      extractJson(finalText) ?? undefined,
      sessionRef,
      task,
      usage,
      events,
      startedAt,
      endedAt,
      exitCode,
      undefined,
      undefined,
      plan.mode,
    );
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
      metadata: { harness: "pi" },
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
      metadata: { harness: "pi", sandbox },
    };
  }
}
