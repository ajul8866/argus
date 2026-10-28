import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { now, parseJson, toJson } from "../util.ts";
import { credentialEnvironment, type StoredCredential } from "../security/credentials.ts";
import { ClaudeCodeHarnessAdapter } from "./claude.ts";
import { PiHarnessAdapter } from "./pi.ts";
import { harnessConfig, storedCredentials } from "../settings.ts";
import { redactSecrets } from "../security/redact.ts";
import type {
  HarnessAdapter,
  HarnessDetection,
  HarnessEvent,
  HarnessKind,
  HarnessRunResult,
  HarnessTask,
} from "./types.ts";

export class HarnessManager {
  private adapters = new Map<HarnessKind, { adapter: HarnessAdapter; configHash: string }>();
  private runKinds = new Map<string, HarnessKind>();

  constructor(
    private readonly config: Config,
    private readonly store: Store,
  ) {}

  adapter(kind: HarnessKind): HarnessAdapter {
    const config = harnessConfig(this.store, kind);
    const credentials = storedCredentials(this.store).filter(
      (credential: StoredCredential) =>
        !config.provider || credential.provider === config.provider || credential.provider === "global",
    );
    const env = credentialEnvironment(this.config, credentials, config.provider ?? undefined);
    const hash = JSON.stringify({ config, envKeys: Object.keys(env).sort() });
    const cached = this.adapters.get(kind);
    if (cached && cached.configHash === hash) return cached.adapter;
    const adapter =
      kind === "pi"
        ? new PiHarnessAdapter(this.config, config, env)
        : new ClaudeCodeHarnessAdapter(this.config, config, env);
    this.adapters.set(kind, { adapter, configHash: hash });
    return adapter;
  }

  invalidate(kind?: HarnessKind): void {
    if (kind) this.adapters.delete(kind);
    else this.adapters.clear();
  }

  async detectAll(force = false): Promise<HarnessDetection[]> {
    const results = await Promise.allSettled([
      this.adapter("pi").detect(force),
      this.adapter("claude-code").detect(force),
    ]);
    const detections: HarnessDetection[] = [];
    for (const result of results) {
      if (result.status === "fulfilled") {
        const detection = this.redactDetection(result.value);
        detections.push(detection);
        this.persist(detection);
      }
    }
    return detections;
  }

  async health(kind: HarnessKind, force = true): Promise<HarnessDetection> {
    const detection = this.redactDetection(await this.adapter(kind).health(force));
    this.persist(detection);
    return detection;
  }

  async testConnection(kind: HarnessKind): Promise<{ detection: HarnessDetection; result: HarnessRunResult | null }> {
    const detection = await this.adapter(kind).health(true);
    if (detection.status !== "ready") return { detection, result: null };
    const adapter = this.adapter(kind);
    const config = harnessConfig(this.store, kind);
    const runId = crypto.randomUUID();
    const workspace = join(this.config.dataDir, "workspaces", "harness-check", runId);
    await mkdir(workspace, { recursive: true, mode: 0o700 });
    const task: HarnessTask = {
      runId,
      auditId: "harness-test",
      taskId: "harness-test",
      role: "connectivity_test",
      prompt:
        'Return JSON with {"ok":true,"harness":"<pi|claude-code>","message":"connected"}. No other text.',
      systemPrompt:
        "You are executing a connectivity self-test for Argus. Do not use tools. Return only the requested JSON.",
      workspace,
      model: config.model,
      provider: config.provider,
      timeoutMs: 90_000,
      schema: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          harness: { type: "string" },
          message: { type: "string" },
        },
        required: ["ok", "harness", "message"],
        additionalProperties: false,
      },
    };
    try {
      await writeFile(join(workspace, "connection.txt"), "Argus harness connectivity check\n", { mode: 0o600 });
      let text = "";
      const result = await adapter.run(task, {
        onEvent: (event: HarnessEvent) => {
          if (event.type === "text_delta" && event.text) text += event.text;
        },
      });
      if (!result.structured) {
        const raw = text.trim();
        if (raw) {
          try {
            result.structured = JSON.parse(raw);
          } catch {
            // leave unset; caller reports the failure
          }
        }
      }
      return { detection, result };
    } finally {
      await adapter.cleanup(runId);
      await rm(workspace, { recursive: true, force: true });
    }
  }

  async run(
    kind: HarnessKind,
    task: HarnessTask,
    hooks: { onEvent: (event: HarnessEvent) => void; signal?: AbortSignal },
  ): Promise<HarnessRunResult> {
    this.runKinds.set(task.runId, kind);
    try {
      return await this.adapter(kind).run(task, hooks);
    } finally {
      this.runKinds.delete(task.runId);
    }
  }

  cancel(runId: string): boolean {
    const kind = this.runKinds.get(runId);
    if (!kind) {
      return this.adapter("pi").cancel(runId) || this.adapter("claude-code").cancel(runId);
    }
    return this.adapter(kind).cancel(runId);
  }

  async cleanupRun(runId: string): Promise<void> {
    await Promise.allSettled([
      this.adapter("pi").cleanup(runId),
      this.adapter("claude-code").cleanup(runId),
    ]);
    this.runKinds.delete(runId);
  }

  private persist(detection: HarnessDetection): void {
    const existing = this.store.get<{ id: string }>("SELECT id FROM harnesses WHERE kind = ?", detection.kind);
    if (existing) {
      this.store.run(
        `UPDATE harnesses SET executable = ?, version = ?, status = ?, detail = ?, capabilities = ?, detected_at = ?, updated_at = ?
         WHERE kind = ?`,
        detection.executable,
        detection.version,
        detection.status,
        detection.detail,
        toJson(detection.capabilities),
        now(),
        now(),
        detection.kind,
      );
    } else {
      this.store.run(
        `INSERT INTO harnesses (id, kind, label, executable, version, status, detail, capabilities, config, detected_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        detection.kind,
        detection.kind,
        detection.label,
        detection.executable,
        detection.version,
        detection.status,
        detection.detail,
        toJson(detection.capabilities),
        toJson({}),
        now(),
        now(),
      );
    }
  }

  private redactDetection(detection: HarnessDetection): HarnessDetection {
    return {
      ...detection,
      detail: redactSecrets(detection.detail).text,
      auth: {
        ...detection.auth,
        detail: redactSecrets(detection.auth.detail).text,
      },
    };
  }

  harnessRow(kind: HarnessKind): Record<string, unknown> | null {
    return this.store.get("SELECT * FROM harnesses WHERE kind = ?", kind);
  }

  detections(): HarnessDetection[] {
    const kinds: HarnessKind[] = ["pi", "claude-code"];
    return kinds.map((kind) => {
      const row = this.harnessRow(kind);
      const detail = redactSecrets(String(row?.detail ?? "Not checked yet")).text;
      return {
        kind,
        label: kind === "pi" ? "Pi Coding Agent" : "Claude Code",
        executable: String(row?.executable ?? ""),
        version: row?.version ? String(row.version) : null,
        status: (row?.status as HarnessDetection["status"]) ?? "unknown",
        detail,
        auth: { ready: row?.status === "ready", detail },
        capabilities:
          (row?.capabilities ? parseJson<HarnessDetection["capabilities"]>(String(row.capabilities), {} as never) : ({} as never)),
        models: [],
      };
    });
  }
}
