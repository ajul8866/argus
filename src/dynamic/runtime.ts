import { which } from "../harness/process.ts";

export type RuntimeKind = "docker" | "podman";

export type CommandResult = { code: number; stdout: string; stderr: string };
export type CommandExecutor = (argv: string[]) => Promise<CommandResult>;

export type RuntimePlan = {
  kind: RuntimeKind;
  /** Holds the worker and the broker; no route to the outside world. */
  network: string;
  /** Egress network the broker is attached to so it can reach the target. */
  egressNetwork: string;
  workerName: string;
  brokerName: string;
  workerImage: string;
  brokerImage: string;
  /** Address the worker must use for every request, set as http(s)_proxy. */
  brokerUrl: string;
  brokerPort: number;
};

export type CreateRuntimeOptions = {
  workspacePath?: string;
  workerImage?: string;
  brokerImage?: string;
  brokerPort?: number;
};

export type ContainerRuntimeOptions = {
  executor?: CommandExecutor;
  which?: (bin: string) => Promise<string | null>;
  workerImage?: string;
  brokerImage?: string;
};

const defaultExecutor: CommandExecutor = async (argv) => {
  const proc = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const code = await proc.exited;
  return { code, stdout, stderr };
};

function nameFor(prefix: string, auditId: string): string {
  const safe = auditId
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, "-")
    .slice(0, 40);
  return `${prefix}-${safe || "audit"}`;
}

export class ContainerRuntime {
  private readonly executor: CommandExecutor;
  private readonly whichBinary: (bin: string) => Promise<string | null>;
  private readonly workerImage: string;
  private readonly brokerImage: string;
  private readonly plans = new Map<string, RuntimePlan>();

  constructor(options: ContainerRuntimeOptions = {}) {
    this.executor = options.executor ?? defaultExecutor;
    this.whichBinary = options.which ?? (async (bin) => (await which(bin)) ?? null);
    this.workerImage = options.workerImage ?? "argus-worker:latest";
    this.brokerImage = options.brokerImage ?? "argus-broker:latest";
  }

  async detect(): Promise<RuntimeKind | null> {
    for (const kind of ["docker", "podman"] as const) {
      if (await this.whichBinary(kind)) return kind;
    }
    return null;
  }

  async create(auditId: string, options: CreateRuntimeOptions = {}): Promise<RuntimePlan> {
    const kind = await this.detect();
    if (!kind) throw new Error("Docker or Podman is required for dynamic audits");
    const brokerPort = options.brokerPort ?? 8080;
    const plan: RuntimePlan = {
      kind,
      network: nameFor("argus-audit", auditId),
      egressNetwork: nameFor("argus-egress", auditId),
      workerName: nameFor("argus-worker", auditId),
      brokerName: nameFor("argus-broker", auditId),
      workerImage: options.workerImage ?? this.workerImage,
      brokerImage: options.brokerImage ?? this.brokerImage,
      brokerUrl: `http://${nameFor("argus-broker", auditId)}:${brokerPort}`,
      brokerPort,
    };
    await this.run(kind, ["network", "create", "--internal", plan.network]);
    try {
      // The broker needs a route to the target; the worker never gets one.
      await this.run(kind, ["network", "create", plan.egressNetwork]);
      await this.run(kind, [
        "run",
        "-d",
        "--name",
        plan.brokerName,
        "--network",
        plan.network,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        plan.brokerImage,
      ]);
      await this.run(kind, ["network", "connect", plan.egressNetwork, plan.brokerName]);
      const workerArgs = [
        "run",
        "-d",
        "--name",
        plan.workerName,
        "--network",
        plan.network,
        "--user",
        "1000:1000",
        "--read-only",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-e",
        `HTTP_PROXY=${plan.brokerUrl}`,
        "-e",
        `HTTPS_PROXY=${plan.brokerUrl}`,
        "-e",
        `http_proxy=${plan.brokerUrl}`,
        "-e",
        `https_proxy=${plan.brokerUrl}`,
        "-e",
        "NO_PROXY=",
        "-e",
        "no_proxy=",
      ];
      if (options.workspacePath) workerArgs.push("-v", `${options.workspacePath}:/workspace:rw`);
      workerArgs.push(plan.workerImage, "sleep", "infinity");
      await this.run(kind, workerArgs);
    } catch (error) {
      await this.destroyPlan(plan);
      throw error;
    }
    this.plans.set(auditId, plan);
    return plan;
  }

  async destroy(auditId: string): Promise<void> {
    const plan = this.plans.get(auditId);
    if (!plan) return;
    await this.destroyPlan(plan);
    this.plans.delete(auditId);
  }

  async exec(auditId: string, argv: string[]): Promise<CommandResult> {
    const plan = this.plans.get(auditId);
    if (!plan) throw new Error(`No dynamic runtime for audit ${auditId}`);
    return this.executor([plan.kind, "exec", plan.workerName, ...argv]);
  }

  plan(auditId: string): RuntimePlan | null {
    return this.plans.get(auditId) ?? null;
  }

  private async run(kind: RuntimeKind, args: string[]): Promise<CommandResult> {
    const result = await this.executor([kind, ...args]);
    if (result.code !== 0) {
      throw new Error(`${kind} ${args.join(" ")} failed: ${result.stderr || result.stdout}`.trim());
    }
    return result;
  }

  private async tryRun(argv: string[]): Promise<void> {
    try {
      await this.executor(argv);
    } catch {
      // Cleanup is best-effort; the original failure is the one reported.
    }
  }

  private async destroyPlan(plan: RuntimePlan): Promise<void> {
    await this.tryRun([plan.kind, "rm", "-f", plan.workerName]);
    await this.tryRun([plan.kind, "rm", "-f", plan.brokerName]);
    await this.tryRun([plan.kind, "network", "rm", plan.network]);
    await this.tryRun([plan.kind, "network", "rm", plan.egressNetwork]);
  }
}
