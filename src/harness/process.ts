import { realpath } from "node:fs/promises";
import { AppError } from "../util.ts";

export async function which(binary: string): Promise<string | null> {
  if (binary.includes("/")) {
    try {
      return await realpath(binary);
    } catch {
      return null;
    }
  }
  const proc = Bun.spawn(["sh", "-c", `command -v -- "$1"`, "argus", binary], {
    stdout: "pipe",
    stderr: "ignore",
    env: { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" },
  });
  const output = (await new Response(proc.stdout).text()).trim();
  const code = await proc.exited;
  return code === 0 && output ? output : null;
}

export async function runCommand(
  command: string[],
  options: {
    cwd?: string;
    env?: Record<string, string>;
    timeoutMs?: number;
    stdin?: string;
  } = {},
): Promise<{ code: number; stdout: string; stderr: string; timedOut: boolean }> {
  const proc = Bun.spawn(command, {
    cwd: options.cwd,
    env: options.env,
    stdin: options.stdin === undefined ? "ignore" : new TextEncoder().encode(options.stdin),
    stdout: "pipe",
    stderr: "pipe",
  });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill("SIGKILL");
  }, options.timeoutMs ?? 15_000);
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  clearTimeout(timer);
  return { code, stdout, stderr, timedOut };
}

/** Split a byte stream only on LF (not on Unicode line separators). */
export async function readJsonLines(
  stream: ReadableStream<Uint8Array>,
  onLine: (line: string) => void,
): Promise<void> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      while (true) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) break;
        let line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line.endsWith("\r")) line = line.slice(0, -1);
        if (line.trim().length > 0) onLine(line);
      }
    }
    buffer += decoder.decode();
    if (buffer.trim().length > 0) onLine(buffer);
  } finally {
    reader.releaseLock();
  }
}

export class ActiveProcess {
  proc: ReturnType<typeof Bun.spawn> | null = null;
  private stopped = false;

  attach(proc: ReturnType<typeof Bun.spawn>): void {
    this.proc = proc;
  }

  async terminate(signal: NodeJS.Signals = "SIGTERM", waitMs = 3_000): Promise<void> {
    if (!this.proc || this.stopped) return;
    this.stopped = true;
    try {
      this.proc.kill(signal);
    } catch {
      return;
    }
    const exited = await Promise.race([
      this.proc.exited.then(() => true),
      new Promise<boolean>((resolvePromise) => setTimeout(() => resolvePromise(false), waitMs)),
    ]);
    if (!exited && this.proc) {
      try {
        this.proc.kill("SIGKILL");
      } catch {
        // already gone
      }
    }
  }

  get alive(): boolean {
    return Boolean(this.proc) && !this.stopped;
  }
}

export function requireCommand(binary: string): never {
  throw new AppError(
    503,
    "harness_missing",
    `Harness executable not found: ${binary}. Install it or configure its path in Settings → Harnesses.`,
  );
}
