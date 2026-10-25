import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const installer = join(root, "install.sh");
const temporary: string[] = [];
let fixture: string;

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "argus-install-test-"));
  temporary.push(directory);
  return directory;
}

function run(command: string[], cwd: string, env: Record<string, string | undefined> = {}) {
  const result = Bun.spawnSync(command, {
    cwd,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
    timeout: 30_000,
  });
  return { code: result.exitCode, output: result.stdout.toString() + result.stderr.toString() };
}

function install(directory: string, args: string[] = ["--no-start"], env: Record<string, string | undefined> = {}) {
  return run(["bash", installer, ...args], root, {
    ARGUS_INSTALL_DIR: directory,
    ARGUS_VERSION: "v0.0.1",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: `url.file://${fixture}.insteadOf`,
    GIT_CONFIG_VALUE_0: "https://github.com/ajul8866/argus.git",
    ...env,
  });
}

beforeAll(() => {
  fixture = mkdtempSync(join(tmpdir(), "argus-install-fixture-"));
  writeFileSync(join(fixture, "package.json"), JSON.stringify({
    name: "argus-installer-fixture",
    version: "0.0.1",
    type: "module",
    scripts: { build: "bun run build.ts" },
  }));
  writeFileSync(join(fixture, "build.ts"), 'await Bun.write("web/dist/index.html", "<!doctype html><title>Installer fixture</title>");');
  writeFileSync(join(fixture, "start.sh"), '#!/usr/bin/env bash\nset -euo pipefail\ncd -- "$(dirname -- "${BASH_SOURCE[0]}")"\nexec bun run smoke.ts\n');
  writeFileSync(join(fixture, "smoke.ts"), 'await Bun.write(`${process.env.ARGUS_DATA_DIR}/launched.json`, JSON.stringify({ data: process.env.ARGUS_DATA_DIR, port: process.env.ARGUS_PORT }));');
  const commands = [
    [process.execPath, "install", "--ignore-scripts"],
    ["git", "init", "-b", "main"],
    ["git", "add", "."],
    ["git", "-c", "user.name=Argus tests", "-c", "user.email=tests@example.invalid", "commit", "-m", "Installer fixture"],
    ["git", "tag", "v0.0.1"],
    ["git", "tag", "v0.0.2"],
  ];
  for (const command of commands) {
    const result = run(command, fixture);
    if (result.code !== 0) throw new Error(`Fixture setup failed: ${result.output}`);
  }
});

afterEach(() => {
  for (const directory of temporary.splice(0)) rmSync(directory, { recursive: true, force: true });
});
afterAll(() => rmSync(fixture, { recursive: true, force: true }));

describe("release installer", () => {
  test("help and invalid inputs do not create an installation", () => {
    const directory = join(temporaryDirectory(), "untouched");
    expect(install(directory, ["--help"]).code).toBe(0);
    expect(install(directory, ["--unexpected"]).code).not.toBe(0);
    expect(install(directory, [], { ARGUS_VERSION: "v0.0.1;echo unsafe" }).code).not.toBe(0);
    expect(existsSync(directory)).toBe(false);
  });

  test("refuses an unrelated nonempty directory without changing its files", () => {
    const directory = temporaryDirectory();
    const sentinel = join(directory, "keep.txt");
    writeFileSync(sentinel, "existing user data");
    const result = install(directory);
    expect(result.code).not.toBe(0);
    expect(result.output).toContain("not managed by Argus");
    expect(readFileSync(sentinel, "utf8")).toBe("existing user data");
    expect(existsSync(join(directory, ".argus-install"))).toBe(false);
  });

  test("installs a pinned local Git release in a path with spaces and starts on rerun while preserving data", () => {
    const directory = join(temporaryDirectory(), "installation with spaces ' and $characters");
    const result = install(directory);
    expect(result.code, result.output).toBe(0);
    expect(readFileSync(join(directory, "VERSION"), "utf8").trim()).toBe("v0.0.1");
    expect(existsSync(join(directory, "app/web/dist/index.html"))).toBe(true);
    expect(existsSync(join(directory, "data"))).toBe(false);
    expect(statSync(join(directory, "start.sh")).mode & 0o777).toBe(0o700);

    mkdirSync(join(directory, "data"));
    writeFileSync(join(directory, "data/keep.txt"), "persistent evidence");
    writeFileSync(join(directory, "app/.env"), "ARGUS_MAX_AGENTS=2\n");
    const started = install(directory, [], { ARGUS_PORT: "8898", ARGUS_DATA_DIR: undefined });
    expect(started.code, started.output).toBe(0);
    const state = JSON.parse(readFileSync(join(directory, "data/launched.json"), "utf8"));
    expect(state).toEqual({ data: join(directory, "data"), port: "8898" });
    expect(readFileSync(join(directory, "data/keep.txt"), "utf8")).toBe("persistent evidence");
    expect(readFileSync(join(directory, "app/.env"), "utf8")).toBe("ARGUS_MAX_AGENTS=2\n");
    expect(existsSync(join(directory, ".install-lock"))).toBe(false);

    const otherVersion = install(directory, ["--no-start"], { ARGUS_VERSION: "v0.0.2" });
    expect(otherVersion.code).not.toBe(0);
    expect(otherVersion.output).toContain("different or incomplete");
    expect(readFileSync(join(directory, "data/keep.txt"), "utf8")).toBe("persistent evidence");
  });

  test("cleans up a version mismatch and allows a successful retry", () => {
    const directory = join(temporaryDirectory(), "retry");
    const failed = install(directory, ["--no-start"], { ARGUS_VERSION: "v0.0.2" });
    expect(failed.code).not.toBe(0);
    expect(failed.output).toContain("does not match");
    expect(existsSync(join(directory, "app"))).toBe(false);
    expect(existsSync(join(directory, ".install-lock"))).toBe(false);
    const retried = install(directory);
    expect(retried.code, retried.output).toBe(0);
    expect(existsSync(join(directory, "app/web/dist/index.html"))).toBe(true);
  });

  test("keeps a concurrent installer's lock intact", () => {
    const directory = temporaryDirectory();
    writeFileSync(join(directory, ".argus-install"), "argus-installer-v1\n");
    mkdirSync(join(directory, ".install-lock"));
    const result = install(directory);
    expect(result.code).not.toBe(0);
    expect(result.output).toContain("Another installation");
    expect(existsSync(join(directory, ".install-lock"))).toBe(true);
  });
});

describe("startup failures", () => {
  test("invalid ports exit without creating runtime data", () => {
    const directory = temporaryDirectory();
    for (const port of ["0", "65536", "8787invalid", "-1"]) {
      const result = run([process.execPath, "run", "scripts/start.ts"], root, {
        ARGUS_PORT: port,
        ARGUS_DATA_DIR: join(directory, "data"),
      });
      expect(result.code).not.toBe(0);
      expect(result.output).toContain("ARGUS_PORT must be");
    }
    expect(existsSync(join(directory, "data"))).toBe(false);
  });

  test("an occupied port exits without initializing audit state", () => {
    const directory = temporaryDirectory();
    writeFileSync(join(directory, "index.html"), "<!doctype html><title>Startup fixture</title>");
    const occupied = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
    try {
      const result = run([process.execPath, "run", "scripts/start.ts"], root, {
        ARGUS_HOST: "127.0.0.1",
        ARGUS_PORT: String(occupied.port),
        ARGUS_DATA_DIR: join(directory, "data"),
        ARGUS_WEB_DIST: directory,
      });
      expect(result.code).not.toBe(0);
      expect(result.output).toContain("already in use");
      expect(existsSync(join(directory, "data"))).toBe(false);
    } finally {
      occupied.stop(true);
    }
  });

  test("missing assets produce a repair command before initializing audit state", () => {
    const directory = temporaryDirectory();
    const result = run([process.execPath, "run", "scripts/start.ts"], root, {
      ARGUS_PORT: "8898",
      ARGUS_DATA_DIR: join(directory, "data"),
      ARGUS_WEB_DIST: join(directory, "absent-assets"),
    });
    expect(result.code).not.toBe(0);
    expect(result.output).toContain("bun run build");
    expect(existsSync(join(directory, "data"))).toBe(false);
  });
});
