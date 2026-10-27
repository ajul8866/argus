import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { closeSync, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readlinkSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { open, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import type { Config } from "../src/config.ts";
import { loadConfig, PHASE_NAMES } from "../src/config.ts";
import { KeyedSerialQueue } from "../src/concurrency.ts";
import { Store } from "../src/db/index.ts";
import { buildFallbackPdf } from "../src/reports/pdf.ts";
import { EventLog } from "../src/events.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { ReportService } from "../src/reports/generator.ts";
import { buildInventory, gitInfo } from "../src/repo/inventory.ts";
import { importRepository, runPinnedGit } from "../src/repo/import.ts";
import { GIT_COMMON_DIR_ERROR, GIT_DIRECTORY_ERROR, GIT_METADATA_ERROR, GIT_OBJECTS_ERROR, assertAuthorizedRoot, canonicalDirectory, createWorkspace, openWorktreeGit, readCappedRegularFile, readScopedFile, verifyQuote } from "../src/repo/workspace.ts";
import { createScopeMatcher, globToRegExp, matchesScope, extractJson, sha256 } from "../src/util.ts";
import { redactSecrets } from "../src/security/redact.ts";
import { credentialEnvironment, decryptSecret, encryptSecret, type StoredCredential } from "../src/security/credentials.ts";
import { MAP_SCHEMA, validateAgainstSchema } from "../src/orchestrator/schemas.ts";
import { detectRepositoryRoots, listRepositoryFolders } from "../src/repo/directories.ts";
import { Database } from "bun:sqlite";
import { migrations } from "../src/db/migrations.ts";
import { DEFAULT_AGENTS } from "../src/settings.ts";
import { readJson } from "../src/api/http.ts";

const fixture = join(import.meta.dir, "fixtures", "vulnerable-app");

describe("HTTP JSON size limits", () => {
  for (const length of [undefined, "1"]) {
    test(`oversized JSON is rejected when Content-Length is ${length ?? "absent"}`, async () => {
      const headers = new Headers({ "content-type": "application/json" });
      if (length) headers.set("content-length", length);
      const request = new Request("http://localhost/api/test", {
        method: "POST", headers, body: JSON.stringify({ data: "x".repeat(2_000_000) }),
      });
      await expect(readJson(request)).rejects.toMatchObject({ status: 413, code: "body_too_large" });
    });
  }
});

function testConfig(dataDir: string): Config {
  return {
    port: 0,
    hostname: "127.0.0.1",
    dataDir,
    webDist: join(dataDir, "web"),
    adminEmail: "test@argus.local",
    adminPassword: "test-admin-password",
    sessionTtlMs: 60_000,
    maxConcurrentAgents: 2,
    sandboxMode: "none",
    piBin: "pi",
    claudeBin: "claude",
    allowedRoots: [fixture, dataDir, join(import.meta.dir, "..")],
    masterKey: "test-master-key-material",
    chromeBin: "google-chrome",
    secureCookies: false,
    logLevel: "error",
  };
}

test("upgrading runtime tool inheritance preserves custom role restrictions and shell choices", () => {
  const directory = mkdtempSync(join(tmpdir(), "argus-tools-upgrade-"));
  const legacy = new Database(join(directory, "test.sqlite"));
  legacy.exec("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)");
  for (const migration of migrations.filter((entry) => entry.version < 3)) {
    legacy.exec(migration.sql);
    legacy.query("INSERT INTO schema_migrations VALUES (?, ?, ?)").run(migration.version, migration.name, new Date().toISOString());
  }
  for (const agent of DEFAULT_AGENTS) {
    legacy.query(`INSERT INTO agent_defs (role,label,harness,system_instructions,allowed_tools,max_duration_ms,max_retries,concurrency_limit,allow_shell,enabled,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(agent.role, agent.label, agent.harness, agent.system_instructions,
      JSON.stringify(agent.allowed_tools), agent.max_duration_ms, agent.max_retries, agent.concurrency_limit, 0, 1, new Date().toISOString());
  }
  legacy.exec(`UPDATE agent_defs SET allowed_tools = '["read"]' WHERE role = 'security_researcher';
    UPDATE agent_defs SET allow_shell = 1 WHERE role = 'retest_auditor';`);
  legacy.close();
  const upgraded = new Store(testConfig(directory), "test.sqlite");
  try {
    expect(upgraded.get("SELECT inherit_tools FROM agent_defs WHERE role = 'codebase_mapper'")).toEqual({ inherit_tools: 1 });
    expect(upgraded.get("SELECT inherit_tools FROM agent_defs WHERE role = 'independent_validator'")).toEqual({ inherit_tools: 1 });
    expect(upgraded.get("SELECT inherit_tools, allowed_tools FROM agent_defs WHERE role = 'security_researcher'")).toEqual({ inherit_tools: 0, allowed_tools: '["read"]' });
    expect(upgraded.get("SELECT inherit_tools, allow_shell FROM agent_defs WHERE role = 'retest_auditor'")).toEqual({ inherit_tools: 0, allow_shell: 1 });
    expect(upgraded.all("SELECT version FROM schema_migrations ORDER BY version")).toEqual([{ version: 1 }, { version: 2 }, { version: 3 }]);
  } finally {
    upgraded.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("host repository folders", () => {
  test("default configuration accepts host folders without environment setup and honors explicit restrictions", async () => {
    const directory = mkdtempSync(join(tmpdir(), "argus-folders-config-"));
    const originalRoots = process.env.ARGUS_ALLOWED_ROOTS;
    const originalData = process.env.ARGUS_DATA_DIR;
    try {
      process.env.ARGUS_DATA_DIR = directory;
      delete process.env.ARGUS_ALLOWED_ROOTS;
      const automatic = loadConfig();
      expect(automatic.allowedRoots).toContain(detectRepositoryRoots([homedir()])[0]!);
      expect((await listRepositoryFolders(automatic.allowedRoots, { path: directory })).path).toBe(detectRepositoryRoots([directory])[0]!);
      mkdirSync(join(directory, "only-this"));
      process.env.ARGUS_ALLOWED_ROOTS = join(directory, "only-this");
      const restricted = loadConfig();
      await expect(listRepositoryFolders(restricted.allowedRoots, { path: directory })).rejects.toMatchObject({ code: "repository_not_authorized" });
      expect((await listRepositoryFolders(restricted.allowedRoots)).path).toBe(join(detectRepositoryRoots([directory])[0]!, "only-this"));
      symlinkSync(join(directory, "only-this"), join(directory, "alias"));
      process.env.ARGUS_ALLOWED_ROOTS = join(directory, "alias");
      const aliased = loadConfig();
      const selection = await listRepositoryFolders(aliased.allowedRoots);
      expect(aliased.allowedRoots).toContain(selection.path);
    } finally {
      if (originalRoots === undefined) delete process.env.ARGUS_ALLOWED_ROOTS;
      else process.env.ARGUS_ALLOWED_ROOTS = originalRoots;
      if (originalData === undefined) delete process.env.ARGUS_DATA_DIR;
      else process.env.ARGUS_DATA_DIR = originalData;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("detects existing readable locations and resolves duplicate aliases", () => {
    const directory = mkdtempSync(join(tmpdir(), "argus-folders-"));
    try {
      mkdirSync(join(directory, "repositories"));
      writeFileSync(join(directory, "file.txt"), "not a directory");
      symlinkSync(join(directory, "repositories"), join(directory, "alias"));
      const roots = detectRepositoryRoots([
        join(directory, "repositories"), join(directory, "missing"), join(directory, "file.txt"), join(directory, "alias"),
      ]);
      expect(roots).toEqual([detectRepositoryRoots([join(directory, "repositories")])[0]!]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("invalid runtime environment values fail instead of silently changing safety modes", () => {
    const names = ["ARGUS_SANDBOX", "ARGUS_LOG_LEVEL", "ARGUS_SESSION_TTL_HOURS", "ARGUS_PORT", "ARGUS_MAX_AGENTS"];
    const original = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    try {
      for (const [name, value] of [
        ["ARGUS_SANDBOX", "bwarp"],
        ["ARGUS_LOG_LEVEL", "verbose"],
        ["ARGUS_SESSION_TTL_HOURS", "0"],
        ["ARGUS_PORT", "not-a-port"],
        ["ARGUS_MAX_AGENTS", "17"],
      ]) {
        for (const key of names) delete process.env[key];
        process.env[name!] = value!;
        expect(() => loadConfig()).toThrow(name!);
      }
    } finally {
      for (const name of names) {
        if (original[name] === undefined) delete process.env[name];
        else process.env[name] = original[name];
      }
    }
  });

  test("lists selectable host folders with Git detection, filtering, and pagination", async () => {
    const directory = mkdtempSync(join(tmpdir(), "argus-folders-"));
    try {
      mkdirSync(join(directory, "smart-contract", ".git"), { recursive: true });
      mkdirSync(join(directory, "smart-contract", "contracts"));
      mkdirSync(join(directory, ".private"));
      mkdirSync(join(directory, "node_modules"));
      writeFileSync(join(directory, "secret.txt"), "file content must not be returned");
      symlinkSync(tmpdir(), join(directory, "outside-link"));
      for (let index = 0; index < 105; index += 1) mkdirSync(join(directory, `project-${String(index).padStart(3, "0")}`));
      const roots = detectRepositoryRoots([directory]);
      const first = await listRepositoryFolders(roots);
      expect(first.path).toBe(roots[0]!);
      expect(first.parent_path).toBeNull();
      expect(first.folders).toHaveLength(100);
      expect(first.next_offset).toBe(100);
      const next = await listRepositoryFolders(roots, { offset: "100" });
      expect(next.folders).toHaveLength(6);
      expect(next.next_offset).toBeNull();
      expect(next.folders.find((folder) => folder.name === "smart-contract")?.is_repository).toBe(true);
      expect(first.folders.every((folder) => !folder.is_repository)).toBe(true);
      const filtered = await listRepositoryFolders(roots, { search: "SMART" });
      expect(filtered.folders.map((folder) => folder.name)).toEqual(["smart-contract"]);
      const nested = await listRepositoryFolders(roots, { path: join(directory, "smart-contract") });
      expect(nested.parent_path).toBe(first.path);
      expect(nested.folders.map((folder) => folder.name)).toEqual(["contracts"]);
      expect(JSON.stringify(first)).not.toContain("secret.txt");
      expect(JSON.stringify(first)).not.toContain("outside-link");
      expect(JSON.stringify(first)).not.toContain(".private");
      expect(JSON.stringify(first)).not.toContain("node_modules");
      await expect(listRepositoryFolders(roots, { path: join(directory, "outside-link") })).rejects.toMatchObject({ code: "invalid_repository" });
      await expect(listRepositoryFolders(roots, { path: join(directory, "missing") })).rejects.toMatchObject({ code: "invalid_repository" });
      await expect(listRepositoryFolders(roots, { path: join(directory, "secret.txt") })).rejects.toMatchObject({ code: "invalid_repository" });
      await expect(listRepositoryFolders(roots, { offset: "-1" })).rejects.toMatchObject({ code: "bad_request" });
      await expect(listRepositoryFolders(roots, { offset: "Infinity" })).rejects.toMatchObject({ code: "bad_request" });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe("scope and parsing", () => {
  test("glob matcher supports ** and directory paths", () => {
    expect(globToRegExp("**/*.js").test("src/server.js")).toBe(true);
    expect(globToRegExp("**/*.js").test("server.js")).toBe(true);
    expect(globToRegExp("src/**").test("src/lib/db.js")).toBe(true);
    expect(globToRegExp("src/*.js").test("src/lib/db.js")).toBe(false);
    expect(matchesScope("src/server.js", { include: ["**/*.js"], exclude: ["src/lib/**"] })).toBe(true);
    expect(matchesScope("src/lib/db.js", { include: ["**/*.js"], exclude: ["src/lib/**"] })).toBe(false);
  });

  test("reusable scope matching preserves glob semantics and path normalization", () => {
    const matcher = createScopeMatcher({
      include: ["src/**/*.{ts,js}", "test/?.[jt]s"],
      exclude: ["src/private/**", "**/*.test.*"],
    });
    const cases: Array<[string, boolean]> = [
      ["src/main.ts", true],
      ["./src/lib/main.js", true],
      ["src\\lib\\main.ts", true],
      ["src/private/main.ts", false],
      ["src/lib/main.test.js", false],
      ["test/a.ts", true],
      ["test/ab.ts", false],
      ["README.md", false],
    ];
    for (let repeat = 0; repeat < 2; repeat += 1) {
      for (const [path, expected] of cases) expect(matcher.matches(path)).toBe(expected);
    }
    expect(matcher.excludes("src/private/argus-probe")).toBe(true);
    expect(matcher.excludes("src/public/argus-probe")).toBe(false);
    expect(createScopeMatcher({ include: [], exclude: [] }).matches("src/main.ts")).toBe(false);
  });

  test("readScopedFile rejects traversal and symlink escapes outside the declared scope", async () => {
    const root = mkdtempSync(join(tmpdir(), "argus-scope-"));
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      writeFileSync(join(root, "src", "a.js"), "console.log('inside');\n");
      writeFileSync(join(root, "secrets.js"), "console.log('outside');\n");
      symlinkSync("../secrets.js", join(root, "src", "link.js"));
      symlinkSync("/etc/passwd", join(root, "src", "outside.js"));
      const scope = { include: ["src/**/*.js"], exclude: [] };
      const inside = await readScopedFile(root, "src/a.js", scope);
      expect(inside.path).toBe("src/a.js");
      expect(inside.content).toContain("inside");
      const normalized = await readScopedFile(root, "src/./a.js", scope);
      expect(normalized.path).toBe("src/a.js");
      const expectOutOfScope = async (path: string): Promise<void> => {
        try {
          await readScopedFile(root, path, scope);
          throw new Error(`Expected ${path} to be rejected`);
        } catch (error) {
          expect((error as { code?: string }).code).toBe("out_of_scope");
        }
      };
      await expectOutOfScope("secrets.js");
      await expectOutOfScope("src/../secrets.js");
      await expectOutOfScope("src/link.js");
      await expectOutOfScope("src/outside.js");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("readScopedFile reads an in-scope symlink target and caps the bytes it loads", async () => {
    const root = mkdtempSync(join(tmpdir(), "argus-scoped-read-"));
    try {
      mkdirSync(join(root, "src"));
      writeFileSync(join(root, "src", "b.js"), "console.log('target');\n");
      symlinkSync("b.js", join(root, "src", "a.js"));
      writeFileSync(join(root, "src", "big.js"), "A".repeat(5_000));
      writeFileSync(join(root, "src", "bin.js"), "a\0b");
      const scope = { include: ["src/**/*.js"], exclude: [] };
      const linked = await readScopedFile(root, "src/a.js", scope);
      expect(linked.path).toBe("src/a.js");
      expect(linked.content).toContain("target");
      const preview = await readScopedFile(root, "src/big.js", scope, 100);
      expect(preview.truncated).toBe(true);
      expect(preview.size).toBe(5_000);
      expect(preview.content).toBe("A".repeat(100));
      expect(preview.binary).toBe(false);
      const binary = await readScopedFile(root, "src/bin.js", scope);
      expect(binary.binary).toBe(true);
      expect(binary.content).toBe("");

      const pipe = join(root, "src", "pipe.js");
      expect(Bun.spawnSync(["mkfifo", pipe]).exitCode).toBe(0);
      const pipeResult = await Promise.race([
        readScopedFile(root, "src/pipe.js", scope).then(() => "opened").catch((error: { code?: string }) => error.code ?? "error"),
        Bun.sleep(500).then(() => "blocked"),
      ]);
      expect(pipeResult).toBe("not_a_file");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("readScopedFile does not load bytes written after the size check", async () => {
    const root = mkdtempSync(join(tmpdir(), "argus-scoped-grow-"));
    const file = join(root, "a.js");
    writeFileSync(file, "small");
    const before = 5;
    const scope = { include: ["**/*"], exclude: [] };
    const probe = await open(file, "r");
    const proto = Object.getPrototypeOf(probe) as {
      stat: (this: unknown, ...args: unknown[]) => Promise<{ isFile: () => boolean; size: number }>;
      read: (
        this: unknown,
        buffer: Buffer,
        offset?: number,
        length?: number,
        position?: number | null,
      ) => Promise<{ bytesRead: number }>;
      readFile: (this: unknown, ...args: unknown[]) => Promise<unknown>;
    };
    await probe.close();
    const originalStat = proto.stat;
    const originalRead = proto.read;
    const originalReadFile = proto.readFile;
    let readFileCalls = 0;
    let bytesRequested = 0;
    proto.stat = async function (this: unknown, ...args: unknown[]) {
      const info = await originalStat.apply(this, args);
      const size = info.size;
      const isFile = info.isFile();
      if (isFile && size === before) writeFileSync(file, "Q".repeat(200_000));
      return { isFile: () => isFile, size };
    };
    proto.read = async function (
      this: unknown,
      buffer: Buffer,
      offset?: number,
      length?: number,
      position?: number | null,
    ) {
      if (length === undefined || length > before) throw new Error(`unbounded scoped read of ${String(length)} bytes`);
      bytesRequested += length;
      return originalRead.call(this, buffer, offset, length, position);
    };
    proto.readFile = async function (this: unknown, ...args: unknown[]) {
      readFileCalls += 1;
      return originalReadFile.apply(this, args);
    };
    try {
      const result = await readScopedFile(root, "a.js", scope, 1_000);
      expect(result.content).toBe("Q".repeat(before));
      expect(result.size).toBe(before);
      expect(result.truncated).toBe(false);
      expect(readFileCalls).toBe(0);
      expect(bytesRequested).toBeGreaterThan(0);
      expect(bytesRequested).toBeLessThanOrEqual(before);
    } finally {
      proto.stat = originalStat;
      proto.read = originalRead;
      proto.readFile = originalReadFile;
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("scope matching only compiles patterns reached by short-circuit evaluation", () => {
    const matcher = createScopeMatcher({ include: ["src/**", "[z-a]"], exclude: [] });
    expect(matcher.matches("src/main.ts")).toBe(true);
    expect(() => matcher.matches("other.ts")).toThrow();
    expect(createScopeMatcher({ include: [], exclude: ["[z-a]"] }).matches("other.ts")).toBe(false);
    expect(createScopeMatcher({ include: ["**/*"], exclude: ["**/*", "[z-a]"] }).matches("src/main.ts")).toBe(false);
  });

  test("JSON extraction accepts raw, fenced, and embedded objects", () => {
    expect(extractJson('{"ok":true}')).toEqual({ ok: true });
    expect(extractJson('```json\n{"ok":true}\n```')).toEqual({ ok: true });
    expect(extractJson('Result follows: {"ok":true} thanks')).toEqual({ ok: true });
    expect(extractJson("no json here")).toBeNull();
  });

  test("schema validator rejects unknown properties and wrong enums", () => {
    const errors = validateAgainstSchema(
      {
        summary: "x",
        languages: [],
        frameworks: [],
        modules: [],
        entrypoints: [],
        endpoints: [],
        auth_boundaries: [],
        data_access: [],
        critical_paths: [],
        areas: [{ id: "a", title: "A", rationale: "r", files: ["x.js"], security_focus: [] }],
        coverage_notes: [],
        limitations: [],
        invented: true,
      },
      MAP_SCHEMA,
    );
    expect(errors.some((error) => error.includes("invented"))).toBe(true);
    const enumErrors = validateAgainstSchema(
      {
        verdict: "MAYBE",
        rationale: "x",
        verified_excerpts: [],
        reproduction_steps: [],
        prerequisites_checked: [],
        alternative_explanations: [],
        mitigating_controls: [],
        severity_assessment: "high",
        impact_assessment: "x",
        completeness_issues: [],
        duplicate_of_finding_code: null,
      },
      {
        type: "object",
        properties: { verdict: { type: "string", enum: ["CONFIRMED"] } },
        required: ["verdict"],
      },
    );
    expect(enumErrors.length).toBeGreaterThan(0);
  });
});

describe("redaction", () => {
  test("redacts credentials but keeps surrounding code", () => {
    const fakeToken = ["sk", "ant", "a".repeat(24)].join("-");
    const input = `const token = "${fakeToken}";\nconst password = "super-secret";\nconst normal = "hello";`;
    const result = redactSecrets(input);
    expect(result.count).toBeGreaterThanOrEqual(2);
    expect(result.text).not.toContain(fakeToken);
    expect(result.text).not.toContain("super-secret");
    expect(result.text).toContain("const normal");
  });
});

describe("credential vault", () => {
  test("encrypts write-only provider credentials and injects only matching env", () => {
    const dir = mkdtempSync(join(tmpdir(), "argus-creds-"));
    try {
      const config = testConfig(dir);
      const encrypted = encryptSecret(config, "provider-secret-value-1234");
      expect(encrypted.ciphertext).not.toContain("provider-secret");
      expect(encrypted.last4).toBe("1234");
      const row: StoredCredential = {
        id: "c1",
        provider: "magpie",
        env_var: "MCODE_PROVIDER_API_KEY",
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        tag: encrypted.tag,
        last4: encrypted.last4,
        created_at: "2026-01-01",
        updated_at: "2026-01-01",
      };
      expect(decryptSecret(config, row)).toBe("provider-secret-value-1234");
      expect(credentialEnvironment(config, [row], "magpie")).toEqual({
        MCODE_PROVIDER_API_KEY: "provider-secret-value-1234",
      });
      expect(credentialEnvironment(config, [row], "other")).toEqual({});
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("inventory and evidence gates", () => {
  test("fixture inventory detects JavaScript, endpoints, and auth signals", async () => {
    const inventory = await buildInventory(fixture, {
      scope: { include: ["**/*.js", "**/*.json", "README.md"], exclude: [".git/**", "node_modules/**"] },
      maxFiles: 100,
      maxFileBytes: 1_000_000,
    });
    expect(inventory.files.length).toBe(10);
    expect(inventory.languages.JavaScript).toBeGreaterThanOrEqual(7);
    expect(inventory.frameworks).toContain("Express");
    expect(inventory.endpoints.length).toBeGreaterThanOrEqual(5);
    expect(inventory.auth_boundaries.length).toBeGreaterThan(0);
    const git = await gitInfo(fixture);
    expect(git.commit?.length).toBeGreaterThan(10);
  });

  test("inventory reads only the checked size when a file grows", async () => {
    const root = mkdtempSync(join(tmpdir(), "argus-inventory-grow-"));
    const file = join(root, "a.js");
    writeFileSync(file, "small");
    const before = 5;
    const probe = await open(file, "r");
    const proto = Object.getPrototypeOf(probe) as {
      stat: (this: unknown, ...args: unknown[]) => Promise<{ isFile: () => boolean; size: number }>;
      read: (
        this: unknown,
        buffer: Buffer,
        offset?: number,
        length?: number,
        position?: number | null,
      ) => Promise<{ bytesRead: number }>;
      readFile: (this: unknown, ...args: unknown[]) => Promise<unknown>;
    };
    await probe.close();
    const originalStat = proto.stat;
    const originalRead = proto.read;
    const originalReadFile = proto.readFile;
    let readFileCalls = 0;
    let bytesRequested = 0;
    proto.stat = async function (this: unknown, ...args: unknown[]) {
      const info = await originalStat.apply(this, args);
      const size = info.size;
      const isFile = info.isFile();
      if (isFile && size === before) writeFileSync(file, "Q".repeat(200_000));
      return { isFile: () => isFile, size };
    };
    proto.read = async function (
      this: unknown,
      buffer: Buffer,
      offset?: number,
      length?: number,
      position?: number | null,
    ) {
      if (length === undefined || length > before) throw new Error(`unbounded inventory read of ${String(length)} bytes`);
      bytesRequested += length;
      return originalRead.call(this, buffer, offset, length, position);
    };
    proto.readFile = async function (this: unknown, ...args: unknown[]) {
      readFileCalls += 1;
      return originalReadFile.apply(this, args);
    };
    try {
      const inventory = await buildInventory(root, {
        scope: { include: ["**/*"], exclude: [] },
        maxFiles: 10,
        maxFileBytes: 1_000,
      });
      expect(inventory.files.map((entry) => entry.path)).toEqual(["a.js"]);
      expect(inventory.files[0]?.size).toBe(before);
      expect(inventory.files[0]?.sha256).toBe(sha256("Q".repeat(before)));
      expect(readFileCalls).toBe(0);
      expect(bytesRequested).toBeGreaterThan(0);
      expect(bytesRequested).toBeLessThanOrEqual(before);
    } finally {
      proto.stat = originalStat;
      proto.read = originalRead;
      proto.readFile = originalReadFile;
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("quote verification rejects fabricated excerpts", async () => {
    const scope = { include: ["**/*.js"], exclude: [".git/**"] };
    const exact = await verifyQuote(fixture, scope, {
      path: "src/lib/db.js",
      quote: '  const query = "SELECT id, email, display_name, role FROM users WHERE email LIKE \'%" + term + "%\'";',
      start_line: 11,
      end_line: 11,
    });
    expect(exact.found).toBe(true);
    const fake = await verifyQuote(fixture, scope, {
      path: "src/lib/db.js",
      quote: "db.query('DROP TABLE users')",
      start_line: 1,
      end_line: 1,
    });
    expect(fake.found).toBe(false);
    const traversal = await verifyQuote(fixture, scope, {
      path: "../etc/passwd",
      quote: "root:x:0:0",
      start_line: 1,
      end_line: 1,
    });
    expect(traversal.found).toBe(false);
  });
});

describe("repository import", () => {
  let dir = "";
  let config: Config;
  let store: Store;
  let project: { id: string; name: string; source_path: string; scope_include: string; scope_exclude: string };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "argus-import-"));
    config = testConfig(dir);
    store = new Store(config, "test.sqlite");
    project = {
      id: "p1",
      name: "Fixture",
      source_path: fixture,
      scope_include: JSON.stringify(["**/*.js", "**/*.json", "README.md"]),
      scope_exclude: JSON.stringify(["src/routes/media.js"]),
    };
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES (?, ?, '', ?, ?, ?, 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      project.id, project.name, project.source_path, project.scope_include, project.scope_exclude,
    );
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("snapshots only in-scope files and records inventory and actor metadata", async () => {
    const imported = await importRepository({ config, store }, project, null, "tester@argus.local");
    expect(imported.path.startsWith(join(dir, "repos", project.id))).toBe(true);
    expect(imported.project_id).toBe(project.id);
    expect(imported.file_count).toBe(9);
    const row = store.get<{ inventory: string }>("SELECT inventory FROM repositories WHERE id = ?", imported.id)!;
    const inventory = JSON.parse(row.inventory) as { files: Array<{ path: string }> };
    expect(inventory.files.some((file) => file.path === "src/routes/media.js")).toBe(false);
    expect(inventory.files.some((file) => file.path.startsWith(".git/"))).toBe(false);
    const source = await Bun.file(join(fixture, "src/lib/db.js")).text();
    expect(await Bun.file(join(imported.path, "src/lib/db.js")).text()).toBe(source);
    const metadata = await Bun.file(join(imported.path, "ARGUS_SCOPE.json")).json();
    expect(metadata.imported_by).toBe("tester@argus.local");
    expect(metadata.source_root).toBe(fixture);
  });

  test("imports a git ref with the resolved commit and requested ref", async () => {
    const git = await gitInfo(fixture);
    const imported = await importRepository({ config, store }, project, "HEAD", "tester@argus.local");
    expect(imported.commit_sha).toBe(git.commit);
    expect(imported.branch).toBe("HEAD");
    expect(imported.file_count).toBe(9);
    expect(await Bun.file(join(imported.path, "src/lib/db.js")).text()).toContain("SELECT id");
    expect(await Bun.file(join(imported.path, "src/routes/media.js")).exists()).toBe(false);
    expect((await stat(join(imported.path, "src/lib/db.js"))).mode & 0o777).toBe(0o400);
    const metadata = await Bun.file(join(imported.path, "ARGUS_SCOPE.json")).json();
    expect(metadata.commit).toBe(git.commit);
    expect(metadata.imported_by).toBe("tester@argus.local");
  });

  test("rejects unauthorized roots, unknown refs, and empty scope without persisting a repository", async () => {
    await expect(importRepository({ config: { ...config, allowedRoots: [dir] }, store }, project, null, "tester"))
      .rejects.toMatchObject({ code: "repository_not_authorized" });
    await expect(importRepository({ config, store }, project, "argus-missing-ref", "tester"))
      .rejects.toThrow("Unknown git ref");
    await expect(importRepository({ config, store }, { ...project, scope_include: "[]" }, null, "tester"))
      .rejects.toThrow("No in-scope files were found");
    expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
  });

  test("workspaces are read-only by default and owner-writable only on explicit request", async () => {
    const scope = { include: ["**/*.js", "**/*.json", "README.md"], exclude: ["src/routes/media.js"] };
    const inventory = await buildInventory(fixture, { scope, maxFiles: 100, maxFileBytes: 1_000_000 });
    const readOnly = join(dir, "workspace-read-only");
    const writable = join(dir, "workspace-writable");
    await createWorkspace(fixture, inventory, scope, readOnly, {});
    await createWorkspace(fixture, inventory, scope, writable, {}, true);

    expect((await stat(join(readOnly, "src/lib/db.js"))).mode & 0o777).toBe(0o400);
    expect((await stat(join(writable, "src/lib/db.js"))).mode & 0o777).toBe(0o600);
    expect((await stat(readOnly)).mode & 0o777).toBe(0o700);
    expect((await stat(writable)).mode & 0o777).toBe(0o700);
    expect((await stat(join(writable, "ARGUS_SCOPE.json"))).mode & 0o777).toBe(0o400);
    expect((await Bun.file(join(readOnly, "ARGUS_SCOPE.json")).json()).writable).toBe(false);
    expect((await Bun.file(join(writable, "ARGUS_SCOPE.json")).json()).writable).toBe(true);
  });

  test("workspace copy rejects a symlink, a directory swap, and bytes that no longer match the inventory", async () => {
    const scope = { include: ["**/*"], exclude: [] };
    const listed = (path: string, content: string) => ({
      files: [{ path, size: Buffer.byteLength(content), lines: 1, language: "JavaScript", sha256: sha256(content) }],
      skipped: [],
      languages: {},
      frameworks: [],
      endpoints: [],
      auth_boundaries: [],
      dependency_graph: [],
      entrypoints: [],
      total_bytes: Buffer.byteLength(content),
      truncated: false,
    });

    const changedRoot = join(dir, "changed-source");
    mkdirSync(changedRoot);
    writeFileSync(join(changedRoot, "a.js"), "alpha");
    const changedCopy = join(dir, "changed-copy");
    await expect(createWorkspace(changedRoot, listed("a.js", "beta"), scope, changedCopy, {})).rejects.toMatchObject({
      code: "conflict",
    });
    expect(existsSync(join(changedCopy, "a.js"))).toBe(false);

    const linkRoot = join(dir, "link-source");
    mkdirSync(linkRoot);
    const outside = join(dir, "outside-secret.txt");
    writeFileSync(outside, "SECRET_OUTSIDE_SENTINEL");
    symlinkSync(outside, join(linkRoot, "link.js"));
    const linkCopy = join(dir, "link-copy");
    await expect(createWorkspace(linkRoot, listed("link.js", "SECRET_OUTSIDE_SENTINEL"), scope, linkCopy, {})).rejects.toMatchObject({
      code: "not_a_file",
    });
    expect(existsSync(join(linkCopy, "link.js"))).toBe(false);

    const swappedRoot = join(dir, "swapped-source");
    const outsideDir = join(dir, "outside-dir");
    mkdirSync(swappedRoot);
    mkdirSync(outsideDir);
    writeFileSync(join(outsideDir, "a.js"), "SECRET_INTERMEDIATE");
    symlinkSync(outsideDir, join(swappedRoot, "src"));
    const swappedCopy = join(dir, "swapped-copy");
    await expect(createWorkspace(swappedRoot, listed("src/a.js", "SECRET_INTERMEDIATE"), scope, swappedCopy, {})).rejects.toMatchObject({
      code: "out_of_scope",
    });
    expect(existsSync(join(swappedCopy, "src", "a.js"))).toBe(false);
  });

  test("scoped reads, inventory, and snapshot copy reject a repository directory replaced by a symlink", async () => {
    const root = mkdtempSync(join(tmpdir(), "argus-root-swap-"));
    const source = join(root, "repo");
    const outside = join(root, "outside");
    const scope = { include: ["**/*"], exclude: [] };
    try {
      mkdirSync(join(source, "src"), { recursive: true });
      mkdirSync(join(outside, "src"), { recursive: true });
      writeFileSync(join(source, "a.js"), "INSIDE_CONTENT");
      writeFileSync(join(source, "src", "a.js"), "INSIDE_NESTED");
      writeFileSync(join(outside, "a.js"), "SECRET_OUTSIDE_SENTINEL");
      writeFileSync(join(outside, "src", "a.js"), "SECRET_NESTED_SENTINEL");

      const before = await readScopedFile(source, "src/a.js", scope);
      expect(before.content).toBe("INSIDE_NESTED");
      const pinned = await canonicalDirectory(source);
      expect(pinned).toBe(realpathSync(source));

      renameSync(source, `${source}.bak`);
      symlinkSync(outside, source);

      await expect(readScopedFile(source, "a.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readScopedFile(source, "src/a.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readCappedRegularFile(join(source, "a.js"), 1_000, {
        root: source,
        relativePath: "a.js",
      })).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readCappedRegularFile(join(source, "src", "a.js"), 1_000, {
        root: source,
        relativePath: "src/a.js",
      })).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(buildInventory(source, { scope, maxFiles: 20, maxFileBytes: 1_000 })).rejects.toMatchObject({
        code: "out_of_scope",
      });
      const copy = join(root, "copy");
      await expect(createWorkspace(source, {
        files: [{
          path: "a.js",
          size: Buffer.byteLength("SECRET_OUTSIDE_SENTINEL"),
          lines: 1,
          language: "JavaScript",
          sha256: sha256("SECRET_OUTSIDE_SENTINEL"),
        }],
        skipped: [],
        languages: {},
        frameworks: [],
        endpoints: [],
        auth_boundaries: [],
        dependency_graph: [],
        entrypoints: [],
        total_bytes: Buffer.byteLength("SECRET_OUTSIDE_SENTINEL"),
        truncated: false,
      }, scope, copy, {})).rejects.toMatchObject({ code: "out_of_scope" });
      expect(existsSync(join(copy, "a.js"))).toBe(false);
      expect(existsSync(join(copy, "src", "a.js"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("scoped reads, inventory, and snapshot copy reject an ancestor directory replaced by a symlink", async () => {
    const root = mkdtempSync(join(tmpdir(), "argus-ancestor-swap-"));
    const parent = join(root, "parent");
    const source = join(parent, "repo");
    const outside = join(root, "outside");
    const outsideRepo = join(outside, "repo");
    const scope = { include: ["**/*"], exclude: [] };
    const secretInventory = {
      files: [{
        path: "a.js",
        size: Buffer.byteLength("SECRET_ANCESTOR_SENTINEL"),
        lines: 1,
        language: "JavaScript",
        sha256: sha256("SECRET_ANCESTOR_SENTINEL"),
      }],
      skipped: [],
      languages: {},
      frameworks: [],
      endpoints: [],
      auth_boundaries: [],
      dependency_graph: [],
      entrypoints: [],
      total_bytes: Buffer.byteLength("SECRET_ANCESTOR_SENTINEL"),
      truncated: false,
    };
    try {
      mkdirSync(join(source, "src"), { recursive: true });
      mkdirSync(join(outsideRepo, "src"), { recursive: true });
      writeFileSync(join(source, "a.js"), "INSIDE_CONTENT");
      writeFileSync(join(source, "src", "a.js"), "INSIDE_NESTED");
      writeFileSync(join(outsideRepo, "a.js"), "SECRET_ANCESTOR_SENTINEL");
      writeFileSync(join(outsideRepo, "src", "a.js"), "SECRET_NESTED_SENTINEL");

      const before = await readScopedFile(source, "src/a.js", scope);
      expect(before.content).toBe("INSIDE_NESTED");

      renameSync(parent, `${parent}.bak`);
      symlinkSync(outside, parent);

      await expect(canonicalDirectory(source)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readScopedFile(source, "a.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readScopedFile(source, "src/a.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readCappedRegularFile(join(source, "a.js"), 1_000, {
        root: source,
        relativePath: "a.js",
      })).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readCappedRegularFile(join(source, "src", "a.js"), 1_000, {
        root: source,
        relativePath: "src/a.js",
      })).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(buildInventory(source, { scope, maxFiles: 20, maxFileBytes: 1_000 })).rejects.toMatchObject({
        code: "out_of_scope",
      });
      const copy = join(root, "copy");
      await expect(createWorkspace(source, secretInventory, scope, copy, {})).rejects.toMatchObject({
        code: "out_of_scope",
      });
      expect(existsSync(join(copy, "a.js"))).toBe(false);
      expect(existsSync(join(copy, "src", "a.js"))).toBe(false);

      const aliasParent = join(root, "alias-parent");
      const alias = join(aliasParent, "tmp");
      const aliasOutside = join(aliasParent, "outside");
      mkdirSync(alias, { recursive: true });
      mkdirSync(aliasOutside, { recursive: true });
      writeFileSync(join(alias, "a.js"), "INSIDE_ALIAS");
      writeFileSync(join(aliasOutside, "a.js"), "SECRET_ALIAS_SENTINEL");
      renameSync(alias, `${alias}.bak`);
      symlinkSync(aliasOutside, alias);
      await expect(readScopedFile(alias, "a.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readCappedRegularFile(join(alias, "a.js"), 1_000, {
        root: alias,
        relativePath: "a.js",
      })).rejects.toMatchObject({ code: "out_of_scope" });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("authorization and import reject a symlink whose target remains inside an allowed root", async () => {
    const allowed = dir;
    const source = join(allowed, "proj", "app");
    const outside = join(allowed, "other", "app");
    const scope = { include: ["**/*"], exclude: [] };
    mkdirSync(source, { recursive: true });
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(source, "a.js"), "INSIDE_CONTENT");
    writeFileSync(join(outside, "a.js"), "SECRET_ANCESTOR_SENTINEL");

    const before = await assertAuthorizedRoot(source, [allowed]);
    expect(before).toBe(realpathSync(source));
    expect((await readScopedFile(before, "a.js", scope)).content).toBe("INSIDE_CONTENT");

    renameSync(join(allowed, "proj"), join(allowed, "proj.bak"));
    symlinkSync(join(allowed, "other"), join(allowed, "proj"));

    await expect(canonicalDirectory(source)).rejects.toMatchObject({ code: "out_of_scope" });
    await expect(assertAuthorizedRoot(source, [allowed])).rejects.toMatchObject({ code: "invalid_repository" });
    const swapped = {
      id: "p-ancestor",
      name: "Swapped",
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    };
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES (?, ?, '', ?, ?, ?, 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      swapped.id, swapped.name, swapped.source_path, swapped.scope_include, swapped.scope_exclude,
    );
    await expect(importRepository({ config: { ...config, allowedRoots: [allowed] }, store }, swapped, null, "tester"))
      .rejects.toMatchObject({ code: "invalid_repository" });
    expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
    expect(existsSync(join(dir, "repos"))).toBe(false);

    const leaf = join(allowed, "leaf");
    const leafOutside = join(allowed, "leaf-out");
    mkdirSync(leaf, { recursive: true });
    mkdirSync(leafOutside, { recursive: true });
    writeFileSync(join(leaf, "a.js"), "LEAF_INSIDE");
    writeFileSync(join(leafOutside, "a.js"), "SECRET_LEAF_SENTINEL");
    const leafBefore = await assertAuthorizedRoot(leaf, [allowed]);
    expect((await readScopedFile(leafBefore, "a.js", scope)).content).toBe("LEAF_INSIDE");
    renameSync(leaf, `${leaf}.bak`);
    symlinkSync(leafOutside, leaf);
    await expect(assertAuthorizedRoot(leaf, [allowed])).rejects.toMatchObject({ code: "invalid_repository" });
    await expect(readScopedFile(leaf, "a.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
  });

  test("a symlink used as an allowed root does not authorize its target", async () => {
    const real = join(dir, "real-root");
    const alias = join(dir, "alias-root");
    const app = join(real, "app");
    mkdirSync(app, { recursive: true });
    writeFileSync(join(app, "a.js"), "SECRET_BOUNDARY_SENTINEL");
    symlinkSync(real, alias);
    await expect(assertAuthorizedRoot(app, [alias])).rejects.toMatchObject({ code: "repository_not_authorized" });
    const authorized = await assertAuthorizedRoot(app, [real]);
    expect(authorized).toBe(realpathSync(app));
    expect((await readScopedFile(authorized, "a.js", { include: ["**/*"], exclude: [] })).content).toBe("SECRET_BOUNDARY_SENTINEL");
  });

  function pointBranch(repo: string, sha: string): void {
    const head = readFileSync(join(repo, ".git/HEAD"), "utf8").trim();
    if (!head.startsWith("ref: ")) throw new Error(`unexpected HEAD ${head}`);
    const ref = head.slice("ref: ".length);
    if (!ref || ref.startsWith("/") || ref.split("/").includes("..")) throw new Error(`unexpected ref ${ref}`);
    writeFileSync(join(repo, ".git", ref), `${sha}\n`);
  }

  function gitExec(directory: string, args: string[]): string {
    const result = Bun.spawnSync(["git", "-C", directory, ...args], {
      stdout: "pipe",
      stderr: "pipe",
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_AUTHOR_NAME: "t",
        GIT_AUTHOR_EMAIL: "t@example.com",
        GIT_COMMITTER_NAME: "t",
        GIT_COMMITTER_EMAIL: "t@example.com",
      },
    });
    if (result.exitCode !== 0) throw new Error(new TextDecoder().decode(result.stderr));
    return new TextDecoder().decode(result.stdout).trim();
  }

  function initRepo(directory: string, files: Record<string, string>): void {
    mkdirSync(directory, { recursive: true });
    for (const [name, content] of Object.entries(files)) {
      const path = join(directory, name);
      mkdirSync(join(path, ".."), { recursive: true });
      writeFileSync(path, content);
    }
    gitExec(directory, ["init", "-q"]);
    gitExec(directory, ["config", "user.email", "t@example.com"]);
    gitExec(directory, ["config", "user.name", "t"]);
    gitExec(directory, ["add", "-A"]);
    gitExec(directory, ["commit", "-qm", "init"]);
  }

  test("a git ref import does not follow a .git symlink or gitdir file", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-git-outside-"));
    try {
      initRepo(outside, { "secret.js": "SECRET_GITDIR_SENTINEL" });
      const source = join(dir, "inside");
      initRepo(source, { "a.js": "INSIDE_CONTENT" });
      const limited = { ...config, allowedRoots: [dir] };
      const requested = {
        ...project,
        source_path: source,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      };
      renameSync(join(source, ".git"), join(source, ".git-real"));
      symlinkSync(join(outside, ".git"), join(source, ".git"));
      await expect(importRepository({ config: limited, store }, requested, "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_METADATA_ERROR });
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);

      rmSync(join(source, ".git"));
      writeFileSync(join(source, ".git"), `gitdir: ${join(outside, ".git")}\n`);
      await expect(importRepository({ config: limited, store }, requested, "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_METADATA_ERROR });

      rmSync(join(source, ".git"));
      symlinkSync(join(outside, ".git"), join(source, ".git"));
      const imported = await importRepository({ config: limited, store }, requested, null, "tester");
      expect(imported.commit_sha).toBeNull();
      expect(await Bun.file(join(imported.path, "a.js")).text()).toBe("INSIDE_CONTENT");
      expect(existsSync(join(imported.path, "secret.js"))).toBe(false);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects an object store outside the allowed root", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-git-objects-"));
    try {
      initRepo(outside, { "hidden.js": "SECRET_ALT_SENTINEL" });
      const alternate = join(dir, "alternate-repo");
      initRepo(alternate, { "a.js": "INSIDE_CONTENT" });
      mkdirSync(join(alternate, ".git/objects/info"), { recursive: true });
      writeFileSync(join(alternate, ".git/objects/info/alternates"), `${join(outside, ".git/objects")}\n`);
      const limited = { ...config, allowedRoots: [dir] };
      const requested = {
        ...project,
        source_path: alternate,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      };
      await expect(importRepository({ config: limited, store }, requested, "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });

      const linked = join(dir, "objects-link");
      initRepo(linked, { "a.js": "INSIDE_CONTENT" });
      renameSync(join(linked, ".git/objects"), join(linked, ".git/objects-real"));
      symlinkSync(join(outside, ".git/objects"), join(linked, ".git/objects"));
      await expect(importRepository({ config: limited, store }, { ...requested, source_path: linked }, "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a subdirectory ref import archives only that subdirectory", async () => {
    const parent = join(dir, "mono");
    initRepo(parent, { "secret.js": "SECRET_PARENT_SENTINEL", "child/a.js": "CHILD_CONTENT" });
    const limited = { ...config, allowedRoots: [dir] };
    const child = join(parent, "child");
    const imported = await importRepository({
      config: limited,
      store,
    }, {
      ...project,
      source_path: child,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    }, "HEAD", "tester");
    expect(await Bun.file(join(imported.path, "a.js")).text()).toBe("CHILD_CONTENT");
    expect(existsSync(join(imported.path, "secret.js"))).toBe(false);

    mkdirSync(join(parent, ".git/objects/info"), { recursive: true });
    const outside = mkdtempSync(join(tmpdir(), "argus-git-parent-alt-"));
    try {
      initRepo(outside, { "hidden.js": "SECRET_PARENT_ALT" });
      writeFileSync(join(parent, ".git/objects/info/alternates"), `${join(outside, ".git/objects")}\n`);
      await expect(importRepository({
        config: limited,
        store,
      }, {
        ...project,
        source_path: child,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      }, "HEAD", "tester")).rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }

    const onlyChild = join(dir, "nested-parent", "child");
    initRepo(join(dir, "nested-parent"), { "secret.js": "SECRET_OUTSIDE_GIT", "child/a.js": "NESTED_CHILD" });
    await expect(importRepository({
      config: { ...config, allowedRoots: [onlyChild] },
      store,
    }, {
      ...project,
      source_path: onlyChild,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    }, "HEAD", "tester")).rejects.toMatchObject({ code: "invalid_repository", message: GIT_DIRECTORY_ERROR });
  });

  test("a pinned git directory ignores a symlink that replaces .git", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-git-swap-"));
    try {
      const source = join(dir, "pinned");
      initRepo(source, { "a.js": "INSIDE_CONTENT" });
      initRepo(outside, { "secret.js": "SECRET_GITDIR_SENTINEL" });
      const imported = await importRepository({
        config: { ...config, allowedRoots: [dir] },
        store,
      }, {
        ...project,
        source_path: source,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      }, "HEAD", "tester");
      expect(imported.commit_sha).toMatch(/^[0-9a-f]{40}$/);
      expect(await Bun.file(join(imported.path, "a.js")).text()).toBe("INSIDE_CONTENT");
      expect(existsSync(join(imported.path, "secret.js"))).toBe(false);
      const opened = await openWorktreeGit(source, [dir]);
      expect(opened.kind).toBe("pinned");
      if (opened.kind !== "pinned") return;
      try {
        renameSync(join(source, ".git"), join(source, ".git.bak"));
        symlinkSync(join(outside, ".git"), join(source, ".git"));
        const output = join(dir, "pinned.tar");
        const archived = await runPinnedGit(opened.git, ["archive", "--format=tar", "--output", output, "HEAD"], 20_000);
        expect(archived.code).toBe(0);
        const listed = new TextDecoder().decode(Bun.spawnSync(["tar", "-tf", output], { stdout: "pipe" }).stdout);
        expect(listed).toContain("a.js");
        expect(listed).not.toContain("secret.js");
      } finally {
        await opened.git.close();
      }
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects a common directory that points at another repository", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-git-common-"));
    const limited = { ...config, allowedRoots: [dir] };
    const requested = (source: string) => ({
      ...project,
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    });
    try {
      initRepo(outside, {
        "secret.js": "SECRET_COMMONDIR_SENTINEL\n",
        "child/secret.js": "SECRET_CHILD_COMMONDIR_SENTINEL\n",
      });
      const absolute = join(dir, "commondir-absolute");
      initRepo(absolute, { "local.js": "LOCAL_ONLY\n" });
      writeFileSync(join(absolute, ".git", "commondir"), `${join(outside, ".git")}\n`);
      const relativeRepo = join(dir, "commondir-relative");
      initRepo(relativeRepo, { "local.js": "LOCAL_ONLY\n" });
      writeFileSync(
        join(relativeRepo, ".git", "commondir"),
        `${relative(join(relativeRepo, ".git"), join(outside, ".git"))}\n`,
      );
      const parent = join(dir, "commondir-parent");
      const child = join(parent, "child");
      mkdirSync(child, { recursive: true });
      writeFileSync(join(child, "a.js"), "LOCAL_CHILD\n");
      gitExec(parent, ["init", "-q"]);
      writeFileSync(join(parent, ".git", "commondir"), `${join(outside, ".git")}\n`);

      const escaped = join(dir, "commondir-escape");
      initRepo(escaped, { "local.js": "LOCAL_ONLY\n" });
      mkdirSync(join(outside, ".git", "inner-decoy"), { recursive: true });
      symlinkSync(join(outside, ".git", "inner-decoy"), join(escaped, ".git", "escape"));
      writeFileSync(join(escaped, ".git", "commondir"), "escape/..\n");

      for (const source of [absolute, relativeRepo, child, escaped]) {
        await expect(importRepository({ config: limited, store }, requested(source), "HEAD", "tester"))
          .rejects.toMatchObject({ code: "invalid_repository", message: GIT_COMMON_DIR_ERROR });
      }
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
      expect(existsSync(join(dir, "repos"))).toBe(false);

      const fifo = join(dir, "commondir-fifo");
      initRepo(fifo, { "a.js": "LOCAL_ONLY\n" });
      rmSync(join(fifo, ".git", "commondir"), { force: true });
      const created = Bun.spawnSync(["mkfifo", join(fifo, ".git", "commondir")]);
      expect(created.exitCode).toBe(0);
      const started = Date.now();
      await expect(openWorktreeGit(fifo, [dir])).rejects.toMatchObject({
        code: "invalid_repository",
        message: GIT_COMMON_DIR_ERROR,
      });
      expect(Date.now() - started).toBeLessThan(1_000);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects a symlink inside the git object store", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-git-objects-link-"));
    const limited = { ...config, allowedRoots: [dir] };
    const requested = (source: string) => ({
      ...project,
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    });
    const removeLooseObjects = (source: string) => {
      const removed = Bun.spawnSync(["find", join(source, ".git", "objects"), "-type", "f", "-delete"]);
      expect(removed.exitCode).toBe(0);
    };
    try {
      initRepo(outside, {
        "secret.js": "SECRET_COMMONDIR_SENTINEL\n",
        "child/secret.js": "SECRET_CHILD_COMMONDIR_SENTINEL\n",
      });
      gitExec(outside, ["repack", "-ad"]);
      const outsideCommit = gitExec(outside, ["rev-parse", "HEAD"]);

      const packLink = join(dir, "pack-link");
      initRepo(packLink, { "local.js": "LOCAL_ONLY\n" });
      rmSync(join(packLink, ".git", "objects", "pack"), { recursive: true, force: true });
      symlinkSync(join(outside, ".git", "objects", "pack"), join(packLink, ".git", "objects", "pack"));
      removeLooseObjects(packLink);
      gitExec(packLink, ["update-ref", "HEAD", outsideCommit]);
      await expect(importRepository({ config: limited, store }, requested(packLink), "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });

      const packFile = join(dir, "pack-file");
      initRepo(packFile, { "local.js": "LOCAL_ONLY\n" });
      const packDir = join(outside, ".git", "objects", "pack");
      const packNames = readdirSync(packDir);
      expect(packNames.length).toBeGreaterThan(0);
      for (const name of packNames) {
        symlinkSync(join(packDir, name), join(packFile, ".git", "objects", "pack", name));
      }
      removeLooseObjects(packFile);
      gitExec(packFile, ["update-ref", "HEAD", outsideCommit]);
      await expect(importRepository({ config: limited, store }, requested(packFile), "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });

      const loose = join(dir, "loose-link");
      const looseOutside = join(outside, "loose-repo");
      initRepo(looseOutside, { "secret.js": "SECRET_LOOSE_SENTINEL\n" });
      const blob = gitExec(looseOutside, ["rev-parse", "HEAD:secret.js"]);
      initRepo(loose, { "local.js": "LOCAL_ONLY\n" });
      mkdirSync(join(loose, ".git", "objects", blob.slice(0, 2)), { recursive: true });
      symlinkSync(
        join(looseOutside, ".git", "objects", blob.slice(0, 2), blob.slice(2)),
        join(loose, ".git", "objects", blob.slice(0, 2), blob.slice(2)),
      );
      const tree = Bun.spawnSync(["git", "-C", loose, "mktree"], {
        stdin: Buffer.from(`100644 blob ${blob}\tsecret.js\n`),
        stdout: "pipe",
        stderr: "pipe",
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_AUTHOR_NAME: "t",
          GIT_AUTHOR_EMAIL: "t@example.com",
          GIT_COMMITTER_NAME: "t",
          GIT_COMMITTER_EMAIL: "t@example.com",
        },
      });
      expect(tree.exitCode).toBe(0);
      const commit = gitExec(loose, ["commit-tree", new TextDecoder().decode(tree.stdout).trim(), "-m", "leak"]);
      gitExec(loose, ["update-ref", "HEAD", commit]);
      await expect(importRepository({ config: limited, store }, requested(loose), "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });

      const fifo = join(dir, "object-fifo");
      initRepo(fifo, { "a.js": "LOCAL_ONLY\n" });
      const fifoBlob = gitExec(fifo, ["rev-parse", "HEAD:a.js"]);
      const fifoObject = join(fifo, ".git", "objects", fifoBlob.slice(0, 2), fifoBlob.slice(2));
      rmSync(fifoObject);
      expect(Bun.spawnSync(["mkfifo", fifoObject]).exitCode).toBe(0);
      const started = Date.now();
      await expect(openWorktreeGit(fifo, [dir])).rejects.toMatchObject({
        code: "invalid_repository",
        message: GIT_OBJECTS_ERROR,
      });
      expect(Date.now() - started).toBeLessThan(1_000);
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects an alternate object directory git would resolve outside the root", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-git-alt-escape-"));
    const limited = { ...config, allowedRoots: [dir] };
    const requested = (source: string) => ({
      ...project,
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    });
    const archiveNames = (directory: string): string => {
      const archived = Bun.spawnSync(["git", "-C", directory, "archive", "--format=tar", "HEAD"], {
        stdout: "pipe",
        stderr: "pipe",
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "/dev/null",
        },
      });
      expect(archived.exitCode).toBe(0);
      return new TextDecoder().decode(Bun.spawnSync(["tar", "-t"], {
        stdin: archived.stdout,
        stdout: "pipe",
      }).stdout);
    };
    try {
      const outsideRepo = join(outside, "alt");
      initRepo(outsideRepo, { "secret.js": "SECRET_OBJECT_SENTINEL\n" });
      gitExec(outsideRepo, ["repack", "-ad"]);
      const outsideCommit = gitExec(outsideRepo, ["rev-parse", "HEAD"]);
      mkdirSync(join(outside, "decoy"), { recursive: true });
      symlinkSync(join(outside, "decoy"), join(dir, "escape"));
      mkdirSync(join(dir, "alt/.git/objects"), { recursive: true });

      const dotdot = join(dir, "dotdot-repo");
      initRepo(dotdot, { "local.js": "LOCAL_ONLY\n" });
      mkdirSync(join(dotdot, ".git/objects/info"), { recursive: true });
      writeFileSync(join(dotdot, ".git/objects/info/alternates"), "../../../escape/../alt/.git/objects\n");
      gitExec(dotdot, ["update-ref", "HEAD", outsideCommit]);
      expect(archiveNames(dotdot)).toContain("secret.js");

      const nested = join(dir, "nested-repo");
      initRepo(nested, { "local.js": "LOCAL_ONLY\n" });
      const bridge = join(dir, "bridge-objects");
      mkdirSync(join(bridge, "info"), { recursive: true });
      writeFileSync(join(bridge, "info/alternates"), `${join(outsideRepo, ".git/objects")}\n`);
      mkdirSync(join(nested, ".git/objects/info"), { recursive: true });
      writeFileSync(join(nested, ".git/objects/info/alternates"), `${bridge}\n`);
      gitExec(nested, ["update-ref", "HEAD", outsideCommit]);
      expect(archiveNames(nested)).toContain("secret.js");

      const linked = join(dir, "linked-alt-repo");
      initRepo(linked, { "local.js": "LOCAL_ONLY\n" });
      const inner = join(dir, "inner-objects");
      mkdirSync(join(inner, "info"), { recursive: true });
      symlinkSync(join(outsideRepo, ".git/objects/pack"), join(inner, "pack"));
      mkdirSync(join(linked, ".git/objects/info"), { recursive: true });
      writeFileSync(join(linked, ".git/objects/info/alternates"), `${inner}\n`);
      gitExec(linked, ["update-ref", "HEAD", outsideCommit]);
      expect(archiveNames(linked)).toContain("secret.js");

      const quoted = join(dir, "quoted-repo");
      initRepo(quoted, { "local.js": "LOCAL_ONLY\n" });
      mkdirSync(join(quoted, ".git/objects/info"), { recursive: true });
      writeFileSync(
        join(quoted, ".git/objects/info/alternates"),
        `"${join(outsideRepo, ".git/objects")}"\n`,
      );
      gitExec(quoted, ["update-ref", "HEAD", outsideCommit]);
      expect(archiveNames(quoted)).toContain("secret.js");

      const raw = join(dir, "raw-byte-repo");
      initRepo(raw, { "local.js": "LOCAL_ONLY\n" });
      symlinkSync(join(outside, "decoy"), Buffer.concat([Buffer.from(dir), Buffer.from("/"), Buffer.from([0xff])]));
      mkdirSync(join(raw, ".git/objects/info"), { recursive: true });
      writeFileSync(
        join(raw, ".git/objects/info/alternates"),
        Buffer.concat([Buffer.from("../../../"), Buffer.from([0xff]), Buffer.from("/../alt/.git/objects\n")]),
      );
      gitExec(raw, ["update-ref", "HEAD", outsideCommit]);
      expect(archiveNames(raw)).toContain("secret.js");

      const crlf = join(dir, "crlf-repo");
      initRepo(crlf, { "local.js": "LOCAL_ONLY\n" });
      mkdirSync(join(crlf, ".git/objects/inside"), { recursive: true });
      symlinkSync(join(outsideRepo, ".git/objects"), join(crlf, ".git/objects/inside\r"));
      mkdirSync(join(crlf, ".git/objects/info"), { recursive: true });
      writeFileSync(join(crlf, ".git/objects/info/alternates"), "inside\r\n");
      gitExec(crlf, ["update-ref", "HEAD", outsideCommit]);
      expect(archiveNames(crlf)).toContain("secret.js");

      const spaced = join(dir, "space-repo");
      initRepo(spaced, { "local.js": "LOCAL_ONLY\n" });
      mkdirSync(join(spaced, ".git/objects/inside"), { recursive: true });
      symlinkSync(join(outsideRepo, ".git/objects"), join(spaced, ".git/objects/inside "));
      mkdirSync(join(spaced, ".git/objects/info"), { recursive: true });
      writeFileSync(join(spaced, ".git/objects/info/alternates"), "inside \n");
      gitExec(spaced, ["update-ref", "HEAD", outsideCommit]);
      expect(archiveNames(spaced)).toContain("secret.js");

      for (const source of [dotdot, nested, linked, quoted, raw, crlf, spaced]) {
        await expect(importRepository({ config: limited, store }, requested(source), "HEAD", "tester"))
          .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });
      }
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
      expect(existsSync(join(dir, "repos"))).toBe(false);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects an alternate that names a process-local path", async () => {
    const fdPrefix = existsSync("/proc/self/fd") ? "/proc/self/fd" : "/dev/fd";
    const outsideRepo = mkdtempSync(join(tmpdir(), "argus-proc-src-"));
    const outsideName = `argus-proc-objects-${crypto.randomUUID().slice(0, 8)}`;
    const outsideObjects = join(tmpdir(), outsideName);
    const limited = { ...config, allowedRoots: [dir] };
    const requested = {
      ...project,
      source_path: join(dir, "proc-repo"),
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    };
    let swappedFd = -1;
    try {
      initRepo(outsideRepo, { "secret.js": "SECRET_PROC_SENTINEL\n" });
      cpSync(join(outsideRepo, ".git/objects"), outsideObjects, { recursive: true });
      const repo = requested.source_path;
      initRepo(repo, { "a.js": "INSIDE_CONTENT\n" });
      const deep = join(dir, "deep/a/b/c/d");
      mkdirSync(join(deep, "objects"), { recursive: true });
      mkdirSync(join(dir, "deep/a", outsideName), { recursive: true });
      mkdirSync(join(repo, ".git/objects/info"), { recursive: true });
      const fdLine = `${fdPrefix}/3/objects/../../../../${outsideName}`;
      writeFileSync(join(repo, ".git/objects/info/alternates"), `${fdLine}\n`);
      pointBranch(repo, gitExec(outsideRepo, ["rev-parse", "HEAD"]));
      const gitDir = await open(join(repo, ".git"), "r");
      try {
        const tarPath = join(dir, "proc.tar");
        const archived = await runPinnedGit({
          fd: gitDir.fd,
          path: join(repo, ".git"),
          close: async () => {},
        }, ["archive", "--format=tar", "--output", tarPath, "HEAD"], 20_000);
        expect(archived.code).toBe(0);
        const listed = new TextDecoder().decode(Bun.spawnSync(["tar", "-tf", tarPath], { stdout: "pipe" }).stdout);
        expect(listed).toContain("secret.js");
      } finally {
        await gitDir.close();
      }

      closeSync(3);
      swappedFd = openSync(deep, "r");
      expect(swappedFd).toBe(3);
      await expect(importRepository({ config: limited, store }, requested, "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });

      const link = join(dir, "to-proc");
      symlinkSync(fdLine, link);
      writeFileSync(join(repo, ".git/objects/info/alternates"), `${link}\n`);
      await expect(importRepository({ config: limited, store }, requested, "HEAD", "tester"))
        .rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
    } finally {
      if (swappedFd >= 0) {
        try { closeSync(swappedFd); } catch { /* already closed */ }
        const restored = openSync("/dev/urandom", "r");
        if (restored !== 3) closeSync(restored);
      }
      rmSync(outsideRepo, { recursive: true, force: true });
      rmSync(outsideObjects, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects an alternate resolved through /proc/self/exe", async () => {
    if (!existsSync("/proc/self/exe")) {
      expect(process.platform).not.toBe("linux");
      return;
    }
    const gitBin = Bun.which("git");
    if (!gitBin) throw new Error("git is required");
    const exeParts = (path: string): string[] => path.split("/").filter((part) => part.length > 0);
    const bunParts = exeParts(readlinkSync("/proc/self/exe").toString());
    const gitParts = exeParts(realpathSync(gitBin));
    const outsideName = `argus-exe-objects-${crypto.randomUUID().slice(0, 8)}`;
    const suffix = [...realpathSync(tmpdir()).split("/").filter((part) => part.length > 0), outsideName, "objects"];
    const landed = (parts: string[], ups: number): string => {
      const kept = parts.slice(0, Math.max(0, parts.length - ups));
      return `/${[...kept, ...suffix].join("/")}`;
    };
    let chosen: { ups: number; server: string; git: string } | null = null;
    for (let ups = 1; ups <= Math.max(bunParts.length, gitParts.length); ups += 1) {
      const server = landed(bunParts, ups);
      const git = landed(gitParts, ups);
      const allowed = dirname(server);
      if (server === git || allowed === "/" || git.startsWith(`${allowed}/`)) continue;
      if (!git.startsWith(`${realpathSync(tmpdir())}/`)) continue;
      chosen = { ups, server, git };
      break;
    }
    if (!chosen) throw new Error("could not separate /proc/self/exe for git and the server");
    const allowed = dirname(chosen.server);
    const outsideRepo = join(dir, "exe-outside-src");
    const repo = join(allowed, "repo");
    try {
      initRepo(outsideRepo, { "secret.js": "SECRET_EXE_SENTINEL\n" });
      mkdirSync(dirname(chosen.git), { recursive: true });
      cpSync(join(outsideRepo, ".git/objects"), chosen.git, { recursive: true });
      mkdirSync(chosen.server, { recursive: true });
      initRepo(repo, { "a.js": "LOCAL_ONLY\n" });
      mkdirSync(join(repo, ".git/objects/info"), { recursive: true });
      const procLine = `/proc/self/exe/${"../".repeat(chosen.ups)}${suffix.join("/")}`;
      writeFileSync(join(repo, ".git/objects/info/alternates"), `${procLine}\n`);
      pointBranch(repo, gitExec(outsideRepo, ["rev-parse", "HEAD"]));
      const gitDir = await open(join(repo, ".git"), "r");
      try {
        const tarPath = join(dir, "exe.tar");
        const archived = await runPinnedGit({
          fd: gitDir.fd,
          path: join(repo, ".git"),
          close: async () => {},
        }, ["archive", "--format=tar", "--output", tarPath, "HEAD"], 20_000);
        expect(archived.code).toBe(0);
        const listed = new TextDecoder().decode(Bun.spawnSync(["tar", "-tf", tarPath], { stdout: "pipe" }).stdout);
        expect(listed).toContain("secret.js");
      } finally {
        await gitDir.close();
      }
      await expect(importRepository({
        config: { ...config, allowedRoots: [allowed] },
        store,
      }, {
        ...project,
        source_path: repo,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      }, "HEAD", "tester")).rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });

      const link = join(allowed, "to-exe");
      symlinkSync(procLine, link);
      writeFileSync(join(repo, ".git/objects/info/alternates"), `${link}\n`);
      await expect(importRepository({
        config: { ...config, allowedRoots: [allowed] },
        store,
      }, {
        ...project,
        source_path: repo,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      }, "HEAD", "tester")).rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
    } finally {
      if (allowed.includes(outsideName)) rmSync(allowed, { recursive: true, force: true });
      const gitRoot = dirname(chosen.git);
      if (gitRoot.includes(outsideName)) rmSync(gitRoot, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects a multi-pack-index that names an outside pack", async () => {
    const outside = mkdtempSync(join(tmpdir(), "ao-"));
    const limited = { ...config, allowedRoots: [dir] };
    const source = join(dir, "midx-repo");
    try {
      initRepo(join(outside, "alt"), { "secret.js": "SECRET_MIDX_SENTINEL\n" });
      gitExec(join(outside, "alt"), ["repack", "-ad"]);
      const outsideCommit = gitExec(join(outside, "alt"), ["rev-parse", "HEAD"]);
      const outsidePack = join(outside, "alt/.git/objects/pack");
      const idxName = readdirSync(outsidePack).find((name) => name.endsWith(".idx"));
      expect(idxName).toBeTruthy();
      if (!idxName) return;
      const packBytes = Bun.file(join(outsidePack, idxName.replace(/idx$/, "pack")));
      const idxBytes = Bun.file(join(outsidePack, idxName));
      initRepo(source, { "local.js": "LOCAL_ONLY\n" });
      const localPack = join(source, ".git/objects/pack");
      mkdirSync(localPack, { recursive: true });
      writeFileSync(join(localPack, idxName), Buffer.from(await idxBytes.arrayBuffer()));
      writeFileSync(join(localPack, idxName.replace(/idx$/, "pack")), Buffer.from(await packBytes.arrayBuffer()));
      gitExec(source, ["multi-pack-index", "write"]);
      const prefix = `${relative(localPack, outside)}/`;
      const stemLength = idxName.length - prefix.length - ".idx".length;
      expect(stemLength).toBeGreaterThan(0);
      const escapedName = `${prefix}${"a".repeat(stemLength)}.idx`;
      expect(escapedName).toHaveLength(idxName.length);
      const escapedPack = escapedName.replace(/idx$/, "pack");
      const targetIdx = resolve(localPack, escapedName);
      expect(targetIdx.startsWith(`${dir}/`)).toBe(false);
      mkdirSync(join(targetIdx, ".."), { recursive: true });
      writeFileSync(targetIdx, Buffer.from(await idxBytes.arrayBuffer()));
      writeFileSync(resolve(localPack, escapedPack), Buffer.from(await packBytes.arrayBuffer()));
      rmSync(join(localPack, idxName));
      rmSync(join(localPack, idxName.replace(/idx$/, "pack")));
      const midxPath = join(localPack, "multi-pack-index");
      const midx = Buffer.from(await Bun.file(midxPath).arrayBuffer());
      const nameAt = midx.indexOf(idxName);
      expect(nameAt).toBeGreaterThanOrEqual(0);
      midx.set(Buffer.from(escapedName), nameAt);
      writeFileSync(midxPath, midx);
      gitExec(source, ["update-ref", "HEAD", outsideCommit]);
      const archived = Bun.spawnSync(["git", "-C", source, "archive", "--format=tar", "HEAD"], {
        stdout: "pipe",
        stderr: "pipe",
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
      });
      expect(archived.exitCode).toBe(0);
      const listing = new TextDecoder().decode(Bun.spawnSync(["tar", "-t"], { stdin: archived.stdout, stdout: "pipe" }).stdout);
      expect(listing).toContain("secret.js");
      await expect(importRepository({
        config: limited,
        store,
      }, {
        ...project,
        source_path: source,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      }, "HEAD", "tester")).rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects a pack symlink whose bytes are not valid UTF-8", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-ff-pack-"));
    const limited = { ...config, allowedRoots: [dir] };
    const source = join(dir, "ff-repo");
    try {
      initRepo(outside, { "secret.js": "SECRET_FF_SENTINEL\n" });
      gitExec(outside, ["repack", "-ad"]);
      const outsideCommit = gitExec(outside, ["rev-parse", "HEAD"]);
      const outsidePack = join(outside, ".git/objects/pack");
      const idxName = readdirSync(outsidePack).find((name) => name.endsWith(".idx"));
      expect(idxName).toBeTruthy();
      if (!idxName) return;
      initRepo(source, { "local.js": "LOCAL_ONLY\n" });
      const localPack = join(source, ".git/objects/pack");
      mkdirSync(localPack, { recursive: true });
      const entry = (name: Buffer) => Buffer.concat([Buffer.from(`${localPack}/`), name]);
      const replacement = Buffer.from([0xef, 0xbf, 0xbd]);
      const raw = Buffer.from([0xff]);
      writeFileSync(entry(Buffer.concat([replacement, Buffer.from(".idx")])), "decoy");
      writeFileSync(entry(Buffer.concat([replacement, Buffer.from(".pack")])), "decoy");
      symlinkSync(join(outsidePack, idxName), entry(Buffer.concat([raw, Buffer.from(".idx")])));
      symlinkSync(join(outsidePack, idxName.replace(/idx$/, "pack")), entry(Buffer.concat([raw, Buffer.from(".pack")])));
      gitExec(source, ["update-ref", "HEAD", outsideCommit]);
      const archived = Bun.spawnSync(["git", "-C", source, "archive", "--format=tar", "HEAD"], {
        stdout: "pipe",
        stderr: "pipe",
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
      });
      expect(archived.exitCode).toBe(0);
      const listing = new TextDecoder().decode(Bun.spawnSync(["tar", "-t"], { stdin: archived.stdout, stdout: "pipe" }).stdout);
      expect(listing).toContain("secret.js");
      await expect(importRepository({
        config: limited,
        store,
      }, {
        ...project,
        source_path: source,
        scope_include: JSON.stringify(["**/*"]),
        scope_exclude: "[]",
      }, "HEAD", "tester")).rejects.toMatchObject({ code: "invalid_repository", message: GIT_OBJECTS_ERROR });
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import accepts a multi-pack-index that names its own packs", async () => {
    const limited = { ...config, allowedRoots: [dir] };
    const source = join(dir, "midx-local");
    initRepo(source, { "keep.js": "KEEP_MIDX\n" });
    gitExec(source, ["repack", "-ad"]);
    gitExec(source, ["multi-pack-index", "write"]);
    const imported = await importRepository({
      config: limited,
      store,
    }, {
      ...project,
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    }, "HEAD", "tester");
    expect(await Bun.file(join(imported.path, "keep.js")).text()).toBe("KEEP_MIDX\n");
    expect(existsSync(join(imported.path, "secret.js"))).toBe(false);
  });

  test("a git ref import accepts an alternate object directory inside the allowed root", async () => {
    const limited = { ...config, allowedRoots: [dir] };
    const source = join(dir, "inside-alt-repo");
    initRepo(source, { "keep.js": "KEEP\n" });
    initRepo(join(dir, "inside-alt"), { "other.js": "OTHER\n" });
    mkdirSync(join(source, ".git/objects/info"), { recursive: true });
    writeFileSync(
      join(source, ".git/objects/info/alternates"),
      "# ignored comment\n../../../inside-alt/.git/objects\n",
    );
    const imported = await importRepository({
      config: limited,
      store,
    }, {
      ...project,
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    }, "HEAD", "tester");
    expect(await Bun.file(join(imported.path, "keep.js")).text()).toBe("KEEP\n");
    expect(existsSync(join(imported.path, "other.js"))).toBe(false);
    expect(existsSync(join(imported.path, "secret.js"))).toBe(false);

    const absoluteSource = join(dir, "inside-abs-repo");
    initRepo(absoluteSource, { "keep.js": "KEEP_ABS\n" });
    mkdirSync(join(absoluteSource, ".git/objects/info"), { recursive: true });
    writeFileSync(
      join(absoluteSource, ".git/objects/info/alternates"),
      `${join(dir, "inside-alt/.git/objects")}\n`,
    );
    const importedAbsolute = await importRepository({
      config: limited,
      store,
    }, {
      ...project,
      source_path: absoluteSource,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    }, "HEAD", "tester");
    expect(await Bun.file(join(importedAbsolute.path, "keep.js")).text()).toBe("KEEP_ABS\n");
  });

  test("a git ref import accepts a common directory that names its own git directory", async () => {
    const limited = { ...config, allowedRoots: [dir] };
    const requested = (source: string) => ({
      ...project,
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: "[]",
    });
    const dot = join(dir, "commondir-dot");
    initRepo(dot, { "a.js": "LOCAL_DOT\n" });
    writeFileSync(join(dot, ".git", "commondir"), ".\n");
    const importedDot = await importRepository({ config: limited, store }, requested(dot), "HEAD", "tester");
    expect(await Bun.file(join(importedDot.path, "a.js")).text()).toBe("LOCAL_DOT\n");
    expect(existsSync(join(importedDot.path, "secret.js"))).toBe(false);

    const absolute = join(dir, "commondir-self");
    initRepo(absolute, { "a.js": "LOCAL_ABS\n" });
    writeFileSync(join(absolute, ".git", "commondir"), `${realpathSync(join(absolute, ".git"))}\n`);
    const importedAbsolute = await importRepository({ config: limited, store }, requested(absolute), "HEAD", "tester");
    expect(await Bun.file(join(importedAbsolute.path, "a.js")).text()).toBe("LOCAL_ABS\n");

    const dotSlash = join(dir, "commondir-dot-slash");
    initRepo(dotSlash, { "a.js": "LOCAL_DOT_SLASH\n" });
    writeFileSync(join(dotSlash, ".git", "commondir"), "./\n");
    const importedDotSlash = await importRepository({ config: limited, store }, requested(dotSlash), "HEAD", "tester");
    expect(await Bun.file(join(importedDotSlash.path, "a.js")).text()).toBe("LOCAL_DOT_SLASH\n");

    const main = join(dir, "worktree-main");
    initRepo(main, { "a.js": "MAIN_FILE\n" });
    gitExec(main, ["worktree", "add", "--detach", "-q", join(dir, "worktree-linked")]);
    const importedMain = await importRepository({ config: limited, store }, requested(main), "HEAD", "tester");
    expect(await Bun.file(join(importedMain.path, "a.js")).text()).toBe("MAIN_FILE\n");
    expect(importedMain.commit_sha).toMatch(/^[0-9a-f]{40}$/);
  });

  test("a git ref import does not wait on a configured excludes or attributes fifo", async () => {
    const source = join(dir, "fifo-config");
    mkdirSync(source, { recursive: true });
    const env = {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.com",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.com",
    };
    const git = (args: string[]) => {
      const result = Bun.spawnSync(["git", "-C", source, ...args], { env });
      if (result.exitCode !== 0) throw new Error(new TextDecoder().decode(result.stderr));
    };
    git(["init", "-q", "-b", "main"]);
    writeFileSync(join(source, "a.js"), "FIFO_CONFIG_OK\n");
    git(["add", "a.js"]);
    git(["commit", "-q", "-m", "init"]);
    const fifo = join(dir, "config-fifo");
    expect(Bun.spawnSync(["mkfifo", fifo]).exitCode).toBe(0);
    git(["config", "core.excludesFile", fifo]);
    git(["config", "core.attributesFile", fifo]);
    const started = Date.now();
    const imported = await importRepository(
      { config, store },
      { ...project, source_path: source, scope_include: JSON.stringify(["**/*"]), scope_exclude: "[]" },
      "HEAD",
      "tester",
    );
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(await Bun.file(join(imported.path, "a.js")).text()).toBe("FIFO_CONFIG_OK\n");
    expect(imported.commit_sha).toMatch(/^[0-9a-f]{40}$/);
  });
});

describe("evidence chain", () => {
  let dir = "";
  let store: Store;
  let evidence: EvidenceStore;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "argus-evidence-"));
    store = new Store(testConfig(dir), "test.sqlite");
    evidence = new EvidenceStore(testConfig(dir), store);
    store.run(
      "INSERT INTO users (id, email, name, password_hash, role, disabled, created_at) VALUES ('u1','a@b.c','T','x','admin',0,'2026-01-01')",
    );
    store.run(
      "INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at) VALUES ('p1','P','','/tmp','[]','[]','T','R','2026-01-01','2026-01-01')",
    );
    store.run(
      "INSERT INTO repositories (id, project_id, path, commit_sha, branch, languages, frameworks, inventory, graph, file_count, total_bytes, imported_at) VALUES ('r1','p1','/tmp',NULL,NULL,'{}','[]','{}','{}',0,0,'2026-01-01')",
    );
    store.run(
      "INSERT INTO audits (id, project_id, repository_id, status, current_phase, config, created_at) VALUES ('a1','p1','r1','running',1,'{}','2026-01-01')",
    );
    for (let phase = 1; phase <= 6; phase += 1) {
      store.run(
        "INSERT INTO audit_phases (audit_id, phase, name, status) VALUES ('a1', ?, ?, 'pending')",
        phase,
        PHASE_NAMES[phase - 1],
      );
    }
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("appends a verifiable hash chain and detects file tampering", async () => {
    await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    const second = await evidence.append({ auditId: "a1", kind: "agent_transcript", title: "two", content: { text: "beta" } });
    await evidence.append({ auditId: "a1", kind: "verification_result", title: "three", content: "gamma" });
    const verified = await evidence.verifyChain("a1");
    expect(verified.ok).toBe(true);
    expect(verified.count).toBe(3);
    await Bun.write(second.content_path, JSON.stringify({ content: "tampered", chain_hash: second.chain_hash }));
    const broken = await evidence.verifyChain("a1");
    expect(broken.ok).toBe(false);
    expect(broken.broken_at).toBe(second.id);
  });

  test("evidence table is append-only at the database layer", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    expect(() => store.run("UPDATE evidence SET title = 'changed' WHERE id = ?", row.id)).toThrow();
    expect(() => store.run("DELETE FROM evidence WHERE id = ?", row.id)).toThrow();
  });

  test("evidence content fails closed when the sidecar does not match the database record", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    expect((await evidence.content(row.id))?.content).toBe("alpha");
    const parsed = await Bun.file(row.content_path).json() as { content?: string };
    parsed.content = "alphb";
    await Bun.write(row.content_path, `${JSON.stringify(parsed, null, 2)}\n`);
    await expect(evidence.content(row.id)).rejects.toMatchObject({ status: 409, code: "conflict" });
    const broken = await evidence.verifyChain("a1");
    expect(broken).toMatchObject({
      ok: false,
      broken_at: row.id,
      reason: "Evidence file content hash does not match the database record",
    });
  });

  test("evidence content rejects a symlink that replaces the sidecar", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    const target = join(dir, "replacement.txt");
    writeFileSync(target, "alpha");
    rmSync(row.content_path);
    symlinkSync(target, row.content_path);
    await expect(evidence.content(row.id)).rejects.toMatchObject({ status: 409, code: "conflict" });
    expect((await evidence.verifyChain("a1")).ok).toBe(false);
  });

  test("evidence content rejects a symlink even when the target copies the sidecar", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    const target = join(dir, "sidecar-copy.json");
    await Bun.write(target, await Bun.file(row.content_path).arrayBuffer());
    rmSync(row.content_path);
    symlinkSync(target, row.content_path);
    await expect(evidence.content(row.id)).rejects.toMatchObject({ status: 409, code: "conflict" });
    expect((await evidence.verifyChain("a1")).ok).toBe(false);
  });

  test("evidence content rejects a named pipe without waiting for a writer", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    rmSync(row.content_path);
    const made = Bun.spawnSync(["mkfifo", row.content_path]);
    expect(made.exitCode).toBe(0);
    await expect(evidence.content(row.id)).rejects.toMatchObject({ status: 409, code: "conflict" });
    expect(await evidence.verifyChain("a1")).toMatchObject({
      ok: false,
      broken_at: row.id,
      reason: "Evidence file is missing or unreadable",
    });
  });

  test("evidence content accepts a JSON-escaped sidecar larger than the recorded text plus one megabyte", async () => {
    const content = "\u0001".repeat(210_000);
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "controls", content });
    expect(Bun.file(row.content_path).size - row.size).toBeGreaterThan(1_000_000);
    expect((await evidence.content(row.id))?.content).toBe(content);
    expect((await evidence.verifyChain("a1")).ok).toBe(true);
  });

  test("evidence content reads only the size it checked when the sidecar grows", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    const before = (await stat(row.content_path)).size;
    const probe = await open(row.content_path, "r");
    const proto = Object.getPrototypeOf(probe) as {
      stat: (this: unknown, ...args: unknown[]) => Promise<{ isFile: () => boolean; size: number }>;
      read: (
        this: unknown,
        buffer: Buffer,
        offset?: number,
        length?: number,
        position?: number | null,
      ) => Promise<{ bytesRead: number }>;
      readFile: (this: unknown, ...args: unknown[]) => Promise<unknown>;
    };
    await probe.close();
    const originalStat = proto.stat;
    const originalRead = proto.read;
    const originalReadFile = proto.readFile;
    let readFileCalls = 0;
    let bytesRequested = 0;
    proto.stat = async function (this: unknown, ...args: unknown[]) {
      const info = await originalStat.apply(this, args);
      const size = info.size;
      const file = info.isFile();
      if (file && size === before) writeFileSync(row.content_path, "Q".repeat(1024 * 1024));
      return { isFile: () => file, size };
    };
    proto.read = async function (
      this: unknown,
      buffer: Buffer,
      offset?: number,
      length?: number,
      position?: number | null,
    ) {
      if (length === undefined || length > before) {
        throw new Error(`unbounded evidence read of ${String(length)} bytes`);
      }
      bytesRequested += length;
      return originalRead.call(this, buffer, offset, length, position);
    };
    proto.readFile = async function (this: unknown, ...args: unknown[]) {
      readFileCalls += 1;
      return originalReadFile.apply(this, args);
    };
    try {
      await expect(evidence.content(row.id)).rejects.toMatchObject({ status: 409, code: "conflict" });
      expect(readFileCalls).toBe(0);
      expect(bytesRequested).toBeGreaterThan(0);
      expect(bytesRequested).toBeLessThanOrEqual(before);
    } finally {
      proto.stat = originalStat;
      proto.read = originalRead;
      proto.readFile = originalReadFile;
    }
  });

  test("evidence content rejects a sidecar larger than the recorded content can encode", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "one", content: "alpha" });
    await Bun.write(row.content_path, "x".repeat(64 * 1024));
    await expect(evidence.content(row.id)).rejects.toMatchObject({ status: 409, code: "conflict" });
    const broken = await evidence.verifyChain("a1");
    expect(broken).toMatchObject({
      ok: false,
      broken_at: row.id,
      reason: "Evidence file is larger than the recorded content",
    });
  });

  test("reports omit a code excerpt whose sidecar does not match the database record", async () => {
    store.run(
      `INSERT INTO findings (
        id, code, audit_id, project_id, title, category, severity, status, files, root_cause,
        preconditions, reproduction, expected, observed, impact, remediation, created_at, updated_at
      ) VALUES (
        'f-report', 'ARG-1', 'a1', 'p1', 'Tampered excerpt', 'injection', 'high', 'reverified', '[]',
        'cause', '[]', '[]', 'expected', 'observed', 'impact', 'fix', '2026-01-01', '2026-01-01'
      )`,
    );
    await evidence.append({
      auditId: "a1",
      findingId: "f-report",
      kind: "code_excerpt",
      title: "src/ok.js:1-1",
      content: { path: "src/ok.js", start_line: 1, end_line: 1, quote: "intact quote stays" },
    });
    const tampered = await evidence.append({
      auditId: "a1",
      findingId: "f-report",
      kind: "code_excerpt",
      title: "src/bad.js:2-2",
      content: { path: "src/bad.js", start_line: 2, end_line: 2, quote: "original quote" },
    });
    const parsed = await Bun.file(tampered.content_path).json() as { content?: string };
    parsed.content = JSON.stringify(
      { path: "src/bad.js", start_line: 2, end_line: 2, quote: "TAMPERED_QUOTE_SENTINEL" },
      null,
      2,
    );
    await Bun.write(tampered.content_path, `${JSON.stringify(parsed, null, 2)}\n`);
    const generated = await new ReportService(testConfig(dir), store, evidence, new EventLog(store)).generate(
      "a1",
      ["markdown", "json"],
      "test",
    );
    const jsonReport = generated.find((report) => report.format === "json");
    expect(jsonReport).toBeTruthy();
    const body = JSON.parse(await Bun.file(jsonReport!.path).text()) as {
      evidence_chain: { ok: boolean };
      findings: Array<{ verified_excerpts: Array<{ quote: string }> }>;
    };
    expect(body.evidence_chain.ok).toBe(false);
    expect(body.findings[0]?.verified_excerpts.map((excerpt) => excerpt.quote)).toEqual(["intact quote stays"]);
    for (const report of generated) {
      const text = await Bun.file(report.path).text();
      expect(text).toContain("intact quote stays");
      expect(text).not.toContain("TAMPERED_QUOTE_SENTINEL");
      expect(text).not.toContain("original quote");
    }
  });

  test("reports still generate when a code excerpt is not structured JSON", async () => {
    store.run(
      `INSERT INTO findings (
        id, code, audit_id, project_id, title, category, severity, status, files, root_cause,
        preconditions, reproduction, expected, observed, impact, remediation, created_at, updated_at
      ) VALUES (
        'f-plain', 'ARG-2', 'a1', 'p1', 'Plain excerpt', 'injection', 'low', 'reverified', '[]',
        'cause', '[]', '[]', 'expected', 'observed', 'impact', 'fix', '2026-01-01', '2026-01-01'
      )`,
    );
    await evidence.append({
      auditId: "a1",
      findingId: "f-plain",
      kind: "code_excerpt",
      title: "note",
      content: "not a structured excerpt",
    });
    const generated = await new ReportService(testConfig(dir), store, evidence, new EventLog(store)).generate(
      "a1",
      ["markdown", "json"],
      "test",
    );
    expect(generated).toHaveLength(2);
    const body = JSON.parse(await Bun.file(generated.find((report) => report.format === "json")!.path).text()) as {
      evidence_chain: { ok: boolean };
      findings: Array<{ verified_excerpts: unknown[] }>;
    };
    expect(body.evidence_chain.ok).toBe(true);
    expect(body.findings[0]?.verified_excerpts).toEqual([]);
  });

  test("evidence content preserves structured excerpts for later parsing", async () => {
    const row = await evidence.append({
      auditId: "a1",
      kind: "code_excerpt",
      title: "src/a:b.js:1-2",
      content: { path: "src/a:b.js", start_line: 1, end_line: 2, quote: "const secret = 1;" },
    });
    const loaded = await evidence.content(row.id);
    expect(JSON.parse(loaded?.content ?? "")).toMatchObject({
      path: "src/a:b.js",
      start_line: 1,
      end_line: 2,
      quote: "const secret = 1;",
    });
  });

  test("evidence verification detects sidecar metadata tampering", async () => {
    const row = await evidence.append({ auditId: "a1", kind: "agent_prompt", title: "original", content: "alpha" });
    const parsed = await Bun.file(row.content_path).json();
    parsed.title = "tampered";
    await Bun.write(row.content_path, `${JSON.stringify(parsed, null, 2)}\n`);
    const broken = await evidence.verifyChain("a1");
    expect(broken).toMatchObject({
      ok: false,
      broken_at: row.id,
      reason: "Evidence file metadata does not match the database record",
    });
  });

  test("concurrent appends preserve every link in the audit chain", async () => {
    const rows = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        evidence.append({ auditId: "a1", kind: "agent_transcript", title: `entry-${index}`, content: `content-${index}` }),
      ),
    );
    expect((await evidence.verifyChain("a1")).ok).toBe(true);
    expect(evidence.listForAudit("a1").map((row) => row.id)).toEqual(rows.map((row) => row.id));
    expect(new Set(rows.map((row) => row.prev_hash)).size).toBe(rows.length);
  });
});

describe("keyed serial queue", () => {
  test("preserves FIFO order per key without blocking other keys", async () => {
    const queue = new KeyedSerialQueue();
    const calls: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const first = queue.run("a", async () => {
      calls.push("a:first");
      await gate;
      return 1;
    });
    const second = queue.run("a", () => {
      calls.push("a:second");
      return 2;
    });
    expect(await queue.run("b", () => "independent")).toBe("independent");
    expect(calls).toEqual(["a:first"]);
    expect(queue.size).toBe(1);
    release();
    expect(await Promise.all([first, second])).toEqual([1, 2]);
    expect(calls).toEqual(["a:first", "a:second"]);
    expect(queue.size).toBe(0);
  });

  test("propagates failures and continues queued work on the same key", async () => {
    const queue = new KeyedSerialQueue();
    const failure = new Error("operation failed");
    const rejected = queue.run("a", async () => { throw failure; });
    const recovered = queue.run("a", () => 42);
    await expect(rejected).rejects.toBe(failure);
    expect(await recovered).toBe(42);
    expect(queue.size).toBe(0);

    await expect(queue.run("a", () => { throw failure; })).rejects.toBe(failure);
    expect(queue.size).toBe(0);
    expect(await queue.run("a", () => "reused")).toBe("reused");
  });

  test("finishing an earlier operation keeps the key locked for queued successors", async () => {
    const queue = new KeyedSerialQueue();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const first = queue.run("a", () => "first");
    const second = queue.run("a", () => gate);
    await first;
    let thirdStarted = false;
    const third = queue.run("a", () => { thirdStarted = true; });
    await queue.run("b", () => undefined);
    expect(thirdStarted).toBe(false);
    expect(queue.size).toBe(1);
    release();
    await Promise.all([second, third]);
    expect(thirdStarted).toBe(true);
    expect(queue.size).toBe(0);
  });
});

describe("fallback PDF", () => {
  test("produces a valid PDF header with pagination", () => {
    const bytes = buildFallbackPdf(["Summary", "line one", "line two", "café"], "Résumé — Security Audit");
    const text = Buffer.from(bytes).toString("latin1");
    expect(text.startsWith("%PDF-1.4")).toBe(true);
    expect(text).toContain("/Type /Page");
    expect(text).toContain("%%EOF");
    expect(text).toMatch(/\/Kids \[3 0 R\]/);
    expect(sha256(bytes).length).toBe(64);
    expect(bytes.length).toBe(Buffer.byteLength(text, "latin1"));

    const startxref = Number(text.match(/startxref\n(\d+)\n%%EOF/)?.[1]);
    expect(text.startsWith("xref\n0 ", startxref)).toBe(true);
    const xrefHeader = text.match(/xref\n0 (\d+)\n/)!;
    const count = Number(xrefHeader[1]);
    const tableStart = xrefHeader.index! + xrefHeader[0].length;
    for (let id = 1; id < count; id += 1) {
      const entry = text.slice(tableStart + id * 20, tableStart + id * 20 + 20);
      const offset = Number(entry.slice(0, 10));
      expect(text.startsWith(`${id} 0 obj\n`, offset)).toBe(true);
    }
  });
});
