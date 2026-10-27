import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { open, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, relative } from "node:path";
import type { Config } from "../src/config.ts";
import { loadConfig, PHASE_NAMES } from "../src/config.ts";
import { KeyedSerialQueue } from "../src/concurrency.ts";
import { Store } from "../src/db/index.ts";
import { buildFallbackPdf } from "../src/reports/pdf.ts";
import { EventLog } from "../src/events.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { ReportService } from "../src/reports/generator.ts";
import { buildInventory, gitInfo } from "../src/repo/inventory.ts";
import { importRepository } from "../src/repo/import.ts";
import { assertAuthorizedRoot, canonicalDirectory, createWorkspace, readCappedRegularFile, readScopedFile, verifyQuote } from "../src/repo/workspace.ts";
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

  test("a git ref import rejects object metadata that points outside the repository", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-outside-git-"));
    const git = (cwd: string, args: string[]): string => {
      const result = Bun.spawnSync(["git", "-C", cwd, ...args], {
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_AUTHOR_NAME: "Tester",
          GIT_AUTHOR_EMAIL: "tester@example.com",
          GIT_COMMITTER_NAME: "Tester",
          GIT_COMMITTER_EMAIL: "tester@example.com",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (result.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${result.stderr.toString()}`);
      return result.stdout.toString().trim();
    };
    const insert = (id: string, source: string): void => {
      store.run(
        `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
         VALUES (?, ?, '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
        id, id, source, JSON.stringify(["**/*.js"]),
      );
    };
    try {
      git(outside, ["init", "-q"]);
      writeFileSync(join(outside, "secret.js"), "SECRET_GITDIR_SENTINEL\n");
      git(outside, ["add", "secret.js"]);
      git(outside, ["commit", "-qm", "secret"]);
      const sha = git(outside, ["rev-parse", "HEAD"]);
      git(outside, ["gc", "-q"]);

      const gitfile = join(dir, "gitfile-decoy");
      mkdirSync(gitfile);
      writeFileSync(join(gitfile, ".git"), `gitdir: ${join(outside, ".git")}\n`);
      writeFileSync(join(gitfile, "local.js"), "LOCAL_ONLY\n");
      insert("p-gitfile", gitfile);

      const linked = join(dir, "linked-decoy");
      mkdirSync(linked);
      symlinkSync(join(outside, ".git"), join(linked, ".git"));
      writeFileSync(join(linked, "local.js"), "LOCAL_ONLY\n");
      insert("p-linked", linked);

      const alternates = join(dir, "alternates-decoy");
      mkdirSync(alternates);
      git(alternates, ["init", "-q"]);
      mkdirSync(join(alternates, ".git", "objects", "info"), { recursive: true });
      writeFileSync(join(alternates, ".git", "objects", "info", "alternates"), `${join(outside, ".git", "objects")}\n`);
      git(alternates, ["update-ref", "refs/heads/stolen", sha]);
      insert("p-alternates", alternates);

      const packed = join(dir, "packed-decoy");
      mkdirSync(packed);
      git(packed, ["init", "-q"]);
      rmSync(join(packed, ".git", "objects", "pack"), { recursive: true, force: true });
      symlinkSync(join(outside, ".git", "objects", "pack"), join(packed, ".git", "objects", "pack"));
      git(packed, ["update-ref", "refs/heads/stolen", sha]);
      insert("p-packed", packed);

      const replaced = join(dir, "objects-decoy");
      mkdirSync(replaced);
      git(replaced, ["init", "-q"]);
      rmSync(join(replaced, ".git", "objects"), { recursive: true, force: true });
      symlinkSync(join(outside, ".git", "objects"), join(replaced, ".git", "objects"));
      git(replaced, ["update-ref", "refs/heads/stolen", sha]);
      insert("p-objects", replaced);

      const cases = [
        { id: "p-gitfile", ref: "HEAD" },
        { id: "p-linked", ref: "HEAD" },
        { id: "p-alternates", ref: "stolen" },
        { id: "p-packed", ref: "stolen" },
        { id: "p-objects", ref: "stolen" },
      ];
      for (const item of cases) {
        const row = store.get<{ source_path: string; scope_include: string; scope_exclude: string }>(
          "SELECT source_path, scope_include, scope_exclude FROM projects WHERE id = ?",
          item.id,
        )!;
        await expect(importRepository({
          config,
          store,
        }, {
          id: item.id,
          source_path: row.source_path,
          scope_include: row.scope_include,
          scope_exclude: row.scope_exclude,
        }, item.ref, "tester")).rejects.toMatchObject({ code: "invalid_repository" });
      }
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
      expect(existsSync(join(dir, "repos"))).toBe(false);

      const parent = join(dir, "parent-repo");
      const child = join(parent, "child");
      mkdirSync(child, { recursive: true });
      writeFileSync(join(parent, "secret.js"), "SIBLING_SECRET\n");
      writeFileSync(join(child, "a.js"), "CHILD_CONTENT\n");
      git(parent, ["init", "-q"]);
      git(parent, ["add", "secret.js", "child/a.js"]);
      git(parent, ["commit", "-qm", "both"]);
      insert("p-child", child);
      const imported = await importRepository({ config, store }, {
        id: "p-child",
        source_path: child,
        scope_include: JSON.stringify(["**/*.js"]),
        scope_exclude: "[]",
      }, "HEAD", "tester");
      expect(await Bun.file(join(imported.path, "a.js")).text()).toBe("CHILD_CONTENT\n");
      expect(existsSync(join(imported.path, "secret.js"))).toBe(false);
      expect(imported.commit_sha).toBe(git(parent, ["rev-parse", "HEAD"]));
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import archives the selected repository when GIT_DIR points elsewhere", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-git-dir-outside-"));
    const inside = join(dir, "inside-repo");
    const previous = process.env.GIT_DIR;
    const git = (cwd: string, args: string[]): string => {
      const result = Bun.spawnSync(["git", "-C", cwd, ...args], {
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_AUTHOR_NAME: "Tester",
          GIT_AUTHOR_EMAIL: "tester@example.com",
          GIT_COMMITTER_NAME: "Tester",
          GIT_COMMITTER_EMAIL: "tester@example.com",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (result.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${result.stderr.toString()}`);
      return result.stdout.toString().trim();
    };
    try {
      git(outside, ["init", "-q"]);
      writeFileSync(join(outside, "secret.js"), "SECRET_ENV_SENTINEL\n");
      git(outside, ["add", "secret.js"]);
      git(outside, ["commit", "-qm", "secret"]);
      mkdirSync(inside);
      writeFileSync(join(inside, "inside.js"), "INSIDE_REF_CONTENT\n");
      git(inside, ["init", "-q"]);
      git(inside, ["add", "inside.js"]);
      git(inside, ["commit", "-qm", "inside"]);
      const insideCommit = git(inside, ["rev-parse", "HEAD"]);
      store.run(
        `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
         VALUES ('p-env', 'env', '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
        inside, JSON.stringify(["**/*.js"]),
      );
      process.env.GIT_DIR = join(outside, ".git");
      const imported = await importRepository({ config, store }, {
        id: "p-env",
        source_path: inside,
        scope_include: JSON.stringify(["**/*.js"]),
        scope_exclude: "[]",
      }, "HEAD", "tester");
      expect(imported.commit_sha).toBe(insideCommit);
      expect(await Bun.file(join(imported.path, "inside.js")).text()).toBe("INSIDE_REF_CONTENT\n");
      expect(existsSync(join(imported.path, "secret.js"))).toBe(false);
    } finally {
      if (previous === undefined) delete process.env.GIT_DIR;
      else process.env.GIT_DIR = previous;
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import rejects a common directory that points at another repository", async () => {
    const outside = mkdtempSync(join(tmpdir(), "argus-outside-common-"));
    const git = (cwd: string, args: string[]): string => {
      const result = Bun.spawnSync(["git", "-C", cwd, ...args], {
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_AUTHOR_NAME: "Tester",
          GIT_AUTHOR_EMAIL: "tester@example.com",
          GIT_COMMITTER_NAME: "Tester",
          GIT_COMMITTER_EMAIL: "tester@example.com",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (result.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${result.stderr.toString()}`);
      return result.stdout.toString().trim();
    };
    const insert = (id: string, source: string): void => {
      store.run(
        `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
         VALUES (?, ?, '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
        id, id, source, JSON.stringify(["**/*.js"]),
      );
    };
    const projectFor = (id: string) => {
      const row = store.get<{ source_path: string; scope_include: string; scope_exclude: string }>(
        "SELECT source_path, scope_include, scope_exclude FROM projects WHERE id = ?",
        id,
      )!;
      return {
        id,
        source_path: row.source_path,
        scope_include: row.scope_include,
        scope_exclude: row.scope_exclude,
      };
    };
    try {
      mkdirSync(join(outside, "child"), { recursive: true });
      writeFileSync(join(outside, "secret.js"), "SECRET_COMMONDIR_SENTINEL\n");
      writeFileSync(join(outside, "child", "secret.js"), "SECRET_CHILD_COMMONDIR_SENTINEL\n");
      git(outside, ["init", "-q"]);
      git(outside, ["add", "secret.js", "child/secret.js"]);
      git(outside, ["commit", "-qm", "secret"]);

      const decoy = join(dir, "commondir-decoy");
      mkdirSync(decoy);
      git(decoy, ["init", "-q"]);
      writeFileSync(join(decoy, "local.js"), "LOCAL_ONLY\n");
      git(decoy, ["add", "local.js"]);
      git(decoy, ["commit", "-qm", "local"]);
      writeFileSync(join(decoy, ".git", "commondir"), `${join(outside, ".git")}\n`);
      insert("p-commondir", decoy);

      const relativeDecoy = join(dir, "commondir-relative");
      mkdirSync(relativeDecoy);
      git(relativeDecoy, ["init", "-q"]);
      writeFileSync(join(relativeDecoy, "local.js"), "LOCAL_ONLY\n");
      git(relativeDecoy, ["add", "local.js"]);
      git(relativeDecoy, ["commit", "-qm", "local"]);
      const relativeCommon = relative(join(relativeDecoy, ".git"), join(outside, ".git"));
      writeFileSync(join(relativeDecoy, ".git", "commondir"), `${relativeCommon}\n`);
      insert("p-commondir-relative", relativeDecoy);

      const parent = join(dir, "commondir-parent");
      const child = join(parent, "child");
      mkdirSync(child, { recursive: true });
      writeFileSync(join(child, "a.js"), "LOCAL_CHILD\n");
      git(parent, ["init", "-q"]);
      writeFileSync(join(parent, ".git", "commondir"), `${join(outside, ".git")}\n`);
      insert("p-common-child", child);

      for (const id of ["p-commondir", "p-commondir-relative", "p-common-child"]) {
        await expect(importRepository({ config, store }, projectFor(id), "HEAD", "tester")).rejects.toMatchObject({
          code: "invalid_repository",
        });
      }
      expect(store.get<{ count: number }>("SELECT COUNT(*) AS count FROM repositories")?.count).toBe(0);
      expect(existsSync(join(dir, "repos"))).toBe(false);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("a git ref import does not run smudge or process filters", async () => {
    const source = join(dir, "filter-repo");
    const globalHome = join(dir, "filter-home");
    const localMarker = join(dir, "local-filter-ran");
    const processMarker = join(dir, "process-filter-ran");
    const globalMarker = join(dir, "global-filter-ran");
    const previousHome = process.env.HOME;
    const git = (cwd: string, args: string[]): void => {
      const result = Bun.spawnSync(["git", "-C", cwd, ...args], {
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_AUTHOR_NAME: "Tester",
          GIT_AUTHOR_EMAIL: "tester@example.com",
          GIT_COMMITTER_NAME: "Tester",
          GIT_COMMITTER_EMAIL: "tester@example.com",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (result.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${result.stderr.toString()}`);
    };
    mkdirSync(source, { recursive: true });
    writeFileSync(join(source, "a.js"), "PLAIN_FILTER_BYTES\n");
    git(source, ["init", "-q"]);
    git(source, ["add", "a.js"]);
    git(source, ["commit", "-qm", "init"]);
    writeFileSync(join(source, ".gitattributes"), "* filter=pwn\n");
    git(source, ["add", ".gitattributes"]);
    git(source, ["commit", "-qm", "attrs"]);
    git(source, ["config", "filter.pwn.smudge", `touch ${localMarker}; echo LOCAL_SMUDGE`]);
    git(source, ["config", "filter.pwn.process", `touch ${processMarker}`]);
    git(source, ["config", "filter.pwn.required", "true"]);

    const globalSource = join(dir, "global-filter-repo");
    mkdirSync(join(globalHome, ".config"), { recursive: true });
    writeFileSync(join(globalHome, ".gitconfig"), `[filter "pwn"]\n\tsmudge = touch ${globalMarker}; echo GLOBAL_SMUDGE\n\trequired = true\n`);
    mkdirSync(globalSource, { recursive: true });
    writeFileSync(join(globalSource, "a.js"), "PLAIN_GLOBAL_BYTES\n");
    git(globalSource, ["init", "-q"]);
    git(globalSource, ["add", "a.js"]);
    git(globalSource, ["commit", "-qm", "init"]);
    writeFileSync(join(globalSource, ".gitattributes"), "* filter=pwn\n");
    git(globalSource, ["add", ".gitattributes"]);
    git(globalSource, ["commit", "-qm", "attrs"]);

    const insert = (id: string, path: string): void => {
      store.run(
        `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
         VALUES (?, ?, '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
        id, id, path, JSON.stringify(["**/*.js"]),
      );
    };
    insert("p-filter-local", source);
    insert("p-filter-global", globalSource);
    process.env.HOME = globalHome;
    try {
      const local = await importRepository({ config, store }, {
        id: "p-filter-local",
        source_path: source,
        scope_include: JSON.stringify(["**/*.js"]),
        scope_exclude: "[]",
      }, "HEAD", "tester");
      expect(await Bun.file(join(local.path, "a.js")).text()).toBe("PLAIN_FILTER_BYTES\n");
      expect(existsSync(localMarker)).toBe(false);
      expect(existsSync(processMarker)).toBe(false);

      const global = await importRepository({ config, store }, {
        id: "p-filter-global",
        source_path: globalSource,
        scope_include: JSON.stringify(["**/*.js"]),
        scope_exclude: "[]",
      }, "HEAD", "tester");
      expect(await Bun.file(join(global.path, "a.js")).text()).toBe("PLAIN_GLOBAL_BYTES\n");
      expect(existsSync(globalMarker)).toBe(false);
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  });

  test("a git ref import archives a sha256 commit without running its filter", async () => {
    const source = join(dir, "sha256-repo");
    const marker = join(dir, "sha256-filter-ran");
    const git = (cwd: string, args: string[]): string => {
      const result = Bun.spawnSync(["git", "-C", cwd, ...args], {
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_AUTHOR_NAME: "Tester",
          GIT_AUTHOR_EMAIL: "tester@example.com",
          GIT_COMMITTER_NAME: "Tester",
          GIT_COMMITTER_EMAIL: "tester@example.com",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (result.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${result.stderr.toString()}`);
      return result.stdout.toString().trim();
    };
    mkdirSync(source, { recursive: true });
    writeFileSync(join(source, "a.js"), "SHA256_PLAIN\n");
    writeFileSync(join(source, ".gitattributes"), "* filter=pwn\n");
    git(source, ["init", "-q", "--object-format=sha256"]);
    git(source, ["add", "a.js", ".gitattributes"]);
    git(source, ["commit", "-qm", "init"]);
    const commit = git(source, ["rev-parse", "HEAD"]);
    git(source, ["config", "filter.pwn.smudge", `touch ${marker}; echo SMUDGED`]);
    git(source, ["config", "filter.pwn.process", `touch ${marker}`]);
    git(source, ["config", "filter.pwn.required", "true"]);
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES ('p-sha256', 'sha256', '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      source, JSON.stringify(["**/*.js"]),
    );
    const imported = await importRepository({ config, store }, {
      id: "p-sha256",
      source_path: source,
      scope_include: JSON.stringify(["**/*.js"]),
      scope_exclude: "[]",
    }, "HEAD", "tester");
    expect(commit).toHaveLength(64);
    expect(imported.commit_sha).toBe(commit);
    expect(await Bun.file(join(imported.path, "a.js")).text()).toBe("SHA256_PLAIN\n");
    expect(existsSync(marker)).toBe(false);
  });

  test("a git ref import does not run gpg for an export-subst signature placeholder", async () => {
    const source = join(dir, "subst-repo");
    const marker = join(dir, "gpg-ran");
    const wrapper = join(dir, "bin");
    const previousPath = process.env.PATH;
    const git = (cwd: string, args: string[]): string => {
      const result = Bun.spawnSync(["git", "-C", cwd, ...args], {
        env: {
          PATH: "/usr/bin:/bin",
          GIT_AUTHOR_NAME: "Tester",
          GIT_AUTHOR_EMAIL: "tester@example.com",
          GIT_COMMITTER_NAME: "Tester",
          GIT_COMMITTER_EMAIL: "tester@example.com",
          GIT_CONFIG_NOSYSTEM: "1",
          HOME: join(dir, "subst-home"),
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_ATTR_NOSYSTEM: "1",
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (result.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${result.stderr.toString()}`);
      return result.stdout.toString().trim();
    };
    mkdirSync(join(dir, "subst-home"), { recursive: true });
    mkdirSync(join(source, "nested"), { recursive: true });
    writeFileSync(join(source, "sig.js"), "sig:$Format:%G?$\n");
    writeFileSync(join(source, "nested", "sig.js"), "nested:$Format:%G?$\n");
    writeFileSync(join(source, ".gitattributes"), "[attr]evil export-subst\nsig.js evil\n");
    writeFileSync(join(source, "nested", ".gitattributes"), "sig.js export-subst\n");
    git(source, ["init", "-q"]);
    git(source, ["add", "sig.js", "nested/sig.js", ".gitattributes", "nested/.gitattributes"]);
    git(source, ["commit", "-qm", "init"]);
    expect(git(source, ["check-attr", "export-subst", "--", "sig.js", "nested/sig.js"])).toBe(
      "sig.js: export-subst: set\nnested/sig.js: export-subst: set",
    );
    const tree = git(source, ["rev-parse", "HEAD^{tree}"]);
    const signatureHeader = "-----BEGIN PGP SIGNATURE-----";
    const signatureBody = ["", "iQE=", "=abcd", "-----END PGP SIGNATURE-----"];
    const forged = [
      `tree ${tree}`,
      "author Tester <tester@example.com> 1700000000 +0000",
      "committer Tester <tester@example.com> 1700000000 +0000",
      `gpgsig ${signatureHeader}`,
      ...signatureBody.map((line) => ` ${line}`),
      "",
      "signed",
      "",
    ].join("\n");
    const commitFile = join(dir, "signed-commit");
    writeFileSync(commitFile, forged);
    const commit = git(source, ["hash-object", "-t", "commit", "-w", commitFile]);
    git(source, ["update-ref", "HEAD", commit]);
    mkdirSync(wrapper);
    writeFileSync(join(wrapper, "gpg"), `#!/bin/sh\ntouch ${marker}\nexit 0\n`);
    chmodSync(join(wrapper, "gpg"), 0o755);
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES ('p-subst', 'subst', '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      source, JSON.stringify(["**/*.js"]),
    );
    process.env.PATH = `${wrapper}:${previousPath ?? "/usr/bin:/bin"}`;
    try {
      const imported = await importRepository({ config, store }, {
        id: "p-subst",
        source_path: source,
        scope_include: JSON.stringify(["**/*.js"]),
        scope_exclude: "[]",
      }, "HEAD", "tester");
      expect(imported.commit_sha).toBe(commit);
      expect(await Bun.file(join(imported.path, "sig.js")).text()).toBe("sig:$Format:%G?$\n");
      expect(await Bun.file(join(imported.path, "nested/sig.js")).text()).toBe("nested:$Format:%G?$\n");
      expect(existsSync(marker)).toBe(false);
    } finally {
      if (previousPath === undefined) delete process.env.PATH;
      else process.env.PATH = previousPath;
    }
  });

  test("a git ref import ignores global attributes and keeps a committed line-ending rule", async () => {
    const source = join(dir, "attr-repo");
    const globalHome = join(dir, "attr-home");
    const xdg = join(dir, "attr-xdg");
    const previousHome = process.env.HOME;
    const previousXdg = process.env.XDG_CONFIG_HOME;
    const git = (cwd: string, args: string[]): void => {
      const result = Bun.spawnSync(["git", "-C", cwd, ...args], {
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          GIT_AUTHOR_NAME: "Tester",
          GIT_AUTHOR_EMAIL: "tester@example.com",
          GIT_COMMITTER_NAME: "Tester",
          GIT_COMMITTER_EMAIL: "tester@example.com",
          GIT_CONFIG_NOSYSTEM: "1",
          HOME: join(dir, "attr-commit-home"),
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      if (result.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${result.stderr.toString()}`);
    };
    mkdirSync(join(globalHome, ".config", "git"), { recursive: true });
    mkdirSync(join(xdg, "git"), { recursive: true });
    mkdirSync(join(dir, "attr-commit-home"), { recursive: true });
    writeFileSync(join(globalHome, ".config", "git", "attributes"), "*.js text eol=crlf\n");
    writeFileSync(join(xdg, "git", "attributes"), "*.js text eol=crlf\n* ident\n");
    mkdirSync(source, { recursive: true });
    writeFileSync(join(source, "plain.js"), "PLAIN\n");
    writeFileSync(join(source, "crlf.js"), "hello\n");
    writeFileSync(join(source, ".gitattributes"), "crlf.js text eol=crlf\n");
    git(source, ["init", "-q"]);
    git(source, ["add", "plain.js", "crlf.js", ".gitattributes"]);
    git(source, ["commit", "-qm", "init"]);
    mkdirSync(join(source, ".git", "info"), { recursive: true });
    writeFileSync(join(source, ".git", "info", "attributes"), "*.js text eol=crlf\n");
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES ('p-attrs', 'attrs', '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      source, JSON.stringify(["**/*.js"]),
    );
    process.env.HOME = globalHome;
    process.env.XDG_CONFIG_HOME = xdg;
    try {
      const imported = await importRepository({ config, store }, {
        id: "p-attrs",
        source_path: source,
        scope_include: JSON.stringify(["**/*.js"]),
        scope_exclude: "[]",
      }, "HEAD", "tester");
      expect(await Bun.file(join(imported.path, "plain.js")).text()).toBe("PLAIN\n");
      expect(await Bun.file(join(imported.path, "crlf.js")).text()).toBe("hello\r\n");
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      if (previousXdg === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = previousXdg;
    }
  });

  test("import does not wait when git HEAD is a pipe", async () => {
    const source = join(dir, "fifo-head");
    mkdirSync(join(source, ".git"), { recursive: true });
    writeFileSync(join(source, "a.js"), "LOCAL_ONLY\n");
    const result = Bun.spawnSync(["mkfifo", join(source, ".git", "HEAD")]);
    expect(result.exitCode).toBe(0);
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES ('p-fifo', 'fifo', '', ?, ?, '[]', 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      source, JSON.stringify(["**/*.js"]),
    );
    const raced = await Promise.race([
      importRepository({ config, store }, {
        id: "p-fifo",
        source_path: source,
        scope_include: JSON.stringify(["**/*.js"]),
        scope_exclude: "[]",
      }, null, "tester").then(() => "imported").catch((error: { code?: string }) => error.code ?? "error"),
      Bun.sleep(500).then(() => "blocked"),
    ]);
    expect(raced).toBe("invalid_repository");
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
