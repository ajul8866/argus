import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { lstat, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { PHASE_NAMES } from "../src/config.ts";
import { KeyedSerialQueue } from "../src/concurrency.ts";
import { Store } from "../src/db/index.ts";
import { buildFallbackPdf } from "../src/reports/pdf.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { buildInventory, DEFAULT_EXCLUDES, gitInfo } from "../src/repo/inventory.ts";
import { importRepository } from "../src/repo/import.ts";
import { createWorkspace, readScopedFile, verifyQuote } from "../src/repo/workspace.ts";
import { runCommand } from "../src/harness/process.ts";
import { createScopeMatcher, globToRegExp, matchesScope, extractJson, sha256 } from "../src/util.ts";
import { redactSecrets } from "../src/security/redact.ts";
import { credentialEnvironment, decryptSecret, encryptSecret, type StoredCredential } from "../src/security/credentials.ts";
import { MAP_SCHEMA, validateAgainstSchema } from "../src/orchestrator/schemas.ts";

const fixture = join(import.meta.dir, "fixtures", "vulnerable-app");

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

describe("scope and parsing", () => {
  test("glob matcher supports ** and directory paths", () => {
    expect(globToRegExp("**/*.js").test("src/server.js")).toBe(true);
    expect(globToRegExp("**/*.js").test("server.js")).toBe(true);
    expect(globToRegExp("src/**").test("src/lib/db.js")).toBe(true);
    expect(globToRegExp("src/*.js").test("src/lib/db.js")).toBe(false);
    expect(matchesScope("src/server.js", { include: ["**/*.js"], exclude: ["src/lib/**"] })).toBe(true);
    expect(matchesScope("src/lib/db.js", { include: ["**/*.js"], exclude: ["src/lib/**"] })).toBe(false);
  });

  test("default excludes match nested env files and dependency directories", () => {
    const scope = { include: ["**/*"], exclude: DEFAULT_EXCLUDES };
    const excluded = [
      ".env",
      ".env.production",
      ".env/secret",
      "app/.env",
      "app/.env.local",
      "services/api/.env/token",
      "node_modules/leftpad/index.js",
      "app/node_modules/leftpad/index.js",
      "app/dist/bundle.js",
      "svc/target/secret.txt",
      "web/.next/cache.js",
      "pkg/vendor/lib.php",
      "app/build/out.js",
      "cover/coverage/lcov.info",
    ];
    for (const path of excluded) expect(matchesScope(path, scope)).toBe(false);
    expect(matchesScope("src/ok.js", scope)).toBe(true);
    expect(matchesScope("src/node_modules_utils.js", scope)).toBe(true);
    expect(matchesScope(".environment", scope)).toBe(true);
    expect(matchesScope("src/distribution/notes.js", scope)).toBe(true);
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

  test("scoped reads reject symlinks and dotted exclude bypasses", async () => {
    const dir = mkdtempSync(join(tmpdir(), "argus-contain-"));
    try {
      const root = join(dir, "repo");
      const outside = join(dir, "outside");
      await mkdir(join(root, "nested"), { recursive: true });
      await mkdir(outside, { recursive: true });
      await writeFile(join(outside, "master.key"), "OUTSIDE-SECRET-VALUE");
      await writeFile(join(root, "secret.js"), "EXCLUDED-SECRET");
      await writeFile(join(root, "nested", "ok.js"), "visible-file");
      await symlink(join(outside, "master.key"), join(root, "leak.txt"));
      await symlink(outside, join(root, "linkdir"));
      await symlink(join(root, "secret.js"), join(root, "alias.txt"));
      const scope = { include: ["**/*"], exclude: ["secret.js", "private/**"] };
      const visible = await readScopedFile(root, "nested/./ok.js", scope);
      expect(visible.path).toBe("nested/ok.js");
      expect(visible.content).toBe("visible-file");
      await expect(readScopedFile(root, "leak.txt", scope)).rejects.toMatchObject({ code: "symlink_rejected" });
      await expect(readScopedFile(root, "linkdir/master.key", scope)).rejects.toMatchObject({ code: "symlink_rejected" });
      await expect(readScopedFile(root, "alias.txt", scope)).rejects.toMatchObject({ code: "symlink_rejected" });
      await expect(readScopedFile(root, "nested/../secret.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readScopedFile(root, "nested\\..\\secret.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
      await expect(readScopedFile(root, "../outside/master.key", scope)).rejects.toMatchObject({ code: "bad_request" });
      const quoted = await verifyQuote(root, scope, { path: "leak.txt", quote: "OUTSIDE-SECRET-VALUE" });
      expect(quoted.found).toBe(false);
      const workspace = join(dir, "workspace");
      await expect(createWorkspace(root, {
        files: [{ path: "leak.txt", size: 4, lines: 1, language: "Text", sha256: "abc" }],
        skipped: [],
        languages: {},
        frameworks: [],
        endpoints: [],
        auth_boundaries: [],
        dependency_graph: [],
        entrypoints: [],
        total_bytes: 4,
        truncated: false,
      }, scope, workspace, {})).rejects.toMatchObject({ code: "symlink_rejected" });
      await expect(lstat(join(workspace, "leak.txt"))).rejects.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("workspace copies scope-check the canonical path", async () => {
    const dir = mkdtempSync(join(tmpdir(), "argus-ws-scope-"));
    try {
      const root = join(dir, "repo");
      await mkdir(join(root, "nested"), { recursive: true });
      await writeFile(join(root, "secret.js"), "EXCLUDED-SECRET");
      await writeFile(join(root, "nested", "ok.js"), "visible-file");
      const scope = { include: ["**/*"], exclude: ["secret.js"] };
      const workspace = join(dir, "workspace");
      await createWorkspace(root, {
        files: [
          { path: "nested/../secret.js", size: 15, lines: 1, language: "JavaScript", sha256: "abc" },
          { path: "././secret.js", size: 15, lines: 1, language: "JavaScript", sha256: "abc" },
          { path: "foo/./../secret.js", size: 15, lines: 1, language: "JavaScript", sha256: "abc" },
          { path: "nested/../nested/ok.js", size: 12, lines: 1, language: "JavaScript", sha256: "def" },
        ],
        skipped: [],
        languages: {},
        frameworks: [],
        endpoints: [],
        auth_boundaries: [],
        dependency_graph: [],
        entrypoints: [],
        total_bytes: 57,
        truncated: false,
      }, scope, workspace, {});
      await expect(lstat(join(workspace, "secret.js"))).rejects.toThrow();
      expect(await Bun.file(join(workspace, "nested", "ok.js")).text()).toBe("visible-file");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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

  test("git ref snapshots remove symlinks and keep excluded files unreadable", async () => {
    const source = join(dir, "source");
    const outside = join(dir, "outside");
    await mkdir(join(source, "nested"), { recursive: true });
    await mkdir(outside, { recursive: true });
    await writeFile(join(outside, "master.key"), "OUTSIDE-SECRET-VALUE");
    await writeFile(join(source, "readme.txt"), "hello snapshot");
    await writeFile(join(source, "secret.js"), "EXCLUDED-SECRET");
    await writeFile(join(source, "nested", "ok.js"), "visible-file");
    await symlink(join(outside, "master.key"), join(source, "leak.txt"));
    await symlink(outside, join(source, "linkdir"));
    await symlink(join(source, "secret.js"), join(source, "alias.txt"));
    const env = {
      ...process.env,
      GIT_AUTHOR_NAME: "Argus Test",
      GIT_AUTHOR_EMAIL: "test@argus.local",
      GIT_COMMITTER_NAME: "Argus Test",
      GIT_COMMITTER_EMAIL: "test@argus.local",
    };
    for (const args of [["init", "-b", "main"], ["add", "."], ["commit", "-m", "init"]] as const) {
      const result = await runCommand(["git", "-C", source, ...args], { env });
      if (result.code !== 0) throw new Error(result.stderr || result.stdout);
    }
    const scoped = {
      id: "p-symlink",
      name: "Symlink",
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: JSON.stringify(["secret.js"]),
    };
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES (?, ?, '', ?, ?, ?, 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      scoped.id, scoped.name, scoped.source_path, scoped.scope_include, scoped.scope_exclude,
    );
    const scope = { include: ["**/*"], exclude: ["secret.js"] };
    const worktree = await importRepository({ config, store }, scoped, null, "tester@argus.local");
    expect(await Bun.file(join(worktree.path, "readme.txt")).text()).toBe("hello snapshot");
    await expect(lstat(join(worktree.path, "leak.txt"))).rejects.toThrow();
    await expect(lstat(join(worktree.path, "secret.js"))).rejects.toThrow();
    const archived = await importRepository({ config, store }, scoped, "HEAD", "tester@argus.local");
    expect(archived.commit_sha).toMatch(/^[0-9a-f]{40}$/);
    expect(await Bun.file(join(archived.path, "readme.txt")).text()).toBe("hello snapshot");
    await expect(lstat(join(archived.path, "leak.txt"))).rejects.toThrow();
    await expect(lstat(join(archived.path, "linkdir"))).rejects.toThrow();
    await expect(lstat(join(archived.path, "alias.txt"))).rejects.toThrow();
    await expect(readScopedFile(archived.path, "secret.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
    await expect(readScopedFile(archived.path, "nested/../secret.js", scope)).rejects.toMatchObject({ code: "out_of_scope" });
    await expect(readScopedFile(archived.path, "linkdir/master.key", scope)).rejects.toMatchObject({ code: "not_found" });
    expect(await readScopedFile(archived.path, "nested/ok.js", scope)).toMatchObject({ content: "visible-file" });
  });

  test("git ref snapshots do not keep default-excluded files that project scope would allow", async () => {
    const source = join(dir, "env-source");
    await mkdir(join(source, "nested"), { recursive: true });
    const secret = "AWS_SECRET_ACCESS_KEY=SUPERSECRETVALUE123456";
    await writeFile(join(source, ".env"), secret);
    await writeFile(join(source, "secret.js"), "EXCLUDED-SECRET");
    await writeFile(join(source, "ok.js"), "visible-file");
    await writeFile(join(source, "nested", "keep.js"), "nested-visible");
    const env = {
      ...process.env,
      GIT_AUTHOR_NAME: "Argus Test",
      GIT_AUTHOR_EMAIL: "test@argus.local",
      GIT_COMMITTER_NAME: "Argus Test",
      GIT_COMMITTER_EMAIL: "test@argus.local",
    };
    for (const args of [["init", "-b", "main"], ["add", "-A"], ["commit", "-m", "init"]] as const) {
      const result = await runCommand(["git", "-C", source, ...args], { env });
      if (result.code !== 0) throw new Error(result.stderr || result.stdout);
    }
    const committed = await runCommand(["git", "-C", source, "ls-files"], { env });
    expect(committed.stdout.split("\n")).toContain(".env");
    const scoped = {
      id: "p-env",
      name: "Env",
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: JSON.stringify(["secret.js"]),
    };
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES (?, ?, '', ?, ?, ?, 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      scoped.id, scoped.name, scoped.source_path, scoped.scope_include, scoped.scope_exclude,
    );
    const projectScope = { include: ["**/*"], exclude: ["secret.js"] };
    const archived = await importRepository({ config, store }, scoped, "HEAD", "tester@argus.local");
    const row = store.get<{ inventory: string }>("SELECT inventory FROM repositories WHERE id = ?", archived.id)!;
    const inventory = JSON.parse(row.inventory) as { files: Array<{ path: string }> };
    expect(inventory.files.map((file) => file.path).sort()).toEqual(["nested/keep.js", "ok.js"]);
    await expect(lstat(join(archived.path, ".env"))).rejects.toThrow();
    await expect(lstat(join(archived.path, "secret.js"))).rejects.toThrow();
    await expect(readScopedFile(archived.path, ".env", projectScope)).rejects.toMatchObject({ code: "not_found" });
    expect(await verifyQuote(archived.path, projectScope, { path: ".env", quote: secret })).toMatchObject({ found: false });
    expect(await readScopedFile(archived.path, "ok.js", projectScope)).toMatchObject({ content: "visible-file" });
    expect(await readScopedFile(archived.path, "nested/keep.js", projectScope)).toMatchObject({ content: "nested-visible" });
    const worktree = await importRepository({ config, store }, scoped, null, "tester@argus.local");
    await expect(lstat(join(worktree.path, ".env"))).rejects.toThrow();
    await expect(readScopedFile(worktree.path, ".env", projectScope)).rejects.toMatchObject({ code: "not_found" });
  });

  test("git and worktree snapshots drop nested env files and dependency directories", async () => {
    const source = join(dir, "nested-excludes");
    await mkdir(join(source, "app", "node_modules", "leftpad"), { recursive: true });
    await mkdir(join(source, "app", "dist"), { recursive: true });
    await mkdir(join(source, "src"), { recursive: true });
    const secret = "AWS_SECRET_ACCESS_KEY=NESTEDSECRETVALUE123456";
    await writeFile(join(source, "app", ".env"), secret);
    await writeFile(join(source, "app", ".env.local"), "LOCAL_TOKEN=nested-local-secret");
    await writeFile(join(source, "app", "node_modules", "leftpad", "index.js"), "module.exports=1");
    await writeFile(join(source, "app", "dist", "bundle.js"), "DIST-BUNDLE");
    await writeFile(join(source, "src", "ok.js"), "console.log('ok')");
    await writeFile(join(source, "src", "node_modules_utils.js"), "export const kept = true");
    const env = {
      ...process.env,
      GIT_AUTHOR_NAME: "Argus Test",
      GIT_AUTHOR_EMAIL: "test@argus.local",
      GIT_COMMITTER_NAME: "Argus Test",
      GIT_COMMITTER_EMAIL: "test@argus.local",
    };
    for (const args of [["init", "-b", "main"], ["add", "-A"], ["commit", "-m", "init"]] as const) {
      const result = await runCommand(["git", "-C", source, ...args], { env });
      if (result.code !== 0) throw new Error(result.stderr || result.stdout);
    }
    const scoped = {
      id: "p-nested",
      name: "Nested",
      source_path: source,
      scope_include: JSON.stringify(["**/*"]),
      scope_exclude: JSON.stringify([]),
    };
    store.run(
      `INSERT INTO projects (id, name, description, source_path, scope_include, scope_exclude, authorized_by, authorization_ref, created_at, updated_at)
       VALUES (?, ?, '', ?, ?, ?, 'Tester', 'TEST-AUTH', '2026-01-01', '2026-01-01')`,
      scoped.id, scoped.name, scoped.source_path, scoped.scope_include, scoped.scope_exclude,
    );
    const projectScope = { include: ["**/*"], exclude: [] as string[] };
    const archived = await importRepository({ config, store }, scoped, "HEAD", "tester@argus.local");
    const row = store.get<{ inventory: string }>("SELECT inventory FROM repositories WHERE id = ?", archived.id)!;
    const inventory = JSON.parse(row.inventory) as { files: Array<{ path: string }> };
    expect(inventory.files.map((file) => file.path).sort()).toEqual(["src/node_modules_utils.js", "src/ok.js"]);
    for (const rel of ["app/.env", "app/.env.local", "app/node_modules/leftpad/index.js", "app/dist/bundle.js"]) {
      await expect(lstat(join(archived.path, rel))).rejects.toThrow();
      await expect(readScopedFile(archived.path, rel, projectScope)).rejects.toMatchObject({ code: "not_found" });
    }
    expect(await verifyQuote(archived.path, projectScope, { path: "app/.env", quote: secret })).toMatchObject({ found: false });
    expect(await readScopedFile(archived.path, "src/ok.js", projectScope)).toMatchObject({ content: "console.log('ok')" });
    expect(await readScopedFile(archived.path, "src/node_modules_utils.js", projectScope)).toMatchObject({ content: "export const kept = true" });
    const worktree = await importRepository({ config, store }, scoped, null, "tester@argus.local");
    await expect(lstat(join(worktree.path, "app", ".env"))).rejects.toThrow();
    await expect(readScopedFile(worktree.path, "app/.env", projectScope)).rejects.toMatchObject({ code: "not_found" });
    await expect(lstat(join(worktree.path, "app", "node_modules", "leftpad", "index.js"))).rejects.toThrow();
    expect(await readScopedFile(worktree.path, "src/ok.js", projectScope)).toMatchObject({ content: "console.log('ok')" });
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
