import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { PHASE_NAMES } from "../src/config.ts";
import { KeyedSerialQueue } from "../src/concurrency.ts";
import { Store } from "../src/db/index.ts";
import { buildFallbackPdf } from "../src/reports/pdf.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { buildInventory, gitInfo } from "../src/repo/inventory.ts";
import { importRepository } from "../src/repo/import.ts";
import { createWorkspace, verifyQuote } from "../src/repo/workspace.ts";
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
