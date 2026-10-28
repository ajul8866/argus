import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { seedDefaults } from "../src/settings.ts";
import { LocalCatalog } from "../src/local/catalog.ts";
import { AuthService } from "../src/auth.ts";
import { createApi } from "../src/api/api.ts";
import { EventLog } from "../src/events.ts";
import { EvidenceStore } from "../src/orchestrator/evidence.ts";
import { ReportService } from "../src/reports/generator.ts";
import { AuditEngine } from "../src/orchestrator/engine.ts";
import { HarnessManager } from "../src/harness/manager.ts";
import { PiHarnessAdapter } from "../src/harness/pi.ts";
import { ClaudeCodeHarnessAdapter } from "../src/harness/claude.ts";
import { DEFAULT_HARNESS_CONFIG } from "../src/settings.ts";
import type { SessionResources } from "../src/local/types.ts";

let dir: string;
let store: Store;
let catalog: LocalCatalog;
let home: string;
let project: string;
let config: Config;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "argus-local-"));
  home = join(dir, "home");
  project = join(dir, "project");
  await mkdir(home);
  await mkdir(project);
  config = {
    port: 0, hostname: "127.0.0.1", dataDir: join(dir, "data"), webDist: join(dir, "web"),
    adminEmail: "admin@test.local", adminPassword: "test-password", sessionTtlMs: 60_000,
    maxConcurrentAgents: 2, sandboxMode: "none", piBin: "pi", claudeBin: "claude",
    allowedRoots: [dir], masterKey: "local-test-key", chromeBin: "missing-chrome", secureCookies: false, logLevel: "error",
  };
  store = new Store(config);
  seedDefaults(store, config);
  catalog = new LocalCatalog(store, { home, projectRoot: project, env: { TEST_TOKEN: "private-token-value" }, refreshMs: 0 });
});

afterEach(async () => {
  store.close();
  await rm(dir, { recursive: true, force: true });
});

async function localSkill(name = "source-review"): Promise<string> {
  const root = join(home, ".agents", "skills", name);
  await mkdir(join(root, "references"), { recursive: true });
  await writeFile(join(root, "SKILL.md"), `---\nname: ${name}\ndescription: >\n  Review source with evidence.\n  Check trust boundaries.\n---\n# Review\nRead references/checks.md.\n`);
  await writeFile(join(root, "references", "checks.md"), "Check source-to-sink paths.\n");
  return root;
}

test("discovers local skills automatically, parses frontmatter and deduplicates symlink aliases", async () => {
  const root = await localSkill();
  await mkdir(join(home, ".claude", "skills"), { recursive: true });
  await symlink(root, join(home, ".claude", "skills", "source-review"));
  const view = await catalog.refresh();
  expect(view.skills).toHaveLength(1);
  expect(view.skills[0]).toMatchObject({ name: "source-review", present: true, roles: [], enabled: true });
  expect(view.skills[0]!.description).toContain("Check trust boundaries.");
  expect(view.skills[0]!.sources.length).toBeGreaterThan(1);
  expect((await catalog.skillDetail(view.skills[0]!.id)).files).toContain("references/checks.md");
});

test("discovers JSON and TOML MCP configs without returning credentials or running commands", async () => {
  await mkdir(join(home, ".pi", "agent"), { recursive: true });
  await mkdir(join(home, ".codex"), { recursive: true });
  await writeFile(join(home, ".pi", "agent", "mcp.json"), JSON.stringify({ mcpServers: {
    search: { url: "https://example.test/mcp?token=hidden", headers: { Authorization: "Bearer ${TEST_TOKEN}" } },
    local: { command: "command-must-not-run", args: ["--key", "secret-argument"] },
  } }));
  await writeFile(join(home, ".codex", "config.toml"), '[mcp_servers.docs]\nurl = "https://docs.example.test/mcp"\n[mcp_servers.docs.env_http_headers]\nAuthorization = "TEST_TOKEN"\n');
  const view = await catalog.refresh();
  expect(view.servers.map((server) => server.name).sort()).toEqual(["docs", "local", "search"]);
  const output = JSON.stringify(view);
  for (const secret of ["private-token-value", "secret-argument", "token=hidden", "Bearer ${TEST_TOKEN}"]) {
    expect(output).not.toContain(secret);
  }
});

test("rescans preserve assignments, track removed skills and discover additions", async () => {
  const root = await localSkill();
  const initial = await catalog.refresh();
  const id = initial.skills[0]!.id;
  catalog.setSkillAccess(id, { roles: ["security_researcher"], mcp_ids: [], enabled: true });
  await writeFile(join(root, "SKILL.md"), "---\nname: source-review\ndescription: Updated description\n---\nUpdated source review.");
  await localSkill("new-skill");
  const updated = await catalog.refresh();
  expect(updated.skills).toHaveLength(2);
  expect(updated.skills.find((skill) => skill.id === id)).toMatchObject({ roles: ["security_researcher"], description: "Updated description" });
  await rm(root, { recursive: true });
  expect((await catalog.refresh()).skills.find((skill) => skill.id === id)?.present).toBe(false);
  expect((await catalog.resourcesForRole("security_researcher")).skills).toHaveLength(0);
});

test("skill file preview rejects traversal and symlinks that escape the skill directory", async () => {
  const root = await localSkill();
  await writeFile(join(dir, "secret.txt"), "outside secret");
  await symlink(join(dir, "secret.txt"), join(root, "leak.txt"));
  await writeFile(join(root, ".env.local"), "PRIVATE_CREDENTIAL=hidden");
  await writeFile(join(root, ".npmrc"), "//registry.example/:_authToken=hidden");
  await writeFile(join(root, "credentials.yaml"), "token: hidden\n");
  await writeFile(join(root, "id_ed25519"), "private key material");
  const id = (await catalog.refresh()).skills[0]!.id;
  await expect(catalog.readSkillFile(id, "../../secret.txt")).rejects.toThrow();
  await expect(catalog.readSkillFile(id, "leak.txt")).rejects.toThrow();
  await expect(catalog.readSkillFile(id, ".env.local")).rejects.toThrow();
  await expect(catalog.readSkillFile(id, ".npmrc")).rejects.toThrow();
  await expect(catalog.readSkillFile(id, "credentials.yaml")).rejects.toThrow();
  await expect(catalog.readSkillFile(id, "id_ed25519")).rejects.toThrow();
  expect((await catalog.readSkillFile(id, "references/checks.md")).content).toContain("source-to-sink");
});

test("only assigned skills unlock linked MCP and source-disabled servers stay disabled", async () => {
  await localSkill();
  await writeFile(join(project, ".mcp.json"), JSON.stringify({ mcpServers: {
    enabled: { command: "local-tool" }, disabled: { command: "other-tool", enabled: false },
  } }));
  const view = await catalog.refresh();
  const skill = view.skills[0]!;
  catalog.setSkillAccess(skill.id, { roles: ["security_researcher"], mcp_ids: view.servers.map((server) => server.id), enabled: true });
  expect((await catalog.resourcesForRole("codebase_mapper")).servers).toHaveLength(0);
  const resources = await catalog.resourcesForRole("security_researcher");
  expect(resources.skills).toHaveLength(1);
  expect(resources.servers).toHaveLength(1);
  expect(resources.servers[0]!.name).toBe("enabled");
  expect(resources.skills[0]!.files.some((file) => file.path === "references/checks.md")).toBe(true);
  expect(() => catalog.setSkillAccess(skill.id, { roles: ["made-up-role"], mcp_ids: [], enabled: true })).toThrow();
  expect(() => catalog.setSkillAccess(skill.id, { roles: [], mcp_ids: ["unknown-server"], enabled: true })).toThrow();
});

test("malformed configs and missing environment variables are visible without leaking source text", async () => {
  await mkdir(join(home, ".pi", "agent"), { recursive: true });
  await writeFile(join(home, ".pi", "agent", "mcp.json"), '{"secret":"do-not-return",');
  await writeFile(join(project, ".mcp.json"), JSON.stringify({ mcpServers: {
    missing: { url: "https://example.test", headers: { Authorization: "${MISSING_TOKEN}" } },
  } }));
  const view = await catalog.refresh();
  expect(view.scan.errors.length).toBeGreaterThan(0);
  expect(JSON.stringify(view)).not.toContain("do-not-return");
  expect(view.servers[0]!.error).toContain("MISSING_TOKEN");
});

test("resource API requires authentication, CSRF and admin access; manual resource creation is unavailable", async () => {
  await localSkill();
  const skill = (await catalog.refresh()).skills[0]!;
  const auth = new AuthService(config, store);
  await auth.bootstrap();
  const login = await auth.login(config.adminEmail, config.adminPassword!, "local", "test");
  const events = new EventLog(store);
  const manager = new HarnessManager(config, store);
  const evidence = new EvidenceStore(config, store);
  const reports = new ReportService(config, store, evidence, events);
  const engine = new AuditEngine(config, store, manager, evidence, events, reports, catalog);
  const api = createApi({ config, store, auth, events, manager, evidence, reports, engine, catalog });
  const headers = { cookie: `argus_session=${login.token}`, "x-csrf-token": login.csrf, "content-type": "application/json" };
  expect((await api(new Request("http://localhost/api/skills"))).status).toBe(401);
  expect((await api(new Request("http://localhost/api/skills", { headers }))).status).toBe(200);
  const body = JSON.stringify({ enabled: true, roles: ["codebase_mapper"], mcp_ids: [] });
  expect((await api(new Request(`http://localhost/api/skills/${skill.id}`, { method: "PUT", headers: { ...headers, "x-csrf-token": "invalid" }, body }))).status).toBe(403);
  expect((await api(new Request(`http://localhost/api/skills/${skill.id}`, { method: "PUT", headers, body }))).status).toBe(200);
  expect((await api(new Request("http://localhost/api/skills", { method: "POST", headers, body }))).status).toBe(404);
  const sessionRow = auth.authenticate(new Request("http://localhost/api/auth/me", { headers }))!;
  store.run("UPDATE users SET role = 'viewer' WHERE id = ?", sessionRow.user.id);
  expect((await api(new Request(`http://localhost/api/skills/${skill.id}`, { method: "PUT", headers, body }))).status).toBe(403);
  expect((await api(new Request("http://localhost/api/mcp/rescan", { method: "POST", headers }))).status).toBe(403);
});

test("observed loads and MCP calls are deduplicated and reported with task provenance", async () => {
  await localSkill();
  await writeFile(join(project, ".mcp.json"), JSON.stringify({ mcpServers: { local: { command: "test-tool" } } }));
  const view = await catalog.refresh();
  const skill = view.skills[0]!;
  const server = view.servers[0]!;
  catalog.setSkillAccess(skill.id, { enabled: true, roles: ["codebase_mapper"], mcp_ids: [server.id] });
  const resources = await catalog.resourcesForRole("codebase_mapper");
  const context = { auditId: "audit", taskId: "task", sessionId: "session", role: "codebase_mapper", harness: "pi" };
  catalog.recordLoads(resources, context);
  catalog.recordLoads(resources, context);
  const tool = `mcp__${resources.servers[0]!.key}__read`;
  catalog.recordTool(resources, context, tool, "call-1");
  catalog.recordTool(resources, context, tool, "call-1");
  catalog.recordTool(resources, context, "mcp__unassigned__read", "call-2");
  expect(catalog.usage("skill", skill.id).stats).toMatchObject({ total_calls: 1, tasks_covered: 1 });
  const usage = catalog.usage("mcp", server.id);
  expect(usage.stats).toMatchObject({ total_calls: 1, tasks_covered: 1 });
  expect(usage.recent[0]).toMatchObject({ audit_id: "audit", task_id: "task", role: "codebase_mapper", tool_name: "read" });
});

test("Codex discovery tolerates valid digit-leading table names outside and inside MCP settings", async () => {
  await mkdir(join(home, ".codex"), { recursive: true });
  await writeFile(join(home, ".codex/config.toml"), '[model_providers.9router]\nname = "provider"\n[mcp_servers.9remote]\nurl = "https://example.test/mcp"\n');
  const view = await catalog.refresh();
  expect(view.servers).toHaveLength(1);
  expect(view.servers[0]).toMatchObject({ name: "9remote", transport: "http", error: null });
  expect(view.scan.errors).toHaveLength(0);
});

test("an unreadable skill remains visible with an error instead of silently disappearing", async () => {
  const root = await localSkill();
  await writeFile(join(root, "SKILL.md"), "# Binary marker\0invalid text");
  const view = await catalog.refresh();
  expect(view.skills).toHaveLength(1);
  expect(view.skills[0]!.present).toBe(true);
  expect(view.skills[0]!.error).toBeTruthy();
});

for (const kind of ["pi", "claude-code"] as const) {
  test(`${kind} adapter passes only session MCP configuration and snapshots skill resources`, async () => {
    const capture = join(dir, "capture.json");
    const executable = join(dir, `fake-${kind}`);
    const code = `#!/usr/bin/env bun
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
writeFileSync('resource-scratch.txt', 'local resource session wrote a scratch file');
const args=process.argv.slice(2);
const configPath=${JSON.stringify(kind === "pi" ? null : "claude")}
  ? args[args.indexOf('--mcp-config')+1] : join(process.env.HOME,'.pi/agent/mcp.json');
const mcp=JSON.parse(readFileSync(configPath,'utf8'));
const skill=readFileSync(join(process.env.HOME,'.argus-skills/skill-id/references/checks.md'),'utf8');
writeFileSync(${JSON.stringify(capture)},JSON.stringify({args,mcp,skill}));
if(${JSON.stringify(kind)}==='claude-code') {
  console.log(JSON.stringify({type:'result',subtype:'success',is_error:false,result:'{"ok":true}',structured_output:{ok:true},total_cost_usd:0,usage:{}}));
} else {
  let buffer='';
  for await(const chunk of Bun.stdin.stream()) {
    buffer+=new TextDecoder().decode(chunk);
    while(buffer.includes('\\n')) {
      const n=buffer.indexOf('\\n'); const line=buffer.slice(0,n); buffer=buffer.slice(n+1);
      const command=JSON.parse(line);
      console.log(JSON.stringify({type:'response',id:command.id,command:command.type,success:true,data:{}}));
      if(command.type==='prompt') {
        console.log(JSON.stringify({type:'message_end',message:{role:'assistant',content:[{type:'text',text:'{"ok":true}'}]}}));
        console.log(JSON.stringify({type:'agent_settled'}));
        process.exit(0);
      }
    }
  }
}
`;
    await writeFile(executable, code, { mode: 0o700 });
    const resources: SessionResources = {
      skills: [{ id: "skill-id", name: "review", content: "Review code", files: [{ path: "SKILL.md", content: "Review code" }, { path: "references/checks.md", content: "Bounded reference snapshot" }] }],
      servers: [{ id: "server-id", key: "argus_server_id", name: "local", connection: { type: "http", url: "https://example.test/mcp", headers: { Authorization: "private-token-value" } } }],
    };
    const harnessConfig = { ...DEFAULT_HARNESS_CONFIG[kind], executable };
    const adapter = kind === "pi" ? new PiHarnessAdapter(config, harnessConfig, {}) : new ClaudeCodeHarnessAdapter(config, harnessConfig, {});
    const result = await adapter.run({ runId: "session", auditId: "audit", taskId: "task", role: "codebase_mapper",
      prompt: "Return JSON", systemPrompt: "Test", workspace: project, model: "test-model", timeoutMs: 5_000, resources }, { onEvent() {} });
    expect(result.status).toBe("completed");
    expect(await Bun.file(join(project, "resource-scratch.txt")).text()).toBe("local resource session wrote a scratch file");
    const captured = await Bun.file(capture).json();
    expect(Object.keys(captured.mcp.mcpServers)).toEqual(["argus_server_id"]);
    expect(captured.mcp.mcpServers.argus_server_id.headers.Authorization).toBe("private-token-value");
    expect(captured.args.join(" ")).not.toContain("private-token-value");
    if (kind === "pi") {
      expect(captured.args.join(" ")).toContain("--tools +grep,+find,+ls");
      expect(captured.args).not.toContain("--no-builtin-tools");
      expect(captured.args).not.toContain("--no-mcp");
    } else {
      expect(captured.args).toContain("--strict-mcp-config");
      expect(captured.args.join(" ")).toContain("Bash");
      expect(captured.args.join(" ")).toContain("Edit");
    }
    expect(captured.args.join(" ")).not.toContain("private-token-value");
    expect(captured.skill).toBe("Bounded reference snapshot");
    if (kind === "pi") {
      expect(captured.args).not.toContain("--no-mcp");
    } else expect(captured.args).toContain("--strict-mcp-config");
    expect(existsSync(join(config.dataDir, "harness-homes/session"))).toBe(false);
  }, 15_000);
}
