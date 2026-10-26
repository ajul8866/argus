import { chromium, type Browser } from "playwright-core";
import { chmod, cp, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const temporary = await mkdtemp(join(tmpdir(), "argus-usability-"));
const source = join(temporary, "source");
const runtime = join(temporary, "runtime");
await cp(join(root, "test/fixtures/vulnerable-app"), source, { recursive: true });
await writeFile(runtime, '#!/bin/sh\nif [ "$1" = "--version" ]; then printf "qa-runtime\\n"; exit 0; fi\nif [ "$1" = "--list-models" ]; then printf "[]\\n"; exit 0; fi\nexit 64\n');
await chmod(runtime, 0o700);
const reservation = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() });
const port = reservation.port;
reservation.stop(true);
const base = `http://127.0.0.1:${port}`;
const password = crypto.randomUUID();
const env: Record<string, string | undefined> = {
  ...process.env, ARGUS_DATA_DIR: join(temporary, "data"), ARGUS_HOST: "127.0.0.1", ARGUS_PORT: String(port),
  ARGUS_ADMIN_EMAIL: "ui@test.local", ARGUS_ADMIN_PASSWORD: password, ARGUS_PI_BIN: runtime, ARGUS_CLAUDE_BIN: runtime,
  ARGUS_SECURE_COOKIES: "0", ARGUS_SANDBOX: "none", ARGUS_MAX_AGENTS: "2",
};
delete env.ARGUS_ALLOWED_ROOTS;
const server = Bun.spawn([process.execPath, "run", "src/server.ts"], { cwd: root, env, stdout: "ignore", stderr: "ignore" });
let browser: Browser | undefined;
const check = (condition: boolean, message: string) => { if (!condition) throw new Error(message); };
const screenshots = join(tmpdir(), "argus-usability-screenshots");
await mkdir(screenshots, { recursive: true });
try {
  const deadline = Date.now() + 15_000;
  for (;;) {
    try { if ((await fetch(`${base}/api/health`)).ok) break; } catch { /* Wait for startup. */ }
    if (Date.now() > deadline) throw new Error("Isolated UI server failed to start");
    await Bun.sleep(100);
  }
  browser = await chromium.launch({ executablePath: process.env.ARGUS_CHROME_BIN ?? "/usr/bin/google-chrome", headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
  const errors: string[] = [];
  const writes: Array<{ settings: Record<string, unknown> }> = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type()) && !/401|503/.test(message.text())) errors.push(message.text());
  });
  page.on("request", (request) => {
    if (request.url().endsWith("/api/settings") && request.method() === "PUT") writes.push(request.postDataJSON() as { settings: Record<string, unknown> });
  });
  await page.goto(base);
  await page.getByLabel("Email", { exact: true }).fill("ui@test.local");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.locator(".sidebar").waitFor();
  check(await page.locator('.sidebar a[data-route]:visible').count() === 6, "default navigation must show six destinations");
  await page.getByRole("button", { name: "New audit", exact: true }).first().click();
  const projectForm = page.getByRole("dialog", { name: "New project", exact: true });
  await projectForm.waitFor();
  await projectForm.getByRole("button", { name: "Browse folders", exact: true }).click();
  const picker = page.getByRole("dialog", { name: "Choose repository folder", exact: true });
  await picker.locator("summary").click();
  await picker.getByLabel("Folder path", { exact: true }).fill(source);
  await picker.getByRole("button", { name: "Open", exact: true }).click();
  await page.waitForFunction((path) => document.querySelector<HTMLInputElement>('[name="folder_path"]')?.value === path, source);
  await picker.getByRole("button", { name: "Use this folder", exact: true }).click();
  await picker.waitFor({ state: "detached" });
  await projectForm.getByLabel("Project name", { exact: true }).fill("Usability QA");
  const automaticImport = page.waitForResponse((response) => /\/api\/projects\/[^/]+\/import$/.test(response.url()));
  await projectForm.getByRole("button", { name: "Create project", exact: true }).click();
  check((await automaticImport).status() === 201, "project creation must import files automatically");
  await projectForm.waitFor({ state: "detached" });
  await page.getByRole("heading", { name: "Usability QA", exact: true }).waitFor();
  await page.getByRole("button", { name: "New audit", exact: true }).first().click();
  const auditForm = page.getByRole("dialog", { name: "New audit", exact: true });
  await auditForm.getByRole("button", { name: "Start audit", exact: true }).waitFor({ state: "visible" });
  check(await auditForm.locator('input:visible, select:visible, textarea:visible').count() === 0, "single-project audit must need no configuration");
  check(await auditForm.locator('[name="writable_workspace"]').count() === 0, "disabled write policy must not add a dead checkbox");
  for (const width of [320, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 960 });
    check(await auditForm.evaluate((element) => element.scrollWidth <= element.clientWidth), `${width}: audit form overflows`);
    await page.screenshot({ path: join(screenshots, `audit-${width}.png`), fullPage: true });
  }
  await page.route("**/api/audits/*/start", (route) => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { code: "test_start_failure", message: "Test start is paused" } }) }));
  const creation = page.waitForResponse((response) => response.url().endsWith("/api/audits") && response.request().method() === "POST");
  await auditForm.getByRole("button", { name: "Start audit", exact: true }).click();
  const created = (await (await creation).json()) as { audit: { id: string; config: string } };
  check(JSON.parse(created.audit.config).max_areas === 4, "audit should inherit server defaults");
  await page.waitForURL(`**/#/audits/${created.audit.id}`);
  await auditForm.waitFor({ state: "detached" });
  const auditRegistry = await (await page.request.get(`${base}/api/audits`)).json() as { audits: Array<{ id: string }> };
  check(auditRegistry.audits.length === 1, "failed start must preserve exactly one saved audit");

  await page.goto(`${base}/#/settings`);
  await page.getByRole("button", { name: "Save settings", exact: true }).waitFor();
  check(await page.locator(".setting-row:visible").count() === 3, "settings should show only three common defaults");
  await page.locator("summary").filter({ hasText: "Advanced execution settings" }).click();
  await page.getByRole("switch", { name: "Allow shell tools", exact: true }).click();
  await page.getByRole("switch", { name: "Allow writable workspaces", exact: true }).click();
  await page.getByRole("button", { name: "Save settings", exact: true }).click();
  await page.getByRole("button", { name: "Enable shell tools", exact: true }).click();
  const enabled = page.waitForResponse((response) => response.url().endsWith("/api/settings") && response.request().method() === "PUT");
  await page.getByRole("button", { name: "Enable writable workspaces", exact: true }).click();
  check((await enabled).status() === 200, "first enablement must save after confirmation");
  await page.getByLabel("Report organization", { exact: true }).fill("Changed organization");
  const changed = page.waitForResponse((response) => response.url().endsWith("/api/settings") && response.request().method() === "PUT");
  await page.getByRole("button", { name: "Save settings", exact: true }).click();
  check((await changed).status() === 200, "unrelated settings must save without repeated enablement dialogs");
  check(Object.keys(writes.at(-1)!.settings).join() === "reports.organization", "only changed settings should be sent");
  await page.getByLabel("Report organization", { exact: true }).waitFor();
  const beforeNoChange = writes.length;
  await page.getByRole("button", { name: "Save settings", exact: true }).click();
  await page.getByText("No changes to save.", { exact: true }).waitFor();
  check(writes.length === beforeNoChange, "unchanged settings must not write or require confirmation");

  await page.locator("summary").filter({ hasText: "Add credential (optional)" }).click();
  check(await page.locator('[name="provider"]:visible').count() === 0, "provider scoping must be optional");
  await page.locator('[name="env_var"]').fill("UI_TEST_API_KEY");
  await page.locator('[name="value"]').fill("fixture-only-secret");
  const credentialWrite = page.waitForResponse((response) => response.url().endsWith("/api/credentials") && response.request().method() === "PUT");
  await page.getByRole("button", { name: "Store credential", exact: true }).click();
  check((await credentialWrite).status() === 200, "default credential scope should work");
  const credentials = await (await page.request.get(`${base}/api/credentials`)).json() as { credentials: Array<{ provider: string }> };
  check(credentials.credentials[0]?.provider === "global", "credential should default to global scope");
  check(!JSON.stringify(credentials).includes("fixture-only-secret"), "credential value must not be returned");

  await page.goto(`${base}/#/harnesses`);
  const pi = page.locator(".harness-card").filter({ hasText: "Pi Coding Agent" });
  await pi.getByRole("button", { name: "Use for audits", exact: true }).waitFor();
  check(await pi.locator(".cap-grid:visible").count() === 0, "runtime capabilities should be under technical details");
  const assigned = page.waitForResponse((response) => response.url().endsWith("/api/harnesses/pi/assign"));
  await pi.getByRole("button", { name: "Use for audits", exact: true }).click();
  check((await assigned).status() === 200, "one runtime assignment must succeed");
  const agents = await (await page.request.get(`${base}/api/agents`)).json() as { agents: Array<{ role: string; harness: string; model: string | null; allow_shell: boolean }> };
  const roles = agents.agents.filter((agent) => ["codebase_mapper", "security_researcher", "independent_validator", "retest_auditor"].includes(agent.role));
  check(roles.length === 4 && roles.every((agent) => agent.harness === "pi" && agent.model === null && !agent.allow_shell), "all roles must use explicit runtime defaults and read-only tools");
  await pi.getByRole("button", { name: "Configure", exact: true }).click();
  const config = page.getByRole("dialog", { name: "Configure Pi Coding Agent", exact: true });
  check(await config.locator("input:visible, select:visible").count() === 2, "runtime setup should show provider and model only");
  await page.keyboard.press("Escape");

  await page.goto(`${base}/#/agents`);
  await page.getByRole("button", { name: "Edit", exact: true }).first().click();
  const roleForm = page.locator('[role="dialog"]');
  check(await roleForm.locator("input:visible, select:visible, textarea:visible").count() === 2, "role form should show runtime and model only");
  check(await roleForm.locator('[name="concurrency_limit"]').count() === 0, "nonfunctional role concurrency control must be removed");
  await roleForm.locator("summary").click();
  await roleForm.getByLabel("Max duration (seconds)", { exact: true }).fill("1");
  await roleForm.locator("summary").click();
  await roleForm.getByRole("button", { name: "Save role", exact: true }).click();
  check(await roleForm.locator("details").evaluate((element) => element instanceof HTMLDetailsElement && element.open), "invalid hidden fields must open their section");
  await page.keyboard.press("Escape");

  const routes = ["dashboard", "projects", "audits", "findings", "reports", "settings", "harnesses", "agents", "skills", "mcp", "explorer", "tasks", "approvals"];
  for (const width of [320, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 960 });
    for (const route of routes) {
      await page.goto(`${base}/#/${route}`);
      await page.waitForFunction(() => document.querySelector("#view h1") && !document.querySelector("#view .loading-state"));
      check(await page.locator("#view .error-state").count() === 0, `${route} failed to render`);
      check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${route} overflows at ${width}px`);
      if (width === 320 || width === 1440) await page.screenshot({ path: join(screenshots, `${route}-${width}.png`), fullPage: true });
    }
  }
  const adminSession = await (await page.request.get(`${base}/api/auth/me`)).json() as { csrf: string };
  const addedViewer = await page.request.post(`${base}/api/users`, {
    headers: { "x-csrf-token": adminSession.csrf },
    data: { email: "viewer@test.local", name: "Viewer", password, role: "viewer" },
  });
  check(addedViewer.status() === 201, "viewer setup failed");
  const viewerContext = await browser.newContext();
  const viewer = await viewerContext.newPage();
  const forbiddenRequests: string[] = [];
  viewer.on("request", (request) => { if (/\/api\/(users|audit-log)$/.test(request.url())) forbiddenRequests.push(request.url()); });
  await viewer.goto(base);
  await viewer.getByLabel("Email", { exact: true }).fill("viewer@test.local");
  await viewer.getByLabel("Password", { exact: true }).fill(password);
  await viewer.getByRole("button", { name: "Sign in", exact: true }).click();
  await viewer.locator(".sidebar").waitFor();
  for (const route of ["dashboard", "projects", "audits", "settings", `audits/${created.audit.id}`]) {
    await viewer.goto(`${base}/#/${route}`);
    await viewer.waitForFunction(() => document.querySelector("#view h1") && !document.querySelector("#view .loading-state"));
    check(await viewer.getByRole("button", { name: "New audit", exact: true }).count() === 0, "viewers must not see audit-creation actions");
    check(await viewer.getByRole("button", { name: "Start audit", exact: true }).count() === 0, "viewers must not see start actions");
    check(await viewer.getByRole("button", { name: "New project", exact: true }).count() === 0, "viewers must not see project-creation actions");
  }
  check(forbiddenRequests.length === 0, "viewer settings must not request administrator resources");
  await viewerContext.close();
  check(errors.length === 0, `Browser errors: ${errors.join("; ")}`);
  console.log("Usability UI passed: automatic import, default audit setup, start-failure recovery, changed-only settings, one-time enablement, optional credentials, one-runtime setup, advanced controls, keyboard validation, and all 13 routes at 320/768/1024/1440px. No model calls were made.");
  console.log(`Screenshots: ${screenshots}`);
} finally {
  await browser?.close();
  server.kill("SIGTERM");
  await Promise.race([server.exited, Bun.sleep(5_000)]);
  if (server.exitCode === null) { server.kill("SIGKILL"); await server.exited; }
  await rm(temporary, { recursive: true, force: true });
}
