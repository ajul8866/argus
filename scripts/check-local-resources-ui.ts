import { chromium } from "playwright-core";
import { readFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const base = process.env.ARGUS_BASE_URL ?? "http://127.0.0.1:8899";
const bootstrapPath = join(import.meta.dir, "../data/bootstrap-admin.txt");
const bootstrap = existsSync(bootstrapPath) ? readFileSync(bootstrapPath, "utf8") : "";
const email = process.env.ARGUS_ADMIN_EMAIL ?? bootstrap.match(/^Email: (.+)$/m)?.[1];
const password = process.env.ARGUS_ADMIN_PASSWORD ?? bootstrap.match(/^Password: (.+)$/m)?.[1];
if (!email || !password) throw new Error("Local test login credentials are unavailable");
const output = "/tmp/argus-local-ui";
mkdirSync(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.ARGUS_CHROME_BIN ?? "/usr/bin/google-chrome", headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => { if (["error", "warning"].includes(message.type()) && !message.text().includes("401 (Unauthorized)")) errors.push(message.text()); });
  await page.goto(base, { waitUntil: "networkidle" });
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.locator(".sidebar").waitFor();
  await page.getByRole("link", { name: "Skills", exact: true }).click();
  await page.locator(".local-resource-item").first().waitFor();
  const detected = await page.locator(".local-resource-item").count();
  await page.getByRole("searchbox", { name: "Search local skills" }).fill("api-and-interface-design");
  await page.locator(".local-resource-item").first().click();
  const mapper = page.getByRole("checkbox", { name: "Codebase Mapper", exact: true });
  await mapper.waitFor();
  const original = await mapper.isChecked();
  await mapper.setChecked(!original);
  await page.getByRole("button", { name: "Save access", exact: true }).click();
  await page.getByText("Saved. Applies to new agent sessions.", { exact: true }).waitFor();
  await page.reload({ waitUntil: "networkidle" });
  await page.getByRole("searchbox", { name: "Search local skills" }).fill("api-and-interface-design");
  await page.locator(".local-resource-item").first().click();
  await mapper.waitFor();
  if ((await mapper.isChecked()) === original) throw new Error("Role access did not persist across reload");
  await mapper.setChecked(original);
  await page.getByRole("button", { name: "Save access", exact: true }).click();
  await page.getByText("Saved. Applies to new agent sessions.", { exact: true }).waitFor();
  await page.getByRole("button", { name: "SKILL.md", exact: true }).click();
  await page.waitForFunction(() => document.querySelector(".local-file-preview")?.textContent?.includes("---"));
  await page.getByRole("heading", { name: "Skills", exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: join(output, "skills-desktop.png"), fullPage: true });
  await page.getByRole("button", { name: "Rescan local", exact: true }).click();
  await page.getByRole("link", { name: "MCP servers", exact: true }).first().click();
  await page.locator(".local-mcp-table tbody tr").first().waitFor();
  const servers = await page.locator(".local-mcp-table tbody tr").count();
  await page.getByRole("searchbox", { name: "Search local MCP servers" }).fill("playwright");
  await page.locator(".local-server-button").first().click();
  const availability = page.getByRole("checkbox", { name: "Allow use by linked skills in Argus" });
  await availability.waitFor();
  const wasEnabled = await availability.isChecked();
  await availability.setChecked(!wasEnabled);
  await page.getByText("MCP access setting saved.", { exact: true }).waitFor();
  await availability.setChecked(wasEnabled);
  await page.getByText("MCP access setting saved.", { exact: true }).waitFor();
  await page.getByRole("heading", { name: "MCP servers", exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: join(output, "mcp-desktop.png"), fullPage: true });
  const sizes: Array<{ route: string; width: number; overflow: number }> = [];
  for (const route of ["skills", "mcp"]) {
    for (const width of [320, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 960 });
      await page.goto(`${base}/#/${route}`, { waitUntil: "networkidle" });
      await page.locator(".local-page").waitFor();
      await page.waitForFunction(() => !document.querySelector(".local-detail .loading-state"));
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      sizes.push({ route, width, overflow });
      if (overflow > 1) throw new Error(`${route} overflows at ${width}px by ${overflow}px`);
      if (width === 320) await page.screenshot({ path: join(output, `${route}-mobile.png`), fullPage: true });
    }
  }
  if (errors.length) throw new Error(`Browser console errors: ${errors.join("; ")}`);
  console.log(JSON.stringify({ detected_skills: detected, detected_servers: servers, role_access_persisted: true, access_settings_restored: true, responsive_sizes: sizes, console_errors: errors.length, screenshots: output }, null, 2));
} finally { await browser.close(); }
