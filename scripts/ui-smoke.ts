import { chromium } from "playwright-core";

const base = process.env.ARGUS_BASE_URL ?? "http://127.0.0.1:8899";
const email = process.env.ARGUS_ADMIN_EMAIL ?? "admin@argus.local";
const password = process.env.ARGUS_ADMIN_PASSWORD;
if (!password) {
  console.error("ARGUS_ADMIN_PASSWORD is required for the UI smoke test");
  process.exit(1);
}

const browser = await chromium.launch({
  executablePath: process.env.ARGUS_CHROME_BIN ?? "/usr/bin/google-chrome",
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
});
const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
const errors: string[] = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
page.on("console", (message) => {
  if (message.type() === "error" && !message.text().includes("401 (Unauthorized)")) {
    errors.push(`console: ${message.text()}`);
  }
});

await page.goto(base, { waitUntil: "networkidle" });
await page.locator('input[name="email"]').fill(email);
await page.locator('input[name="password"]').fill(password);
await page.getByRole("button", { name: "Sign in" }).click();
await page.locator(".sidebar").waitFor({ timeout: 20_000 });
await page.waitForTimeout(800);
await page.screenshot({ path: "/tmp/opencode/argus-dashboard.png", fullPage: true });

const routes: Array<[string, string]> = [
  ["projects", "#/projects"],
  ["harnesses", "#/harnesses"],
  ["agents", "#/agents"],
  ["tasks", "#/tasks"],
  ["findings", "#/findings"],
  ["reports", "#/reports"],
  ["settings", "#/settings"],
  ["explorer", "#/explorer"],
];
if (process.env.ARGUS_AUDIT_ID) {
  routes.unshift(["audit", `#/audits/${process.env.ARGUS_AUDIT_ID}`]);
}
for (const [name, hash] of routes) {
  await page.goto(`${base}/${hash}`, { waitUntil: "networkidle" });
  await page.waitForFunction(() => !document.querySelector(".loading-state"), { timeout: 30_000 }).catch(() => {});
  await page.waitForTimeout(600);
  await page.screenshot({ path: `/tmp/opencode/argus-${name}.png`, fullPage: true });
  const heading = await page.locator("h1").first().textContent().catch(() => null);
  console.log(`${name}: ${heading?.trim() ?? "(no heading)"}`);
}

console.log(`console/page errors: ${errors.length}`);
for (const error of errors) console.log(error);
await browser.close();
if (errors.length > 0) process.exit(1);
