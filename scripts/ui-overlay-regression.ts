/**
 * Browser regression for the shared overlay contract.
 *
 * This is intentionally independent of Argus audit data: it builds a small
 * fixture against web/src/ui.ts, then verifies nested drawer + confirmation
 * focus, Escape layering, backdrop dismissal, hash cleanup, and the Tab trap.
 *
 * Run with: bun run test:ui-overlay
 */
import { chromium, type Browser } from "playwright-core";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

type OverlayServer = { port: number | undefined; stop(closeActiveConnections?: boolean): void };
type TestWindow = Window & { __lastConfirm?: boolean | null; __overlayCloses?: { count: number } };

const root = resolve(import.meta.dir, "..");
const fixture = join(root, "test", "fixtures", "overlay", "entry.ts");
const temp = await mkdtemp(join(tmpdir(), "argus-overlay-"));
const errors: string[] = [];
function check(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}


let server: OverlayServer | null = null;
let browser: Browser | null = null;
let failed = false;

try {
  const build = await Bun.build({
    entrypoints: [fixture],
    outdir: temp,
    target: "browser",
    format: "esm",
    minify: false,
  });
  if (!build.success) {
    for (const log of build.logs) console.error(log);
    throw new Error("Overlay fixture build failed");
  }
  const output = build.outputs.find((entry) => entry.path.endsWith(".js"));
  if (!output) throw new Error("Overlay fixture produced no JavaScript bundle");
  const javascript = await Bun.file(output.path).text();
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  html, body { margin: 0; font: 16px system-ui, sans-serif; background: #151515; color: #eee; }
  #app { padding: 24px; }
  button { font: inherit; padding: 8px 12px; }
  .modal-overlay, .drawer-overlay { position: fixed; inset: 0; z-index: 10; display: flex; align-items: center; justify-content: center; background: color-mix(in oklab, #000 72%, transparent); }
  .drawer-overlay { justify-content: flex-end; padding: 0; }
  .modal, .drawer { width: 320px; box-sizing: border-box; padding: 20px; background: #1e1e1e; border: 1px solid #444; color: #eee; }
  .drawer { height: 100vh; }
  .modal-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
</style>
</head>
<body>
<div id="app"></div>
<div id="result"></div>
<script type="module" src="/entry.js"></script>
</body>
</html>`;

  const running = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const pathname = new URL(request.url).pathname;
      if (pathname === "/entry.js") {
        return new Response(javascript, { headers: { "content-type": "text/javascript; charset=utf-8" } });
      }
      if (pathname === "/" || pathname === "/index.html") {
        return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      return new Response("Not found", { status: 404 });
    },
  });
  server = running;
  const port = running.port;
  if (port === undefined) throw new Error("Overlay fixture server did not bind a port");

  browser = await chromium.launch({
    executablePath: process.env.ARGUS_CHROME_BIN ?? "/usr/bin/google-chrome",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
  });
  const page = await browser.newPage({ viewport: { width: 900, height: 700 } });
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));

  const activeLabel = () => page.evaluate(() => document.activeElement?.getAttribute("aria-label") ?? null);
  const activeId = () => page.evaluate(() => document.activeElement?.id ?? null);
  const activeText = () => page.evaluate(() => document.activeElement?.textContent?.trim() ?? null);
  const lastConfirm = () => page.evaluate(() => (window as TestWindow).__lastConfirm);
  const overlayCloseCount = () => page.evaluate(() => (window as TestWindow).__overlayCloses?.count ?? -1);
  const overlayCounts = () => page.evaluate(() => ({
    drawers: document.querySelectorAll(".drawer-overlay").length,
    modals: document.querySelectorAll(".modal-overlay").length,
    appInert: document.getElementById("app")?.inert ?? false,
  }));

  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "load" });
  await page.evaluate(() => {
    const record = { count: 0 };
    (window as TestWindow).__overlayCloses = record;
    window.addEventListener("argus:overlays-closed", () => {
      record.count += 1;
    });
  });
  await page.waitForSelector("#open-drawer");

  await page.click("#open-drawer");
  await page.waitForSelector(".drawer-overlay");
  await page.waitForFunction(() => document.activeElement?.getAttribute("aria-label") === "Close");
  check(await activeLabel() === "Close", "drawer should focus its close control");
  check((await overlayCounts()).appInert, "app should be inert while the drawer is open");

  await page.click("#confirm-trigger");
  await page.waitForSelector(".modal-overlay");
  await page.waitForFunction(() => document.activeElement?.textContent?.trim() === "Cancel");
  check((await overlayCounts()).modals === 1 && (await overlayCounts()).drawers === 1, "confirmation should stack over the drawer");
  check(await activeText() === "Cancel", "confirmation should focus Cancel first");

  await page.keyboard.press("Escape");
  await page.waitForSelector(".modal-overlay", { state: "detached" });
  check((await overlayCounts()).drawers === 1, "Escape should close only the top confirmation");
  check(await lastConfirm() === false, "Escape should resolve the confirmation as false");
  check(await activeId() === "confirm-trigger", "focus should return to the confirmation trigger inside the drawer");
  check(await overlayCloseCount() === 0, "closing a nested dialog should not signal that the overlay stack is clear");

  await page.click("#confirm-trigger");
  await page.waitForSelector(".modal-overlay");
  await page.waitForFunction(() => document.activeElement?.textContent?.trim() === "Cancel");
  await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
  await page.waitForSelector(".modal-overlay", { state: "detached" });
  check(await lastConfirm() === false, "backdrop dismissal should resolve the confirmation as false");
  check(await activeId() === "confirm-trigger", "backdrop dismissal should return focus to the trigger");
  check((await overlayCounts()).drawers === 1, "backdrop dismissal should leave the drawer open");

  await page.keyboard.press("Escape");
  await page.waitForSelector(".drawer-overlay", { state: "detached" });
  check((await overlayCounts()).appInert === false, "closing the last overlay should clear app inert");
  check(await activeId() === "open-drawer", "closing the drawer should restore focus to its trigger");
  check(await overlayCloseCount() === 1, "closing the last overlay should notify listeners once");

  await page.click("#open-drawer");
  await page.waitForSelector(".drawer-overlay");
  await page.evaluate(() => { location.hash = "#changed"; });
  await page.waitForSelector(".drawer-overlay", { state: "detached" });
  check((await overlayCounts()).modals === 0, "hash changes should close open overlays");
  check(await overlayCloseCount() === 2, "hash changes should notify listeners when the last overlay closes");

  await page.click("#open-drawer");
  await page.waitForSelector(".drawer-overlay");
  for (let index = 0; index < 12; index += 1) {
    await page.keyboard.press("Tab");
    check(await page.evaluate(() => Boolean(document.querySelector(".drawer-overlay")?.contains(document.activeElement))), `Tab ${index + 1} escaped the drawer`);
  }

  check(errors.length === 0, `browser errors: ${errors.join("; ")}`);
  console.log("overlay regression passed: nested Escape, backdrop dismissal, hash cleanup, focus restoration, Tab trap, and overlay-close signal");
} catch (error) {
  console.error("overlay regression failed:", error);
  failed = true;
} finally {
  if (browser) await browser.close().catch(() => {});
  server?.stop(true);
  await rm(temp, { recursive: true, force: true });
  if (errors.length > 0) {
    for (const error of errors) console.error(error);
    failed = true;
  }
  if (failed) process.exit(1);
}
