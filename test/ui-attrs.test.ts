import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";

const chrome = ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser"].find((path) => existsSync(path));

test.skipIf(!chrome)("ARIA false states survive element creation", async () => {
  const directory = mkdtempSync(join(tmpdir(), "argus-ui-"));
  const entry = join(directory, "entry.ts");
  const uiPath = join(import.meta.dir, "../web/src/ui.ts");
  writeFileSync(entry, `import { button, h } from ${JSON.stringify(uiPath)};\nObject.assign(globalThis, { button, h });\n`);
  const built = await Bun.build({
    entrypoints: [entry],
    target: "browser",
    format: "esm",
    outdir: directory,
  });
  expect(built.success).toBe(true);
  const output = built.outputs.find((file) => file.path.endsWith(".js"));
  expect(output).toBeDefined();
  const source = await output!.text();
  const { chromium } = await import("playwright-core");
  const browser = await chromium.launch({
    executablePath: chrome,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
  });
  try {
    const page = await browser.newPage();
    await page.setContent("<!doctype html><html><body></body></html>");
    await page.addScriptTag({ content: source, type: "module" });
    await page.waitForFunction(() => "h" in globalThis);
    const result = await page.evaluate(() => {
      const ui = globalThis as unknown as {
        h: (tag: string, attrs?: Record<string, unknown>, ...children: unknown[]) => HTMLElement;
        button: (label: string, onclick: () => void, tone?: string, extra?: Record<string, unknown>) => HTMLButtonElement;
      };
      const off = ui.h("button", { type: "button", "aria-pressed": false, "aria-label": "Allow shell tools" });
      const on = ui.h("button", { type: "button", "aria-pressed": true, "aria-label": "Allow shell tools" });
      const omitted = ui.h("a", { href: "#/dashboard", "aria-current": null });
      const unchecked = ui.h("input", { type: "checkbox", checked: false });
      const server = ui.button("filesystem", () => {}, "ghost", { class: "local-server-button", "aria-pressed": false });
      document.body.append(off, on, omitted, unchecked, server);
      return {
        off: off.getAttribute("aria-pressed"),
        on: on.getAttribute("aria-pressed"),
        current: omitted.hasAttribute("aria-current"),
        checked: (unchecked as HTMLInputElement).checked,
        checkedAttr: unchecked.hasAttribute("checked"),
        serverPressed: server.getAttribute("aria-pressed"),
        serverClass: server.className,
      };
    });
    expect(result).toEqual({
      off: "false",
      on: "true",
      current: false,
      checked: false,
      checkedAttr: false,
      serverPressed: "false",
      serverClass: "btn btn-ghost local-server-button",
    });
  } finally {
    await browser.close();
  }
});
