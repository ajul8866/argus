import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";

function iconPath(source: string, name: string): string {
  const match = source.match(new RegExp(`\\n\\s*${name}: "([^"]+)"`));
  if (!match?.[1]) throw new Error(`missing icon path for ${name}`);
  return match[1];
}

test("mobile navigation toggle uses a menu glyph, not the tasks checklist", () => {
  const ui = readFileSync(new URL("../web/src/ui.ts", import.meta.url), "utf8");
  const main = readFileSync(new URL("../web/src/main.ts", import.meta.url), "utf8");
  const menu = iconPath(ui, "menu");
  const tasks = iconPath(ui, "tasks");

  expect(menu).toBe("M3 5h14 M3 10h14 M3 15h14");
  expect(menu).not.toBe(tasks);
  expect(tasks).toContain("l1 1 2-2");

  const toggleAt = main.indexOf('class: "btn btn-ghost btn-icon mobile-toggle"');
  expect(toggleAt).toBeGreaterThan(-1);
  const toggle = main.slice(toggleAt, toggleAt + 700);
  expect(toggle).toContain('icon("menu")');
  expect(toggle).not.toContain("tasks");
  expect(toggle).toContain('"aria-label": "Open navigation"');
});
