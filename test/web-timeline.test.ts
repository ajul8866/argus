import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

class DomNode {
  readonly childNodes: DomNode[] = [];
  appendChild(child: DomNode): DomNode {
    this.childNodes.push(child);
    return child;
  }
}

class DomText extends DomNode {
  constructor(readonly data: string) {
    super();
  }
}

class DomElement extends DomNode {
  className = "";
  readonly attributes = new Map<string, string>();
  readonly style = { setProperty(): void {} };
  dataset: Record<string, string> = {};
  constructor(readonly tagName: string) {
    super();
  }
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }
  addEventListener(): void {}
}

function installDom(): () => void {
  const root = globalThis as unknown as { Node?: unknown; document?: unknown };
  const previous = { Node: root.Node, document: root.document };
  root.Node = DomNode;
  root.document = {
    createElement: (tag: string) => new DomElement(tag),
    createTextNode: (text: string) => new DomText(text),
  };
  return () => {
    root.Node = previous.Node;
    root.document = previous.document;
  };
}

test("timeline entries keep a status dot for confirmed and failed verdicts", async () => {
  const restore = installDom();
  try {
    const ui = await import("../web/src/ui.ts");
    expect(ui.verificationTimelineTone("CONFIRMED")).toBe("on");
    expect(ui.verificationTimelineTone("REVERIFIED")).toBe("on");
    expect(ui.verificationTimelineTone("REJECTED")).toBe("bad");
    expect(ui.verificationTimelineTone("FALSE_POSITIVE")).toBe("bad");

    for (const tone of ["on", "bad"] as const) {
      const entry = ui.timelineEntry(tone, `${tone} label`) as unknown as DomElement;
      expect(entry.tagName).toBe("div");
      expect(entry.className).toBe(`timeline-item ${tone}`);
      const dot = entry.childNodes[0] as DomElement;
      expect(dot.tagName).toBe("span");
      expect(dot.className).toBe("timeline-dot");
      expect(dot.attributes.get("aria-hidden")).toBe("true");
      const label = entry.childNodes[1] as DomText;
      expect(label.data).toBe(`${tone} label`);
    }
  } finally {
    restore();
  }
});

test("timeline stylesheet still colors status dots", () => {
  const css = readFileSync(join(import.meta.dir, "../web/src/styles.css"), "utf8");
  expect(css).toContain(".timeline-item.on .timeline-dot { background: var(--accent); }");
  expect(css).toContain(".timeline-item.bad .timeline-dot { background: var(--red); }");
});

test("finding history and the project workflow render timeline entries", () => {
  const finding = readFileSync(join(import.meta.dir, "../web/src/components/execution-detail.ts"), "utf8");
  const projects = readFileSync(join(import.meta.dir, "../web/src/pages/projects.ts"), "utf8");
  expect(finding).toContain("timelineEntry(verificationTimelineTone(verification.verdict)");
  expect(projects).toContain('timelineEntry("on"');
});
