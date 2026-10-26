import { confirmAction, drawer } from "../../../web/src/ui.ts";

type TestWindow = Window & { __lastConfirm?: boolean | null };

const testWindow = window as TestWindow;
const root = document.getElementById("app")!;

function recordConfirm(value: boolean): void {
  testWindow.__lastConfirm = value;
  const result = document.getElementById("result");
  if (result) result.textContent = String(value);
}

async function openConfirm(): Promise<void> {
  const confirmed = await confirmAction("Nested confirmation", "Confirm the nested action.", "Confirm");
  recordConfirm(confirmed);
}

function openDrawer(): void {
  const body = document.createElement("div");
  const trigger = document.createElement("button");
  trigger.id = "confirm-trigger";
  trigger.type = "button";
  trigger.textContent = "Open confirm";
  trigger.addEventListener("click", () => void openConfirm());
  body.appendChild(trigger);
  drawer("Regression drawer", body);
}

const open = document.createElement("button");
open.id = "open-drawer";
open.type = "button";
open.textContent = "Open drawer";
open.addEventListener("click", openDrawer);
root.appendChild(open);
