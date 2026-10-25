import { loadConfig } from "../src/config.ts";
import { Store } from "../src/db/index.ts";
import { HarnessManager } from "../src/harness/manager.ts";
import { seedDefaults } from "../src/settings.ts";

const config = loadConfig();
const store = new Store(config);
seedDefaults(store, config);
const manager = new HarnessManager(config, store);

const detections = await manager.detectAll(true);
for (const detection of detections) {
  console.log(`${detection.label}: ${detection.status} (${detection.version ?? "version unknown"})`);
  console.log(`  executable: ${detection.executable}`);
  console.log(`  detail: ${detection.detail}`);
  console.log(`  auth: ${detection.auth.ready ? "ready" : "not verified"} — ${detection.auth.detail}`);
  console.log(`  models: ${detection.models.length}`);
}
for (const kind of ["pi", "claude-code"] as const) {
  const health = await manager.health(kind, true);
  console.log(`health ${kind}: ${health.status} — ${health.detail}`);
  if (!health.auth.ready) process.exitCode = 2;
}
store.close();
