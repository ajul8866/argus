import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { APP_NAME, APP_VERSION } from "../src/config.ts";

if (!Bun.semver.satisfies(Bun.version, ">=1.3.14")) {
  console.error(`[argus] Bun >= 1.3.14 is required; found ${Bun.version}.`);
  process.exit(1);
}

const rawPort = process.env.ARGUS_PORT || "8787";
const port = Number(rawPort);
if (!/^\d+$/.test(rawPort) || !Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  console.error("[argus] ARGUS_PORT must be an integer between 1 and 65535.");
  process.exit(1);
}

process.env.ARGUS_HOST ||= "127.0.0.1";
process.env.ARGUS_PORT = String(port);
const webDist = resolve(process.env.ARGUS_WEB_DIST || resolve(import.meta.dir, "../web/dist"));
if (!existsSync(resolve(webDist, "index.html"))) {
  console.error("[argus] Dashboard assets are missing. Run: bun install --frozen-lockfile && bun run build");
  process.exit(1);
}

try {
  const probe = Bun.listen({
    hostname: process.env.ARGUS_HOST,
    port,
    socket: { data() {} },
  });
  probe.stop(true);
} catch (error) {
  const code = (error as NodeJS.ErrnoException).code;
  console.error(code === "EADDRINUSE"
    ? `[argus] Port ${port} is already in use. Choose another: ARGUS_PORT=8899 bash start.sh`
    : `[argus] Cannot listen on ${process.env.ARGUS_HOST}:${port}: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}

console.log(`[argus] Starting ${APP_NAME} v${APP_VERSION}. Press Ctrl+C to stop.`);
console.log("[argus] First sign-in: use the credentials in <data directory>/bootstrap-admin.txt, then change the password in Settings.");
await import("../src/server.ts");
