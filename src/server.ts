import { existsSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";
import { createApi } from "./api/api.ts";
import { AuthService } from "./auth.ts";
import { APP_NAME, APP_VERSION, ensureRuntimeDirs, loadConfig } from "./config.ts";
import { Store } from "./db/index.ts";
import { EventLog } from "./events.ts";
import { HarnessManager } from "./harness/manager.ts";
import { AuditEngine } from "./orchestrator/engine.ts";
import { EvidenceStore } from "./orchestrator/evidence.ts";
import { ReportService } from "./reports/generator.ts";
import { getSetting, seedDefaults } from "./settings.ts";
import { LocalCatalog } from "./local/catalog.ts";

const config = loadConfig();
ensureRuntimeDirs(config);
const store = new Store(config);
seedDefaults(store, config);
const persistedSandbox = getSetting(store, "security.sandbox_mode", config.sandboxMode);
if (persistedSandbox === "auto" || persistedSandbox === "bwrap" || persistedSandbox === "none") {
  config.sandboxMode = persistedSandbox;
}
const auth = new AuthService(config, store);
await auth.bootstrap();
const events = new EventLog(store);
const manager = new HarnessManager(config, store);
const evidence = new EvidenceStore(config, store);
const reports = new ReportService(config, store, evidence, events);
const catalog = new LocalCatalog(store);
void catalog.refresh().catch((error) => console.error("[argus] Local discovery failed:", error));
const engine = new AuditEngine(config, store, manager, evidence, events, reports, catalog);
engine.start();
void manager.detectAll(true).catch((error) => {
  console.error("[argus] Harness detection failed:", error);
});

const api = createApi({ config, store, auth, events, manager, engine, evidence, reports, catalog });

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".map": "application/json; charset=utf-8",
};

function securityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "no-referrer");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set(
    "content-security-policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
  );
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function serveStatic(request: Request, pathname: string): Promise<Response> {
  if (!["GET", "HEAD"].includes(request.method)) {
    return new Response("Method not allowed", { status: 405 });
  }
  const dist = resolve(config.webDist);
  const relative = pathname === "/" ? "index.html" : decodeURIComponent(pathname.replace(/^\/+/, ""));
  const candidate = resolve(join(dist, normalize(relative)));
  if (!candidate.startsWith(`${dist}/`) && candidate !== dist) {
    return new Response("Not found", { status: 404 });
  }
  if (existsSync(candidate) && !candidate.endsWith("/")) {
    const file = Bun.file(candidate);
    if (await file.exists()) {
      return new Response(request.method === "HEAD" ? null : file, {
        headers: {
          "content-type": MIME[extname(candidate)] ?? "application/octet-stream",
          "cache-control": relative.includes("/assets/")
            ? "public, max-age=31536000, immutable"
            : "no-cache",
        },
      });
    }
  }
  const index = join(dist, "index.html");
  if (existsSync(index)) {
    return new Response(request.method === "HEAD" ? null : Bun.file(index), {
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache" },
    });
  }
  return new Response(
    `<!doctype html><html><body style="font-family:system-ui;background:#0b1016;color:#dce7f1;padding:40px">
      <h1>${APP_NAME} ${APP_VERSION}</h1>
      <p>The web dashboard has not been built yet.</p>
      <pre>bun run build:web</pre>
      <p>API health: <a style="color:#55d6be" href="/api/health">/api/health</a></p>
    </body></html>`,
    { status: 200, headers: { "content-type": "text/html; charset=utf-8" } },
  );
}

const server = Bun.serve({
  port: config.port,
  hostname: config.hostname,
  idleTimeout: 120,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      return securityHeaders(await api(request));
    }
    return securityHeaders(await serveStatic(request, url.pathname));
  },
  error(error) {
    console.error("[argus] Server error:", error);
    return securityHeaders(
      new Response(JSON.stringify({ error: { code: "internal_error", message: "Internal server error" } }), {
        status: 500,
        headers: { "content-type": "application/json" },
      }),
    );
  },
});

console.log(`[argus] ${APP_NAME} ${APP_VERSION} listening on http://${config.hostname}:${config.port}`);
console.log(`[argus] Data directory: ${config.dataDir}`);
console.log(`[argus] Sandbox mode: ${config.sandboxMode}; max concurrent agents: ${config.maxConcurrentAgents}`);

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[argus] ${signal} received; shutting down`);
  await engine.stop();
  server.stop(true);
  store.close();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
