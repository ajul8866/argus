/**
 * Real end-to-end demonstration.
 *
 * Starts an isolated Argus server, imports the authorized local fixture, runs
 * the full six-phase workflow with Pi and Claude Code, then verifies and
 * downloads the generated reports. Nothing about the agents is simulated.
 */
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const fixture = join(root, "test", "fixtures", "vulnerable-app");
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const dataDir = process.env.ARGUS_E2E_DATA_DIR ?? await mkdtemp(join(tmpdir(), "argus-e2e-"));
const outputDir = join(root, "demo-output");
const port = Number(process.env.ARGUS_E2E_PORT ?? 8912);
const adminEmail = "admin@argus.local";
const adminPassword = randomBytes(24).toString("base64url");

await mkdir(dataDir, { recursive: true });
await mkdir(outputDir, { recursive: true });

const server = Bun.spawn(["bun", "run", "src/server.ts"], {
  cwd: root,
  env: {
    ...process.env,
    ARGUS_PORT: String(port),
    ARGUS_HOST: "127.0.0.1",
    ARGUS_DATA_DIR: dataDir,
    ARGUS_ADMIN_EMAIL: adminEmail,
    ARGUS_ADMIN_PASSWORD: adminPassword,
    ARGUS_MAX_AGENTS: "3",
    ARGUS_SANDBOX: process.env.ARGUS_SANDBOX ?? "auto",
    ARGUS_LOG_LEVEL: "info",
  },
  stdout: "inherit",
  stderr: "inherit",
});

let cookie = "";
let csrf = "";
const base = `http://127.0.0.1:${port}`;

function stopServer(): void {
  try {
    server.kill("SIGTERM");
  } catch {
    // already stopped
  }
}

try {
  await waitForHealth();
  await login();
  const project = await createProject();
  const repository = await importRepository(project.id);
  const audit = await createAndStartAudit(project.id, repository.id);
  const finished = await waitForAudit(audit.id);
  await verifyAndDownload(finished.id);
  console.log("\nREAL E2E AUDIT COMPLETED");
  console.log(`Audit: ${finished.id}`);
  console.log(`Data:  ${dataDir}`);
  console.log(`Reports: ${outputDir}`);
} catch (error) {
  console.error("\nREAL E2E FAILED:", error);
  stopServer();
  process.exit(1);
}

stopServer();
await server.exited;
process.exit(0);

async function waitForHealth(): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/api/health`);
      if (response.ok) return;
    } catch {
      // server still starting
    }
    await Bun.sleep(300);
  }
  throw new Error("Argus server did not become healthy");
}

async function login(): Promise<void> {
  const response = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: adminEmail, password: adminPassword }),
  });
  if (!response.ok) throw new Error(`Login failed: ${response.status} ${await response.text()}`);
  const setCookie = response.headers.get("set-cookie");
  if (!setCookie) throw new Error("Login did not return a session cookie");
  cookie = setCookie.split(";")[0]!;
  const body = (await response.json()) as { csrf: string };
  csrf = body.csrf;
}

async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = { cookie, accept: "application/json" };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.method && options.method !== "GET") headers["x-csrf-token"] = csrf;
  const response = await fetch(`${base}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (!response.ok) throw new Error(`${options.method ?? "GET"} ${path} failed: ${response.status} ${await response.text()}`);
  return (await response.json()) as T;
}

async function createProject(): Promise<{ id: string }> {
  const result = await api<{ project: { id: string } }>("/api/projects", {
    method: "POST",
    body: {
      name: "ACME Invoice Portal (E2E)",
      description: "Authorized local fixture for the real dual-harness demonstration",
      source_path: fixture,
      scope_include: ["**/*.js", "**/*.json", "README.md"],
      scope_exclude: [".git/**", "node_modules/**", "uploads/**"],
      authorized_by: "Argus E2E operator",
      authorization_ref: `LOCAL-E2E-${stamp}`,
      max_concurrent_agents: 3,
    },
  });
  console.log(`Project created: ${result.project.id}`);
  return result.project;
}

async function importRepository(projectId: string): Promise<{ id: string; file_count: number }> {
  const result = await api<{ repository: { id: string; file_count: number; commit_sha: string | null } }>(
    `/api/projects/${projectId}/import`,
    { method: "POST", body: {} },
  );
  console.log(`Repository snapshot imported: ${result.repository.id} (${result.repository.file_count} files, commit ${result.repository.commit_sha?.slice(0, 10) ?? "n/a"})`);
  return result.repository;
}

async function createAndStartAudit(projectId: string, repositoryId: string): Promise<{ id: string }> {
  const result = await api<{ audit: { id: string } }>("/api/audits", {
    method: "POST",
    body: {
      project_id: projectId,
      repository_id: repositoryId,
      overrides: {
        max_areas: 2,
        max_candidates_per_area: 2,
        max_confirmations: 3,
        max_reverifications: 3,
        max_concurrent_agents: 3,
        require_distinct_harness_for_retest: true,
      },
    },
  });
  await api(`/api/audits/${result.audit.id}/start`, { method: "POST", body: {} });
  console.log(`Audit started: ${result.audit.id}`);
  return result.audit;
}

async function waitForAudit(auditId: string): Promise<{ id: string; status: string }> {
  const deadline = Date.now() + 45 * 60 * 1000;
  let lastLine = "";
  while (Date.now() < deadline) {
    const detail = await api<{
      audit: { status: string; current_phase: number };
      phases: Array<{ phase: number; status: string }>;
      task_counts: Record<string, number>;
    }>(`/api/audits/${auditId}`);
    const line = `[${new Date().toLocaleTimeString()}] ${detail.audit.status} · phase ${detail.audit.current_phase}/6 · tasks ${JSON.stringify(detail.task_counts)}`;
    if (line !== lastLine) {
      console.log(line);
      lastLine = line;
    }
    if (["completed", "completed_with_errors", "failed", "cancelled"].includes(detail.audit.status)) {
      if (!["completed", "completed_with_errors"].includes(detail.audit.status)) {
        const tasks = await api<{ tasks: Array<{ phase: number; kind: string; status: string; error: string | null }> }>(
          `/api/audits/${auditId}/tasks`,
        );
        throw new Error(`Audit ${detail.audit.status}: ${JSON.stringify(tasks.tasks.filter((task) => task.status !== "completed"))}`);
      }
      return { id: auditId, status: detail.audit.status };
    }
    await Bun.sleep(4_000);
  }
  throw new Error("Audit timed out after 45 minutes");
}

async function verifyAndDownload(auditId: string): Promise<void> {
  const detail = await api<{
    audit: { status: string };
    phases: Array<{ phase: number; status: string }>;
    sessions: Array<{ harness: string; role: string; status: string }>;
    evidence: { chain: { ok: boolean; count: number } };
  }>(`/api/audits/${auditId}`);
  const findings = await api<{ findings: Array<{ code: string; title: string; severity: string; status: string; files: Array<{ path: string }> }> }>(
    `/api/audits/${auditId}/findings`,
  );
  const reports = await api<{ reports: Array<{ id: string; format: string; status: string; sha256: string }> }>(
    `/api/audits/${auditId}/reports`,
  );
  const harnesses = [...new Set(detail.sessions.map((session) => session.harness))];
  console.log("\nVerification:");
  console.log(`- Status: ${detail.audit.status}`);
  console.log(`- Harnesses used: ${harnesses.join(", ")}`);
  console.log(`- Evidence chain: ${detail.evidence.chain.ok ? "intact" : "BROKEN"} (${detail.evidence.chain.count} records)`);
  console.log(`- Findings: ${findings.findings.length}`);
  for (const finding of findings.findings) {
    console.log(`  ${finding.code} [${finding.severity}/${finding.status}] ${finding.title} — ${finding.files.map((file) => file.path).join(", ")}`);
  }
  if (!harnesses.includes("pi") || !harnesses.includes("claude-code")) {
    throw new Error(`Expected both harnesses; observed: ${harnesses.join(", ")}`);
  }
  if (!detail.evidence.chain.ok) throw new Error("Evidence chain verification failed");
  if (findings.findings.length === 0) throw new Error("Expected at least one independently verified finding");
  if (!findings.findings.some((finding) => finding.status === "reverified")) {
    throw new Error("No finding reached REVERIFIED; the deliverable must demonstrate independent reverification");
  }
  if (reports.reports.filter((report) => report.status === "generated").length !== 4) {
    throw new Error(`Expected 4 generated report formats; got ${reports.reports.length}`);
  }
  for (const report of reports.reports) {
    const response = await fetch(`${base}/api/reports/${report.id}/download`, { headers: { cookie } });
    if (!response.ok) throw new Error(`Report download failed for ${report.format}: ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const extension = report.format === "markdown" ? "md" : report.format;
    const path = join(outputDir, `argus-audit-${stamp}.${extension}`);
    await Bun.write(path, bytes);
    const digest = new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
    if (digest !== report.sha256) throw new Error(`Report hash mismatch for ${report.format}`);
    console.log(`- ${report.format.toUpperCase()}: ${path} (${bytes.length} bytes, sha256 verified)`);
  }
}
