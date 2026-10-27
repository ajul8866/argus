#!/usr/bin/env bun
/**
 * Acceptance run for the dynamic layer. It is not part of CI: it needs Docker,
 * a reachable target, and Argus credentials. Every step is printed so a run is
 * auditable after the fact.
 */
import { buildDynamicE2EPlan } from "../src/dynamic/e2e-plan.ts";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<number> {
  const base = (process.env.ARGUS_API_BASE_URL ?? "http://127.0.0.1:8787").replace(/\/+$/, "");
  const plan = buildDynamicE2EPlan({
    projectId: required("ARGUS_E2E_PROJECT_ID"),
    targetId: required("ARGUS_E2E_TARGET_ID"),
    repositoryId: process.env.ARGUS_E2E_REPOSITORY_ID || undefined,
    baseUrl: required("ARGUS_E2E_TARGET_URL"),
  });

  const health = await fetch(`${base}/api/health`).catch(() => null);
  if (!health?.ok) {
    process.stderr.write(`Argus is not reachable at ${base}\n`);
    return 2;
  }

  process.stdout.write(`dynamic e2e against ${plan.audit.target_id} (${plan.audit.mode})\n`);
  for (const step of plan.steps) {
    process.stdout.write(`- ${step.name}: ${step.detail}\n`);
  }

  const docker = Bun.spawn(["docker", "version"], { stdout: "pipe", stderr: "pipe" });
  if ((await docker.exited) !== 0) {
    process.stderr.write(
      "Docker is required for this acceptance run. Build the images first:\n" +
        "  docker build -f deploy/Dockerfile.broker -t argus-broker:test .\n" +
        "  docker build -f deploy/Dockerfile.worker -t argus-worker:test .\n",
    );
    return 3;
  }

  // The interactive half needs a human-created target with a live authorization
  // and a worker token; the plan above is what those steps must satisfy.
  process.stdout.write(
    `\naudit body: ${JSON.stringify(plan.audit)}\nworker scopes: ${plan.workerScopes.join(", ")}\n`,
  );
  process.stdout.write("Create the audit with the body above, issue a worker token, then run the worker container.\n");
  return 0;
}

process.exit(await main());
