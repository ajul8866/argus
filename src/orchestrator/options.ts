import type { Store } from "../db/index.ts";
import { badRequest } from "../util.ts";

const INTEGER_LIMITS: Record<string, [number, number]> = {
  max_areas: [1, 8],
  max_candidates_per_area: [1, 8],
  max_confirmations: [0, 30],
  max_reverifications: [0, 30],
  max_concurrent_agents: [1, 12],
  task_timeout_ms: [10_000, 3_600_000],
  max_tasks: [1, 100_000],
  max_requests: [1, 10_000_000],
  max_runtime_minutes: [1, 10_080],
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateAuditOverrides(store: Store, overrides: unknown): void {
  if (!isObject(overrides)) throw badRequest("overrides must be an object");
  for (const [key, [minimum, maximum]] of Object.entries(INTEGER_LIMITS)) {
    const value = overrides[key];
    if (value !== undefined && (typeof value !== "number" || !Number.isInteger(value) || value < minimum || value > maximum)) {
      throw badRequest(`${key} must be an integer between ${minimum} and ${maximum}`);
    }
  }
  for (const key of ["writable_workspace", "require_distinct_harness_for_retest"]) {
    if (overrides[key] !== undefined && typeof overrides[key] !== "boolean") throw badRequest(`${key} must be a boolean`);
  }
  const budget = overrides.max_cost_usd;
  if (budget !== undefined && budget !== null && (typeof budget !== "number" || !Number.isFinite(budget) || budget < 0)) {
    throw badRequest("max_cost_usd must be a finite non-negative number or null");
  }
  const harnesses = overrides.harness_overrides;
  if (harnesses === undefined) return;
  if (!isObject(harnesses)) throw badRequest("harness_overrides must be an object");
  for (const [role, override] of Object.entries(harnesses)) {
    if (!store.get("SELECT role FROM agent_defs WHERE role = ?", role)) throw badRequest(`Unknown agent role: ${role.slice(0, 100)}`);
    if (!isObject(override)) throw badRequest(`Harness override for ${role} must be an object`);
    if (override.harness !== undefined && override.harness !== "pi" && override.harness !== "claude-code") {
      throw badRequest(`Harness override for ${role} must select pi or claude-code`);
    }
    if (override.model !== undefined && override.model !== null && (typeof override.model !== "string" || override.model.length > 300)) {
      throw badRequest(`Model override for ${role} must be a string of at most 300 characters or null`);
    }
  }
}
