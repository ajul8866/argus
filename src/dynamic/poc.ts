import { badRequest } from "../util.ts";

export type PocCheck = {
  identity: string;
  request: { method: string; path: string };
  expect: { status: number | number[]; body_contains?: string };
};

export type PocManifest = {
  language: string;
  script_evidence_id: string;
  object: { asset_id: string; object_id: string; owner_identity: string };
  checks: { positive: PocCheck; exploit: PocCheck; negative: PocCheck };
  cleanup?: string;
  environment: { target: string; commit_sha?: string | null; identities: string[] };
};

export type PocExchange = {
  status: number;
  body: string;
  /**
   * Redacted body for storage. Evaluation still uses `body`, so a control that
   * asserts on a credential value is not changed by storage redaction.
   */
  evidenceBody?: string;
  /** Set when the broker generated the response (scope, rate, upstream error). */
  brokerError?: string | null;
};

export type PocRunResult = {
  status: "passed" | "failed" | "error";
  positive: boolean;
  exploit: boolean;
  negative: boolean;
  reason?: string;
};

function requireString(value: unknown, field: string): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw badRequest(`${field} is required`);
  }
}

function allowedStatuses(check: PocCheck): number[] {
  const status = check.expect?.status;
  const list = Array.isArray(status) ? status : [status];
  if (list.length === 0 || list.some((entry) => !Number.isInteger(entry))) {
    throw badRequest("expect.status must be an integer or an array of integers");
  }
  return list;
}

export function validatePoc(manifest: PocManifest): void {
  requireString(manifest.language, "language");
  requireString(manifest.script_evidence_id, "script_evidence_id");
  requireString(manifest.object?.asset_id, "object.asset_id");
  requireString(manifest.object?.object_id, "object.object_id");
  requireString(manifest.object?.owner_identity, "object.owner_identity");

  for (const name of ["positive", "exploit", "negative"] as const) {
    const check = manifest.checks?.[name];
    if (!check) throw badRequest(`${name} check is required`);
    requireString(check.identity, `${name}.identity`);
    requireString(check.request?.method, `${name}.request.method`);
    requireString(check.request?.path, `${name}.request.path`);
    allowedStatuses(check);
  }

  const positive = manifest.checks.positive;
  const exploit = manifest.checks.exploit;
  const negative = manifest.checks.negative;

  if (positive.identity !== manifest.object.owner_identity) {
    throw badRequest("positive control must use the object owner identity");
  }
  if (exploit.identity === manifest.object.owner_identity) {
    throw badRequest("exploit must use a different identity from the owner");
  }
  if (negative.identity !== exploit.identity) {
    throw badRequest("negative control must use the exploit identity");
  }
  if (positive.request.path !== exploit.request.path) {
    throw badRequest("positive and exploit checks must target the same object");
  }
  if (!positive.request.path.includes(manifest.object.object_id)) {
    throw badRequest("positive and exploit checks must target object.object_id");
  }
  if (negative.request.path.includes(manifest.object.object_id)) {
    throw badRequest("negative check must target a different object");
  }
  requireString(manifest.environment?.target, "environment.target");
  if (!Array.isArray(manifest.environment.identities) || manifest.environment.identities.length === 0) {
    throw badRequest("environment.identities is required");
  }
}

function checkResult(check: PocCheck, exchange: PocExchange | undefined): boolean {
  if (!exchange || exchange.brokerError) return false;
  const allowed = Array.isArray(check.expect.status) ? check.expect.status : [check.expect.status];
  if (!allowed.includes(exchange.status)) return false;
  if (check.expect.body_contains && !exchange.body.includes(check.expect.body_contains)) return false;
  return true;
}

export function evaluateRun(
  manifest: PocManifest,
  exchanges: { positive?: PocExchange; exploit?: PocExchange; negative?: PocExchange },
): PocRunResult {
  validatePoc(manifest);
  const brokerError = [exchanges.positive, exchanges.exploit, exchanges.negative]
    .map((exchange) => exchange?.brokerError)
    .find((error): error is string => Boolean(error));
  const positive = checkResult(manifest.checks.positive, exchanges.positive);
  const exploit = checkResult(manifest.checks.exploit, exchanges.exploit);
  const negative = checkResult(manifest.checks.negative, exchanges.negative);

  // A broker-generated response means the controller never obtained a target
  // verdict. Treat it as an error, never as evidence that a control failed.
  if (brokerError) {
    return { status: "error", positive, exploit, negative, reason: `broker error: ${brokerError}` };
  }

  if (!positive) {
    return { status: "error", positive, exploit, negative, reason: "positive control failed" };
  }
  if (!exploit) {
    return { status: "failed", positive, exploit, negative, reason: "exploit check failed" };
  }
  if (!negative) {
    return { status: "failed", positive, exploit, negative, reason: "negative check failed" };
  }
  return { status: "passed", positive, exploit, negative };
}
