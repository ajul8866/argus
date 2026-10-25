export type JsonSchema = {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  additionalProperties?: boolean;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  minItems?: number;
  maxItems?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  description?: string;
};

export type CodeExcerpt = {
  path: string;
  start_line: number;
  end_line: number;
  quote: string;
  explanation?: string;
};

export type MapArea = {
  id: string;
  title: string;
  rationale: string;
  files: string[];
  security_focus: string[];
};

export type MapResult = {
  summary: string;
  languages: string[];
  frameworks: string[];
  modules: Array<{ name: string; path: string; purpose: string }>;
  entrypoints: string[];
  endpoints: Array<{ method: string; path: string; file: string; line: number; auth_required: boolean }>;
  auth_boundaries: Array<{ kind: string; file: string; line: number; description: string }>;
  data_access: Array<{ kind: string; description: string; files: string[] }>;
  critical_paths: Array<{ name: string; description: string; files: string[] }>;
  areas: MapArea[];
  coverage_notes: string[];
  limitations: string[];
};

export type Candidate = {
  title: string;
  category: string;
  cwe: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  files: Array<{ path: string; start_line: number; end_line: number }>;
  hypothesis: string;
  source_to_sink: string;
  preconditions: string[];
  evidence_excerpts: CodeExcerpt[];
  reproduction_notes: string;
  expected: string;
  observed: string;
  impact: string;
  remediation: string;
};

export type DiscoveryResult = {
  area_id: string;
  summary: string;
  inspected_files: string[];
  candidates: Candidate[];
  limitations: string[];
};

export type ConfirmationResult = {
  verdict: "CONFIRMED" | "REFUTED" | "INCONCLUSIVE" | "DUPLICATE";
  rationale: string;
  verified_excerpts: CodeExcerpt[];
  reproduction_steps: string[];
  prerequisites_checked: string[];
  alternative_explanations: string[];
  mitigating_controls: string[];
  severity_assessment: "critical" | "high" | "medium" | "low" | "info";
  impact_assessment: string;
  completeness_issues: string[];
  duplicate_of_finding_code: string | null;
};

export type RetestResult = {
  decision: "REVERIFIED" | "REJECTED" | "NEEDS_CORRECTION" | "UNRESOLVED";
  rationale: string;
  verified_excerpts: CodeExcerpt[];
  impact_assessment: string;
  reproduction_consistency: string;
  completeness_issues: string[];
  unsupported_claims: string[];
  severity_assessment: "critical" | "high" | "medium" | "low" | "info";
  notes: string[];
};

const excerptSchema: JsonSchema = {
  type: "object",
  properties: {
    path: { type: "string", minLength: 1, description: "Repository-relative POSIX path" },
    start_line: { type: "integer", minimum: 1 },
    end_line: { type: "integer", minimum: 1 },
    quote: {
      type: "string",
      minLength: 12,
      maxLength: 4000,
      description: "Verbatim code text copied from the file. No line numbers, ellipsis, or commentary.",
    },
    explanation: { type: "string" },
  },
  required: ["path", "start_line", "end_line", "quote"],
  additionalProperties: false,
};

export const MAP_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    summary: { type: "string" },
    languages: { type: "array", items: { type: "string" } },
    frameworks: { type: "array", items: { type: "string" } },
    modules: {
      type: "array",
      items: {
        type: "object",
        properties: {
          name: { type: "string" },
          path: { type: "string" },
          purpose: { type: "string" },
        },
        required: ["name", "path", "purpose"],
        additionalProperties: false,
      },
    },
    entrypoints: { type: "array", items: { type: "string" } },
    endpoints: {
      type: "array",
      items: {
        type: "object",
        properties: {
          method: { type: "string" },
          path: { type: "string" },
          file: { type: "string" },
          line: { type: "integer", minimum: 1 },
          auth_required: { type: "boolean" },
        },
        required: ["method", "path", "file", "line", "auth_required"],
        additionalProperties: false,
      },
    },
    auth_boundaries: {
      type: "array",
      items: {
        type: "object",
        properties: {
          kind: { type: "string" },
          file: { type: "string" },
          line: { type: "integer", minimum: 1 },
          description: { type: "string" },
        },
        required: ["kind", "file", "line", "description"],
        additionalProperties: false,
      },
    },
    data_access: {
      type: "array",
      items: {
        type: "object",
        properties: {
          kind: { type: "string" },
          description: { type: "string" },
          files: { type: "array", items: { type: "string" } },
        },
        required: ["kind", "description", "files"],
        additionalProperties: false,
      },
    },
    critical_paths: {
      type: "array",
      items: {
        type: "object",
        properties: {
          name: { type: "string" },
          description: { type: "string" },
          files: { type: "array", items: { type: "string" } },
        },
        required: ["name", "description", "files"],
        additionalProperties: false,
      },
    },
    areas: {
      type: "array",
      minItems: 1,
      maxItems: 8,
      items: {
        type: "object",
        properties: {
          id: { type: "string", pattern: "^[a-zA-Z0-9_-]{1,48}$" },
          title: { type: "string" },
          rationale: { type: "string" },
          files: { type: "array", minItems: 1, items: { type: "string" } },
          security_focus: { type: "array", items: { type: "string" } },
        },
        required: ["id", "title", "rationale", "files", "security_focus"],
        additionalProperties: false,
      },
    },
    coverage_notes: { type: "array", items: { type: "string" } },
    limitations: { type: "array", items: { type: "string" } },
  },
  required: [
    "summary",
    "languages",
    "frameworks",
    "modules",
    "entrypoints",
    "endpoints",
    "auth_boundaries",
    "data_access",
    "critical_paths",
    "areas",
    "coverage_notes",
    "limitations",
  ],
  additionalProperties: false,
};

export const DISCOVERY_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    area_id: { type: "string" },
    summary: { type: "string" },
    inspected_files: { type: "array", items: { type: "string" } },
    candidates: {
      type: "array",
      maxItems: 8,
      items: {
        type: "object",
        properties: {
          title: { type: "string" },
          category: { type: "string" },
          cwe: { type: ["string", "null"] },
          severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
          files: {
            type: "array",
            items: {
              type: "object",
              properties: {
                path: { type: "string" },
                start_line: { type: "integer", minimum: 1 },
                end_line: { type: "integer", minimum: 1 },
              },
              required: ["path", "start_line", "end_line"],
              additionalProperties: false,
            },
          },
          hypothesis: { type: "string" },
          source_to_sink: { type: "string" },
          preconditions: { type: "array", items: { type: "string" } },
          evidence_excerpts: { type: "array", minItems: 1, items: excerptSchema },
          reproduction_notes: { type: "string" },
          expected: { type: "string" },
          observed: { type: "string" },
          impact: { type: "string" },
          remediation: { type: "string" },
        },
        required: [
          "title",
          "category",
          "cwe",
          "severity",
          "files",
          "hypothesis",
          "source_to_sink",
          "preconditions",
          "evidence_excerpts",
          "reproduction_notes",
          "expected",
          "observed",
          "impact",
          "remediation",
        ],
        additionalProperties: false,
      },
    },
    limitations: { type: "array", items: { type: "string" } },
  },
  required: ["area_id", "summary", "inspected_files", "candidates", "limitations"],
  additionalProperties: false,
};

export const CONFIRMATION_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    verdict: { type: "string", enum: ["CONFIRMED", "REFUTED", "INCONCLUSIVE", "DUPLICATE"] },
    rationale: { type: "string" },
    verified_excerpts: { type: "array", items: excerptSchema },
    reproduction_steps: { type: "array", items: { type: "string" } },
    prerequisites_checked: { type: "array", items: { type: "string" } },
    alternative_explanations: { type: "array", items: { type: "string" } },
    mitigating_controls: { type: "array", items: { type: "string" } },
    severity_assessment: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
    impact_assessment: { type: "string" },
    completeness_issues: { type: "array", items: { type: "string" } },
    duplicate_of_finding_code: { type: ["string", "null"] },
  },
  required: [
    "verdict",
    "rationale",
    "verified_excerpts",
    "reproduction_steps",
    "prerequisites_checked",
    "alternative_explanations",
    "mitigating_controls",
    "severity_assessment",
    "impact_assessment",
    "completeness_issues",
    "duplicate_of_finding_code",
  ],
  additionalProperties: false,
};

export const RETEST_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    decision: { type: "string", enum: ["REVERIFIED", "REJECTED", "NEEDS_CORRECTION", "UNRESOLVED"] },
    rationale: { type: "string" },
    verified_excerpts: { type: "array", items: excerptSchema },
    impact_assessment: { type: "string" },
    reproduction_consistency: { type: "string" },
    completeness_issues: { type: "array", items: { type: "string" } },
    unsupported_claims: { type: "array", items: { type: "string" } },
    severity_assessment: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
    notes: { type: "array", items: { type: "string" } },
  },
  required: [
    "decision",
    "rationale",
    "verified_excerpts",
    "impact_assessment",
    "reproduction_consistency",
    "completeness_issues",
    "unsupported_claims",
    "severity_assessment",
    "notes",
  ],
  additionalProperties: false,
};

export function validateAgainstSchema(value: unknown, schema: JsonSchema, path = "$"): string[] {
  const errors: string[] = [];
  if (value === null && Array.isArray(schema.type) && schema.type.includes("null")) return errors;
  const types = schema.type === undefined ? [] : Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.length > 0) {
    const actual = jsonType(value);
    if (!types.includes(actual) && !(actual === "integer" && types.includes("number"))) {
      return [`${path}: expected ${types.join(" | ")}, received ${actual}`];
    }
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${path}: value ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${path}: string is shorter than ${schema.minLength}`);
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(`${path}: string is longer than ${schema.maxLength}`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: string does not match ${schema.pattern}`);
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: below minimum ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: above maximum ${schema.maximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${path}: expected at least ${schema.minItems} items`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push(`${path}: expected at most ${schema.maxItems} items`);
    }
    if (schema.items) {
      value.forEach((entry, index) => {
        errors.push(...validateAgainstSchema(entry, schema.items!, `${path}[${index}]`));
      });
    }
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    for (const required of schema.required ?? []) {
      if (!(required in record)) errors.push(`${path}: missing required property "${required}"`);
    }
    for (const [key, entry] of Object.entries(record)) {
      const child = schema.properties?.[key];
      if (child) {
        errors.push(...validateAgainstSchema(entry, child, `${path}.${key}`));
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}: unexpected property "${key}"`);
      }
    }
  }
  return errors;
}

function jsonType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (Number.isInteger(value)) return "integer";
  return typeof value;
}

export function validateResult<T>(value: unknown, schema: JsonSchema): { ok: true; value: T } | { ok: false; errors: string[] } {
  const errors = validateAgainstSchema(value, schema);
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, value: value as T };
}
