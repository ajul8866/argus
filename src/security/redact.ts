const RULES: Array<{ name: string; pattern: RegExp }> = [
  {
    name: "private-key",
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  { name: "aws-access-key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { name: "github-token", pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g },
  { name: "github-pat", pattern: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g },
  { name: "slack-token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "stripe-key", pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { name: "anthropic-key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: "openai-key", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  {
    name: "jwt",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    name: "bearer",
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi,
  },
  {
    name: "assigned-secret",
    pattern:
      /\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b(\s*[:=]\s*)(['"`])([^'"`\n]{6,})\3/gi,
  },
  {
    name: "url-credentials",
    pattern: /\b([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi,
  },
];

export type RedactionResult = { text: string; count: number };

/** Redact credentials from logs, events, and generated reports. */
export function redactSecrets(input: string): RedactionResult {
  let text = input;
  let count = 0;
  for (const rule of RULES) {
    text = text.replace(rule.pattern, (match, ...args: unknown[]) => {
      count += 1;
      if (rule.name === "assigned-secret") {
        const prefix = String(args[0] ?? "");
        const separator = String(args[1] ?? "");
        const quote = String(args[2] ?? "");
        return `${prefix}${separator}${quote}[REDACTED]${quote}`;
      }
      if (rule.name === "url-credentials") {
        const scheme = String(args[0] ?? "");
        return `${scheme}[REDACTED]@`;
      }
      if (rule.name === "bearer") return "Bearer [REDACTED]";
      return `[REDACTED:${rule.name}]`;
    });
  }
  return { text, count };
}

export function redactObject<T>(value: T): T {
  if (typeof value === "string") return redactSecrets(value).text as T;
  if (Array.isArray(value)) return value.map((entry) => redactObject(entry)) as T;
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      if (/password|secret|api_?key|token|credential/i.test(key) && typeof entry === "string") {
        output[key] = "[REDACTED]";
      } else {
        output[key] = redactObject(entry);
      }
    }
    return output as T;
  }
  return value;
}
