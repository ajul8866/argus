import type { Config } from "../config.ts";
import type { Store } from "../db/index.ts";
import { decryptSecret, type StoredCredential } from "../security/credentials.ts";
import { redactSecrets } from "../security/redact.ts";
import { AppError } from "../util.ts";

type IdentityRow = {
  id: string;
  target_id: string;
  role: string;
  auth_kind: "none" | "header" | "cookie" | "basic";
  secret_ref: string | null;
  status: "active" | "expired" | "disabled";
};

export type RedactedExchange = {
  headers: Record<string, string>;
  body: string;
  count: number;
};

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
]);

export class CredentialBroker {
  constructor(
    private readonly config: Config,
    private readonly store: Store,
  ) {}

  inject(identityId: string, expectedTargetId?: string): Record<string, string> {
    const identity = this.store.get<IdentityRow>(
      "SELECT id, target_id, role, auth_kind, secret_ref, status FROM test_identities WHERE id = ?",
      identityId,
    );
    if (!identity) throw new AppError(404, "identity_not_found", "Test identity not found");
    if (expectedTargetId && identity.target_id !== expectedTargetId) {
      throw new AppError(403, "identity_target_mismatch", "Test identity belongs to another target");
    }
    if (identity.status !== "active") {
      throw new AppError(409, "identity_unavailable", "Test identity is not active");
    }
    if (identity.auth_kind === "none") return {};
    if (!identity.secret_ref) {
      throw new AppError(409, "identity_secret_missing", "Test identity has no secret reference");
    }
    const credential = this.store.get<StoredCredential>(
      "SELECT * FROM provider_credentials WHERE provider = 'test-identity' AND env_var = ?",
      identity.secret_ref,
    );
    if (!credential) {
      throw new AppError(409, "identity_secret_missing", "Test identity secret was not found");
    }
    const secret = decryptSecret(this.config, credential);
    switch (identity.auth_kind) {
      case "header":
        return { authorization: /^bearer\s/i.test(secret) ? secret : `Bearer ${secret}` };
      case "cookie":
        return { cookie: secret };
      case "basic":
        return { authorization: `Basic ${Buffer.from(secret).toString("base64")}` };
      default:
        return {};
    }
  }

  /**
   * Decrypted secrets for the identities a replay is allowed to use. Used to
   * remove known credential values from recorded exchanges before storage.
   */
  secretValues(identityIds: string[]): string[] {
    const values = new Set<string>();
    for (const identityId of identityIds) {
      const identity = this.store.get<IdentityRow>(
        "SELECT id, target_id, role, auth_kind, secret_ref, status FROM test_identities WHERE id = ?",
        identityId,
      );
      if (!identity || identity.auth_kind === "none" || !identity.secret_ref) continue;
      const credential = this.store.get<StoredCredential>(
        "SELECT * FROM provider_credentials WHERE provider = 'test-identity' AND env_var = ?",
        identity.secret_ref,
      );
      if (!credential) continue;
      try {
        values.add(decryptSecret(this.config, credential));
      } catch {
        // A corrupt credential is reported when the broker injects it.
      }
    }
    return [...values];
  }

  redactExchange(headers: Record<string, string>, body: string, secrets: string[] = []): RedactedExchange {
    const redacted: Record<string, string> = {};
    let count = 0;
    for (const [key, value] of Object.entries(headers)) {
      const name = key.toLowerCase();
      if (SENSITIVE_HEADERS.has(name)) {
        redacted[name] = "[REDACTED]";
        count += 1;
      } else {
        redacted[name] = value;
      }
    }
    let text = body;
    for (const secret of secrets) {
      if (secret && secret.length >= 4 && text.includes(secret)) {
        text = text.split(secret).join("[REDACTED]");
        count += 1;
      }
    }
    const result = redactSecrets(text);
    return { headers: redacted, body: result.text, count: count + result.count };
  }

  assertNoSecrets(text: string, secrets: string[]): void {
    for (const secret of secrets) {
      if (secret && secret.length >= 4 && text.includes(secret)) {
        throw new AppError(500, "secret_leak", "A secret would be stored in evidence");
      }
    }
  }
}
