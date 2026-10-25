import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../config.ts";

export type StoredCredential = {
  id: string;
  provider: string;
  env_var: string;
  ciphertext: string;
  iv: string;
  tag: string;
  last4: string;
  created_at: string;
  updated_at: string;
};

const keyCache = new Map<string, Buffer>();

function masterKey(config: Config): Buffer {
  const cached = keyCache.get(config.dataDir);
  if (cached) return cached;
  let material = config.masterKey;
  if (!material) {
    const keyPath = join(config.dataDir, "master.key");
    if (existsSync(keyPath)) {
      material = readFileSync(keyPath, "utf8").trim();
    } else {
      material = randomBytes(32).toString("base64");
      writeFileSync(keyPath, material, { mode: 0o600 });
      chmodSync(keyPath, 0o600);
    }
  }
  const key = createHash("sha256").update(material).digest();
  keyCache.set(config.dataDir, key);
  return key;
}

export function encryptSecret(config: Config, value: string): { ciphertext: string; iv: string; tag: string; last4: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", masterKey(config), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    last4: value.slice(-4),
  };
}

export function decryptSecret(config: Config, credential: StoredCredential): string {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    masterKey(config),
    Buffer.from(credential.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(credential.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(credential.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

/** Provider credentials are decrypted only for the harness child process. */
export function credentialEnvironment(
  config: Config,
  credentials: StoredCredential[],
  provider?: string,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const credential of credentials) {
    if (provider && credential.provider !== provider && credential.provider !== "global") continue;
    try {
      env[credential.env_var] = decryptSecret(config, credential);
    } catch {
      // Corrupt or master-key-changed credential: the harness health check will
      // report the authentication failure instead of crashing the server.
    }
  }
  return env;
}
