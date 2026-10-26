import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "./config.ts";
import { SESSION_COOKIE } from "./config.ts";
import type { Store } from "./db/index.ts";
import { now, sha256, uid } from "./util.ts";
import { redactObject } from "./security/redact.ts";

export type User = {
  id: string;
  email: string;
  name: string;
  role: "admin" | "auditor" | "viewer";
  disabled: number;
  created_at: string;
};

export type AuthSession = {
  id: string;
  user_id: string;
  csrf_token: string;
  expires_at: string;
};

export type AuthContext = {
  user: User;
  session: AuthSession;
};

const ROLE_RANK: Record<User["role"], number> = { viewer: 1, auditor: 2, admin: 3 };

const ARGON2_OPTIONS = { algorithm: "argon2id", memoryCost: 65_536, timeCost: 3 } as const;
const PUBLIC_USER_COLUMNS = "id, email, name, role, disabled, created_at";

function hashPassword(password: string): Promise<string> {
  return Bun.password.hash(password, ARGON2_OPTIONS);
}

export function roleAtLeast(user: User, role: User["role"]): boolean {
  return ROLE_RANK[user.role] >= ROLE_RANK[role];
}

export function parseCookies(header: string | null): Record<string, string> {
  if (!header) return {};
  const result: Record<string, string> = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!key) continue;
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      // Ignore malformed cookie values instead of turning them into a 500.
    }
  }
  return result;
}

function secureEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export class AuthService {
  private readonly failures = new Map<string, { count: number; firstAt: number; lockedUntil: number }>();

  constructor(
    private readonly config: Config,
    private readonly store: Store,
  ) {}

  async bootstrap(): Promise<void> {
    const count = this.store.get<{ count: number }>("SELECT COUNT(*) AS count FROM users")?.count ?? 0;
    if (count > 0) return;
    const password = this.config.adminPassword ?? randomBytes(18).toString("base64url");
    const hash = await hashPassword(password);
    const id = uid();
    this.store.run(
      "INSERT INTO users (id, email, name, password_hash, role, disabled, created_at) VALUES (?, ?, 'Administrator', ?, 'admin', 0, ?)",
      id,
      this.config.adminEmail.toLowerCase(),
      hash,
      now(),
    );
    if (!this.config.adminPassword) {
      const path = join(this.config.dataDir, "bootstrap-admin.txt");
      if (!existsSync(path)) {
        writeFileSync(
          path,
          `Argus bootstrap administrator\nEmail: ${this.config.adminEmail}\nPassword: ${password}\n\nChange this password after signing in, then delete this file.\n`,
          { mode: 0o600 },
        );
      }
      console.log(`[argus] Bootstrap administrator created. Initial credentials: ${path} (mode 0600).`);
    } else {
      console.log(`[argus] Bootstrap administrator created: ${this.config.adminEmail}`);
    }
  }

  private loginKey(ip: string, email: string): string {
    return `${ip}|${email.toLowerCase()}`;
  }

  private checkRateLimit(key: string): void {
    const record = this.failures.get(key);
    if (!record) return;
    const nowMs = Date.now();
    if (record.lockedUntil > nowMs) {
      const seconds = Math.ceil((record.lockedUntil - nowMs) / 1000);
      throw new Error(`Too many failed sign-in attempts. Try again in ${seconds}s.`);
    }
    if (nowMs - record.firstAt > 15 * 60 * 1000) this.failures.delete(key);
  }

  private recordFailure(key: string): void {
    const nowMs = Date.now();
    const record = this.failures.get(key);
    if (!record || nowMs - record.firstAt > 15 * 60 * 1000) {
      this.failures.set(key, { count: 1, firstAt: nowMs, lockedUntil: 0 });
      return;
    }
    record.count += 1;
    if (record.count >= 6) record.lockedUntil = nowMs + 15 * 60 * 1000;
  }

  async login(
    email: string,
    password: string,
    ip: string,
    userAgent: string,
  ): Promise<{ user: User; token: string; csrf: string; expiresAt: string }> {
    const key = this.loginKey(ip, email);
    this.checkRateLimit(key);
    const row = this.store.get<User & { password_hash: string }>(
      "SELECT * FROM users WHERE email = ?",
      email.toLowerCase(),
    );
    if (!row || row.disabled === 1) {
      this.recordFailure(key);
      throw new Error("Invalid email or password");
    }
    const valid = await Bun.password.verify(password, row.password_hash);
    if (!valid) {
      this.recordFailure(key);
      throw new Error("Invalid email or password");
    }
    this.failures.delete(key);
    const token = randomBytes(32).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + this.config.sessionTtlMs).toISOString();
    this.store.run(
      "INSERT INTO auth_sessions (id, user_id, csrf_token, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
      sha256(token),
      row.id,
      csrf,
      now(),
      expiresAt,
      ip,
      userAgent.slice(0, 300),
    );
    const { password_hash: _passwordHash, ...user } = row;
    return { user, token, csrf, expiresAt };
  }

  authenticate(request: Request): AuthContext | null {
    const token = parseCookies(request.headers.get("cookie"))[SESSION_COOKIE];
    if (!token) return null;
    const session = this.store.get<AuthSession>(
      "SELECT id, user_id, csrf_token, expires_at FROM auth_sessions WHERE id = ?",
      sha256(token),
    );
    if (!session) return null;
    if (new Date(session.expires_at).getTime() < Date.now()) {
      this.store.run("DELETE FROM auth_sessions WHERE id = ?", session.id);
      return null;
    }
    const user = this.store.get<User>(
      `SELECT ${PUBLIC_USER_COLUMNS} FROM users WHERE id = ?`,
      session.user_id,
    );
    if (!user || user.disabled === 1) return null;
    return { user, session };
  }

  verifyCsrf(session: AuthSession, token: string | null): boolean {
    if (!token) return false;
    return secureEqual(session.csrf_token, token);
  }

  logout(sessionId: string): void {
    this.store.run("DELETE FROM auth_sessions WHERE id = ?", sessionId);
  }

  private renderCookie(value: string, maxAge: number): string {
    const attributes = [
      `${SESSION_COOKIE}=${value}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      `Max-Age=${maxAge}`,
    ];
    if (this.config.secureCookies) attributes.push("Secure");
    return attributes.join("; ");
  }

  sessionCookie(token: string): string {
    return this.renderCookie(encodeURIComponent(token), Math.floor(this.config.sessionTtlMs / 1000));
  }

  clearCookie(): string {
    return this.renderCookie("", 0);
  }

  async changePassword(user: User, currentPassword: string, newPassword: string, currentSessionId: string): Promise<void> {
    const row = this.store.get<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = ?", user.id);
    if (!row) throw new Error("User not found");
    const valid = await Bun.password.verify(currentPassword, row.password_hash);
    if (!valid) throw new Error("Current password is incorrect");
    if (newPassword.length < 12) throw new Error("New password must be at least 12 characters");
    const hash = await hashPassword(newPassword);
    this.store.run("UPDATE users SET password_hash = ? WHERE id = ?", hash, user.id);
    this.store.run("DELETE FROM auth_sessions WHERE user_id = ? AND id != ?", user.id, currentSessionId);
  }

  async createUser(
    email: string,
    name: string,
    password: string,
    role: User["role"],
  ): Promise<User> {
    if (!email.includes("@")) throw new Error("A valid email is required");
    if (password.length < 12) throw new Error("Password must be at least 12 characters");
    if (!(role in ROLE_RANK)) throw new Error("Invalid role");
    const hash = await hashPassword(password);
    const id = uid();
    this.store.run(
      "INSERT INTO users (id, email, name, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)",
      id,
      email.toLowerCase(),
      name.trim() || email,
      hash,
      role,
      now(),
    );
    return this.store.get<User>(`SELECT ${PUBLIC_USER_COLUMNS} FROM users WHERE id = ?`, id)!;
  }

  listUsers(): User[] {
    return this.store.all<User>(`SELECT ${PUBLIC_USER_COLUMNS} FROM users ORDER BY created_at`);
  }

  updateUser(id: string, changes: { role?: User["role"]; disabled?: boolean; name?: string }): void {
    const user = this.store.get<User>("SELECT * FROM users WHERE id = ?", id);
    if (!user) throw new Error("User not found");
    if (changes.role) {
      if (!(changes.role in ROLE_RANK)) throw new Error("Invalid role");
      this.store.run("UPDATE users SET role = ? WHERE id = ?", changes.role, id);
    }
    if (changes.name !== undefined) {
      this.store.run("UPDATE users SET name = ? WHERE id = ?", changes.name.trim() || user.email, id);
    }
    if (changes.disabled !== undefined) {
      this.store.run("UPDATE users SET disabled = ? WHERE id = ?", changes.disabled ? 1 : 0, id);
      if (changes.disabled) this.store.run("DELETE FROM auth_sessions WHERE user_id = ?", id);
    }
  }

  logAction(actor: string | null, action: string, target: string | null, detail: unknown, ip: string | null): void {
    this.store.run(
      "INSERT INTO audit_log (actor, action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      actor,
      action,
      target,
      detail === undefined ? null : JSON.stringify(redactObject(detail)),
      ip,
      now(),
    );
  }
}
