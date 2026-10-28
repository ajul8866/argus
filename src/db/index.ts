import { Database } from "bun:sqlite";
import type { SQLQueryBindings } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { migrations } from "./migrations.ts";

export type Row = Record<string, unknown>;

function bindings(params: unknown[]): SQLQueryBindings[] {
  return params as SQLQueryBindings[];
}

export class Store {
  readonly db: Database;

  constructor(config: Config, filename = "argus.sqlite") {
    mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
    this.db = new Database(join(config.dataDir, filename), { create: true });
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec("PRAGMA busy_timeout = 5000");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)",
    );
    const applied = new Set(
      this.db.query<{ version: number }, []>("SELECT version FROM schema_migrations").all().map((row) => row.version),
    );
    for (const migration of migrations) {
      if (applied.has(migration.version)) continue;
      if (migration.foreignKeysOff) this.db.exec("PRAGMA foreign_keys = OFF");
      try {
        this.db.transaction(() => {
          this.db.exec(migration.sql);
          migration.apply?.(this.db);
          this.db
            .query("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)")
            .run(migration.version, migration.name, new Date().toISOString());
        })();
      } finally {
        if (migration.foreignKeysOff) this.db.exec("PRAGMA foreign_keys = ON");
      }
      if (migration.foreignKeysOff) {
        const violations = this.db.query("PRAGMA foreign_key_check").all();
        if (violations.length > 0) {
          throw new Error(`foreign key violations after migration ${migration.version}: ${JSON.stringify(violations)}`);
        }
      }
    }
  }

  get<T = Row>(sql: string, ...params: unknown[]): T | null {
    return this.db.query(sql).get(...bindings(params)) as T | null;
  }

  all<T = Row>(sql: string, ...params: unknown[]): T[] {
    return this.db.query(sql).all(...bindings(params)) as T[];
  }

  run(sql: string, ...params: unknown[]): void {
    this.db.query(sql).run(...bindings(params));
  }

  changes(sql: string, ...params: unknown[]): number {
    return this.db.query(sql).run(...bindings(params)).changes;
  }

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  close(): void {
    this.db.close();
  }
}
