import type { Store } from "./db/index.ts";
import { now, parseJson, toJson } from "./util.ts";
import { redactObject } from "./security/redact.ts";

export type LiveEvent = {
  id: number;
  auditId: string | null;
  taskId: string | null;
  sessionId: string | null;
  seq: number;
  type: string;
  payload: Record<string, unknown>;
  createdAt: string;
};

export class EventBus {
  private subscribers = new Set<(event: LiveEvent) => void>();

  subscribe(listener: (event: LiveEvent) => void): () => void {
    this.subscribers.add(listener);
    return () => this.subscribers.delete(listener);
  }

  publish(event: LiveEvent): void {
    for (const listener of this.subscribers) {
      try {
        listener(event);
      } catch {
        // A broken SSE client must not break event persistence.
      }
    }
  }
}

export class EventLog {
  constructor(
    private readonly store: Store,
    readonly bus: EventBus = new EventBus(),
  ) {}

  append(options: {
    auditId: string | null;
    type: string;
    payload: Record<string, unknown>;
    taskId?: string | null;
    sessionId?: string | null;
  }): LiveEvent {
    const safePayload = redactObject(options.payload);
    const result = this.store.db
      .query<{ seq: number; id: number }, [string | null, string | null, string, string, string | null, string | null, string]>(
        `INSERT INTO execution_events (audit_id, seq, type, payload, task_id, agent_session_id, created_at)
         VALUES (?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM execution_events WHERE audit_id IS ?), ?, ?, ?, ?, ?)
         RETURNING seq, id`,
      )
      .get(
        options.auditId,
        options.auditId,
        options.type,
        toJson(safePayload),
        options.taskId ?? null,
        options.sessionId ?? null,
        now(),
      );
    const event: LiveEvent = {
      id: result?.id ?? 0,
      auditId: options.auditId,
      taskId: options.taskId ?? null,
      sessionId: options.sessionId ?? null,
      seq: result?.seq ?? 0,
      type: options.type,
      payload: safePayload,
      createdAt: now(),
    };
    this.bus.publish(event);
    return event;
  }

  list(auditId: string, afterSeq = 0, limit = 200): LiveEvent[] {
    const rows = this.store.all<{
      id: number;
      audit_id: string | null;
      task_id: string | null;
      agent_session_id: string | null;
      seq: number;
      type: string;
      payload: string;
      created_at: string;
    }>(
      `SELECT * FROM execution_events WHERE audit_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?`,
      auditId,
      afterSeq,
      Math.min(limit, 1000),
    );
    return rows.map((row) => ({
      id: row.id,
      auditId: row.audit_id,
      taskId: row.task_id,
      sessionId: row.agent_session_id,
      seq: row.seq,
      type: row.type,
      payload: parseJson<Record<string, unknown>>(row.payload, {}),
      createdAt: row.created_at,
    }));
  }
}
