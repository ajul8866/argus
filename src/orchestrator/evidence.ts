import { constants } from "node:fs";
import { mkdir, open, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { KeyedSerialQueue } from "../concurrency.ts";
import { EVIDENCE_DIR } from "../config.ts";
import type { Store } from "../db/index.ts";
import { AppError, now, sha256, toJson, uid } from "../util.ts";
import { redactSecrets } from "../security/redact.ts";

export type EvidenceRow = {
  id: string;
  audit_id: string;
  task_id: string | null;
  agent_session_id: string | null;
  finding_id: string | null;
  kind: string;
  title: string;
  content_path: string;
  sha256: string;
  prev_hash: string;
  chain_hash: string;
  size: number;
  redacted: number;
  created_at: string;
};

export type EvidenceInput = {
  auditId: string;
  taskId?: string | null;
  sessionId?: string | null;
  findingId?: string | null;
  kind: string;
  title: string;
  content: string | Record<string, unknown> | unknown[];
  redacted?: boolean;
};

export class EvidenceStore {
  private readonly appends = new KeyedSerialQueue();

  constructor(
    private readonly config: Config,
    private readonly store: Store,
  ) {}

  async append(input: EvidenceInput): Promise<EvidenceRow> {
    // Evidence is hash-chained per audit. Concurrent agent tasks may append at
    // the same time, so serialize the read-prev/write-next critical section.
    return this.appends.run(input.auditId, () => this.appendInternal(input));
  }

  private async appendInternal(input: EvidenceInput): Promise<EvidenceRow> {
    const text = typeof input.content === "string" ? input.content : `${JSON.stringify(input.content, null, 2)}\n`;
    const contentHash = sha256(text);
    const previous = this.store.get<{ chain_hash: string }>(
      "SELECT chain_hash FROM evidence WHERE audit_id = ? ORDER BY rowid DESC LIMIT 1",
      input.auditId,
    );
    const prevHash = previous?.chain_hash ?? "GENESIS";
    const id = uid();
    const directory = join(EVIDENCE_DIR(this.config), input.auditId);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const filename = join(directory, `${id}.json`);
    const metadata = {
      id,
      audit_id: input.auditId,
      task_id: input.taskId ?? null,
      agent_session_id: input.sessionId ?? null,
      finding_id: input.findingId ?? null,
      kind: input.kind,
      title: input.title,
      created_at: now(),
      sha256: contentHash,
      prev_hash: prevHash,
    };
    const chainHash = sha256(`${prevHash}:${contentHash}:${input.kind}:${input.title}`);
    const body = `${JSON.stringify({ ...metadata, chain_hash: chainHash, content: text }, null, 2)}\n`;
    await writeFile(filename, body, { mode: 0o600 });
    this.store.run(
      `INSERT INTO evidence (id, audit_id, task_id, agent_session_id, finding_id, kind, title, content_path, sha256, prev_hash, chain_hash, size, redacted, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      input.auditId,
      input.taskId ?? null,
      input.sessionId ?? null,
      input.findingId ?? null,
      input.kind,
      input.title,
      filename,
      contentHash,
      prevHash,
      chainHash,
      Buffer.byteLength(text),
      input.redacted ? 1 : 0,
      metadata.created_at,
    );
    return {
      id,
      audit_id: input.auditId,
      task_id: input.taskId ?? null,
      agent_session_id: input.sessionId ?? null,
      finding_id: input.findingId ?? null,
      kind: input.kind,
      title: input.title,
      content_path: filename,
      sha256: contentHash,
      prev_hash: prevHash,
      chain_hash: chainHash,
      size: Buffer.byteLength(text),
      redacted: input.redacted ? 1 : 0,
      created_at: metadata.created_at,
    };
  }

  async content(id: string): Promise<{ row: EvidenceRow; content: string } | null> {
    const row = this.store.get<EvidenceRow>("SELECT * FROM evidence WHERE id = ?", id);
    if (!row) return null;
    const verified = await this.readVerified(row);
    if (!verified.ok) {
      throw new AppError(409, "conflict", `Evidence integrity check failed; ${verified.reason}`);
    }
    return { row, content: verified.text };
  }

  listForAudit(auditId: string, limit = 500): EvidenceRow[] {
    return this.store.all<EvidenceRow>(
      "SELECT * FROM evidence WHERE audit_id = ? ORDER BY rowid ASC LIMIT ?",
      auditId,
      limit,
    );
  }

  listForFinding(findingId: string): EvidenceRow[] {
    return this.store.all<EvidenceRow>(
      "SELECT * FROM evidence WHERE finding_id = ? ORDER BY rowid ASC",
      findingId,
    );
  }

  async verifyChain(auditId: string): Promise<{
    ok: boolean;
    count: number;
    broken_at: string | null;
    reason: string | null;
  }> {
    const rows = this.store.all<EvidenceRow>(
      "SELECT * FROM evidence WHERE audit_id = ? ORDER BY rowid ASC",
      auditId,
    );
    let prev = "GENESIS";
    for (const row of rows) {
      const expectedChain = sha256(`${prev}:${row.sha256}:${row.kind}:${row.title}`);
      if (row.prev_hash !== prev || row.chain_hash !== expectedChain) {
        return {
          ok: false,
          count: rows.length,
          broken_at: row.id,
          reason: "Stored chain metadata does not match the recomputed chain",
        };
      }
      const verified = await this.readVerified(row);
      if (!verified.ok) {
        return {
          ok: false,
          count: rows.length,
          broken_at: row.id,
          reason: verified.reason,
        };
      }
      prev = row.chain_hash;
    }
    return { ok: true, count: rows.length, broken_at: null, reason: null };
  }

  private maxSidecarBytes(row: EvidenceRow): number {
    // JSON.stringify writes one UTF-16 code unit as at most six bytes (\uXXXX).
    // UTF-8 size is at least that code-unit count, so six times the recorded
    // content size bounds the embedded string. Metadata values are known here
    // and use the same bound. Keep the list aligned with the object written by
    // appendInternal. The fixed allowance covers keys, nulls, and pretty-print.
    const fields = [
      row.id,
      row.audit_id,
      row.task_id ?? "",
      row.agent_session_id ?? "",
      row.finding_id ?? "",
      row.kind,
      row.title,
      row.created_at,
      row.sha256,
      row.prev_hash,
      row.chain_hash,
    ];
    const contentBytes = Number.isFinite(row.size) ? Math.max(0, row.size) : 0;
    let bound = contentBytes * 6 + 2;
    for (const field of fields) bound += field.length * 6 + 2;
    return bound + 1024;
  }

  private async readVerified(row: EvidenceRow): Promise<{ ok: true; text: string } | { ok: false; reason: string }> {
    const limit = this.maxSidecarBytes(row);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      // O_NOFOLLOW binds the size check and the read to one inode. A symlink
      // swapped in for the sidecar cannot redirect the hash check.
      handle = await open(row.content_path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const info = await handle.stat();
      if (!info.isFile()) return { ok: false, reason: "Evidence file is missing or unreadable" };
      if (info.size > limit) return { ok: false, reason: "Evidence file is larger than the recorded content" };
      const loaded = await handle.readFile({ encoding: "utf8" });
      const raw = typeof loaded === "string" ? loaded : loaded.toString("utf8");
      if (Buffer.byteLength(raw) > limit) {
        return { ok: false, reason: "Evidence file is larger than the recorded content" };
      }
      const parsed = JSON.parse(raw) as {
        id?: string;
        audit_id?: string;
        task_id?: string | null;
        agent_session_id?: string | null;
        finding_id?: string | null;
        kind?: string;
        title?: string;
        created_at?: string;
        sha256?: string;
        prev_hash?: string;
        chain_hash?: string;
        content?: unknown;
      };
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { ok: false, reason: "Evidence file is missing or unreadable" };
      }
      const metadataMatches =
        parsed.id === row.id &&
        parsed.audit_id === row.audit_id &&
        parsed.task_id === row.task_id &&
        parsed.agent_session_id === row.agent_session_id &&
        parsed.finding_id === row.finding_id &&
        parsed.kind === row.kind &&
        parsed.title === row.title &&
        parsed.created_at === row.created_at &&
        parsed.sha256 === row.sha256 &&
        parsed.prev_hash === row.prev_hash &&
        parsed.chain_hash === row.chain_hash;
      if (!metadataMatches) {
        return { ok: false, reason: "Evidence file metadata does not match the database record" };
      }
      const text = typeof parsed.content === "string" ? parsed.content : `${JSON.stringify(parsed.content, null, 2)}\n`;
      if (Buffer.byteLength(text) !== row.size) {
        return { ok: false, reason: "Evidence content size does not match the database record" };
      }
      if (sha256(text) !== row.sha256) {
        return { ok: false, reason: "Evidence file content hash does not match the database record" };
      }
      return { ok: true, text };
    } catch {
      return { ok: false, reason: "Evidence file is missing or unreadable" };
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  redactedText(text: string): string {
    return redactSecrets(text).text;
  }

  serialize(value: unknown): string {
    return toJson(value);
  }
}
