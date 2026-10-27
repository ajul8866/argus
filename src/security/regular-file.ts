import { constants } from "node:fs";
import { open } from "node:fs/promises";

type SizePolicy = { exactBytes: number } | { maxBytes: number };

type ReadResult =
  | { ok: true; bytes: Buffer<ArrayBuffer> }
  | { ok: false; reason: "unreadable" | "size_mismatch" | "too_large"; error?: unknown };

export async function readRegularFile(path: string, policy: SizePolicy): Promise<ReadResult> {
  // Both flags are required: bitwise OR would silently turn undefined into 0.
  const noFollow = constants.O_NOFOLLOW;
  const nonBlock = constants.O_NONBLOCK;
  if (typeof noFollow !== "number" || typeof nonBlock !== "number" || noFollow === 0 || nonBlock === 0) {
    return { ok: false, reason: "unreadable" };
  }
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    // One descriptor binds stat and read to the same inode. O_NONBLOCK keeps a
    // replaced pipe from waiting for a writer; O_NOFOLLOW rejects symlinks.
    handle = await open(path, constants.O_RDONLY | noFollow | nonBlock);
    const info = await handle.stat();
    if (!info.isFile()) return { ok: false, reason: "unreadable" };
    const size = info.size;
    if ("exactBytes" in policy) {
      if (size !== policy.exactBytes) return { ok: false, reason: "size_mismatch" };
    } else {
      if (!Number.isSafeInteger(size) || size < 0) return { ok: false, reason: "unreadable" };
      if (size > policy.maxBytes) return { ok: false, reason: "too_large" };
    }
    // readFile() stats again and can read past this bound if the file grows.
    const buffer = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(buffer, offset, size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== size) return { ok: false, reason: "size_mismatch" };
    return { ok: true, bytes: buffer };
  } catch (error) {
    return { ok: false, reason: "unreadable", error };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}
