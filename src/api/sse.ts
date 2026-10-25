import type { LiveEvent } from "../events.ts";

const HEARTBEAT_MS = 15_000;

export type SseStreamOptions = {
  request: Request;
  /** Events sent before the live subscription starts, in order. */
  replay: LiveEvent[];
  /** Attach a listener that receives live events; return an unsubscribe function. */
  subscribe: (send: (event: LiveEvent) => void) => () => void;
  /** Audit-scoped streams carry `id:` so EventSource can resume with ?after=. */
  includeEventId: boolean;
};

/**
 * One SSE implementation for every stream endpoint: retry hint, replay,
 * subscription, keepalive, and cleanup on abort or consumer cancel.
 */
export function sseResponse(options: SseStreamOptions): Response {
  const encoder = new TextEncoder();
  let unsubscribe: () => void = () => {};
  let heartbeat: ReturnType<typeof setInterval> | undefined;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode("retry: 3000\n: connected\n\n"));
      const send = (event: LiveEvent) => {
        const frame = options.includeEventId
          ? `id: ${event.seq}\ndata: ${JSON.stringify(event)}\n\n`
          : `data: ${JSON.stringify(event)}\n\n`;
        try {
          controller.enqueue(encoder.encode(frame));
        } catch {
          // client disconnected
        }
      };
      for (const event of options.replay) send(event);
      unsubscribe = options.subscribe(send);
      heartbeat = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(`: keepalive ${Date.now()}\n\n`));
        } catch {
          // client disconnected
        }
      }, HEARTBEAT_MS);
      options.request.signal.addEventListener("abort", () => {
        unsubscribe();
        clearInterval(heartbeat);
        try {
          controller.close();
        } catch {
          // already closed
        }
      });
    },
    cancel() {
      unsubscribe();
      clearInterval(heartbeat);
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
