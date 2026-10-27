#!/usr/bin/env bun
/**
 * Entry point for the argus-broker container. It starts the broker on the
 * audit network, then reads one identity handshake from stdin so no token
 * ever lands in the image, the environment, or a log.
 */
import { readFile, rm, watch } from "node:fs/promises";
import { startBrokerProcess } from "../src/dynamic/broker-process.ts";

// Inside the audit network the broker must accept peers other than itself.
const process_ = await startBrokerProcess({ host: process.env.ARGUS_BROKER_HOST ?? "0.0.0.0" });
process.stdout.write(`argus-broker listening on ${process_.port}\n`);

// The orchestrator writes one handshake file into a tmpfs the broker can read.
// The file is deleted as soon as it is consumed.
const handshakePath = process.env.ARGUS_HANDSHAKE_PATH ?? "/run/argus/handshake.json";
async function consume(): Promise<void> {
  let text: string;
  try {
    text = await readFile(handshakePath, "utf8");
  } catch {
    return;
  }
  try {
    const message = JSON.parse(text) as { type?: string; tokens?: Record<string, string> };
    if (message.type !== "identities" || !message.tokens || typeof message.tokens !== "object") {
      throw new Error("unexpected handshake");
    }
    process_.handshake(message.tokens);
    process.stdout.write("argus-broker ready\n");
  } catch (error) {
    process.stdout.write(`argus-broker handshake failed: ${error instanceof Error ? error.message : String(error)}\n`);
  } finally {
    await rm(handshakePath, { force: true });
  }
}
await consume();
const abort = new AbortController();
void (async () => {
  try {
    for await (const event of watch("/run/argus", { signal: abort.signal })) {
      if (event.filename === "handshake.json" && !process_.ready()) await consume();
    }
  } catch {
    // The watch ends when the process shuts down.
  }
})();

const shutdown = async (): Promise<void> => {
  abort.abort();
  await process_.stop();
  process.exit(0);
};
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
