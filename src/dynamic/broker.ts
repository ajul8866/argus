import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as netConnect, type Socket } from "node:net";
import type { ClientRequest } from "node:http";
import { checkRequest, checkRequestScope, checkTunnel, RateLimiter, resolveAndValidate, type AddressLookup, type EgressPolicy } from "./egress.ts";
import type { CredentialBroker } from "./credentials.ts";

/** The only capability the broker needs from a credential source. */
export type CredentialSource = {
  inject(identityId: string): Record<string, string>;
};

export type ExchangeRecord = {
  method: string;
  url: string;
  identityId: string | null;
  status: number;
  scopeDecision: "allowed" | "blocked" | "approval_required" | "error";
  durationMs: number;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
};

export type BrokerOptions = {
  policy: EgressPolicy;
  credentials?: CredentialSource;
  onExchange?: (record: ExchangeRecord) => void | Promise<void>;
  /** Health checks report whether the broker is ready to serve traffic. */
  isReady?: () => boolean;
  rateLimiter?: RateLimiter;
  lookup?: AddressLookup;
};

export const BROKER_FORWARD_PATH = "/__argus/forward";
export const BROKER_TARGET_HEADER = "x-argus-target-url";
export const BROKER_DEADLINE_HEADER = "x-argus-deadline";

const SENSITIVE = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "x-argus-identity"]);
const HOP_BY_HOP = new Set(["host", "proxy-connection", "connection", "content-length", "x-argus-identity", BROKER_TARGET_HEADER, BROKER_DEADLINE_HEADER]);

export class BrokerServer {
  private server: Server | null = null;
  private readonly sockets = new Set<Socket>();
  private readonly upstreamRequests = new Map<ClientRequest, (error: Error) => void>();
  private readonly limiter: RateLimiter;
  private stopping = false;

  constructor(private readonly options: BrokerOptions) {
    this.limiter = options.rateLimiter ?? new RateLimiter();
  }

  start(port = 0, host = "127.0.0.1"): Promise<{ port: number }> {
    this.stopping = false;
    this.server = createServer((request, response) => {
      void this.handleHttp(request, response).catch((error) => {
        if (response.destroyed) return;
        if (!response.headersSent) {
          response.writeHead(502, { "content-type": "application/json" });
        }
        response.end(JSON.stringify({ error: { code: "broker_error", message: String(error) } }));
      });
    });
    this.server.on("connection", (socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
    });
    this.server.on("connect", (request, socket, head) => {
      void this.handleConnect(request, socket as Socket, head).catch(() => socket.destroy());
    });
    return new Promise((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, host, () => {
        const address = this.server!.address();
        resolve({ port: typeof address === "object" && address ? address.port : port });
      });
    });
  }

  async stop(): Promise<void> {
    this.stopping = true;
    for (const cancel of this.upstreamRequests.values()) cancel(new Error("the broker stopped"));
    this.upstreamRequests.clear();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    await new Promise<void>((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
    this.server = null;
  }

  private async handleHttp(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const started = Date.now();
    const method = (request.method ?? "GET").toUpperCase();
    const requestedDeadline = Number(request.headers[BROKER_DEADLINE_HEADER]);
    const deadline = Math.min(started + 30_000, Number.isFinite(requestedDeadline) ? requestedDeadline : Infinity);
    const target = request.headers[BROKER_TARGET_HEADER];
    const url = request.url === BROKER_FORWARD_PATH
      ? typeof target === "string" ? target : ""
      : request.url ?? "";
    // Container health checks must not be treated as proxied traffic.
    if (request.url === "/__argus/health" && (method === "GET" || method === "HEAD")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: this.options.isReady?.() ?? true }));
      return;
    }
    const decision = checkRequestScope(this.options.policy, { method, url });
    if (!decision.allowed) {
      await this.reject(response, "scope_blocked", decision.reason ?? "request blocked", method, url, started);
      return;
    }
    const resolved = await this.resolveTarget(url);
    if (this.stopping || response.destroyed) return;
    if (!resolved.allowed) {
      await this.reject(response, "scope_blocked", resolved.reason ?? "address not allowed", method, url, started);
      return;
    }
    const approval = (this.options.policy.authorizedActions?.require_approval_for ?? []).map((entry) =>
      entry.toUpperCase(),
    );
    if (approval.includes(method)) {
      await this.reject(response, "approval_required", `${method} requires approval`, method, url, started);
      return;
    }
    if (!this.limiter.allow(`target:${new URL(url).hostname}`, this.options.policy.maxRps)) {
      await this.reject(response, "rate_limited", "rate limit exceeded", method, url, started);
      return;
    }

    const identityId = typeof request.headers["x-argus-identity"] === "string"
      ? request.headers["x-argus-identity"]
      : null;
    const headers = new Headers();
    for (const [key, value] of Object.entries(request.headers)) {
      if (HOP_BY_HOP.has(key.toLowerCase())) continue;
      if (Array.isArray(value)) for (const item of value) headers.append(key, item);
      else if (value) headers.set(key, value);
    }
    if (identityId && this.options.credentials) {
      for (const [key, value] of Object.entries(this.options.credentials.inject(identityId))) {
        headers.set(key, value);
      }
    }

    try {
      const body = await this.readBody(request);
      if (this.stopping || response.destroyed) return;
      if (!resolved.address) throw new Error("the target address was not resolved");
      const pinned = await this.pinnedFetch(url, method, headers, body, resolved.address, request, response, deadline);
      if (!response.destroyed) {
        response.writeHead(pinned.status, pinned.headers);
        response.end(pinned.body);
      }
      await this.record({
        method,
        url,
        identityId,
        status: pinned.status,
        scopeDecision: "allowed",
        durationMs: Date.now() - started,
        requestHeaders: this.redactHeaders(request.headers),
        responseHeaders: pinned.recordedHeaders,
      });
      return;
    } catch (error) {
      if (!response.destroyed) {
        response.writeHead(502, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { code: "upstream_error", message: String(error) } }));
      }
      await this.record({
        method,
        url,
        identityId,
        status: 502,
        scopeDecision: "error",
        durationMs: Date.now() - started,
        requestHeaders: this.redactHeaders(request.headers),
        responseHeaders: {},
      });
      return;
    }
  }

  /**
   * Resolves the target once and validates every address. The returned address
   * is the one the connection is pinned to, so a later DNS answer cannot move
   * the request to a different host (DNS rebinding).
   */
  private async resolveTarget(url: string): Promise<{ allowed: boolean; reason?: string; address?: string }> {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return { allowed: false, reason: "url is invalid" };
    }
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    const resolved = await resolveAndValidate(this.options.policy, host, this.options.lookup);
    if (!resolved.allowed) return { allowed: false, reason: resolved.reason };
    const address = resolved.addresses[0];
    if (!address) return { allowed: false, reason: `host ${host} did not resolve` };
    return { allowed: true, address };
  }

  /**
   * Performs the upstream request against a fixed address while keeping the
   * original Host header and TLS server name.
   */
  private pinnedFetch(
    url: string,
    method: string,
    headers: Headers,
    body: Buffer,
    address: string,
    incoming: IncomingMessage,
    downstream: ServerResponse,
    deadline: number,
  ): Promise<{ status: number; headers: Record<string, string>; recordedHeaders: Record<string, string>; body: Buffer }> {
    if (deadline <= Date.now()) return Promise.reject(new Error("the broker request timed out"));
    const parsed = new URL(url);
    const isHttps = parsed.protocol === "https:";
    const plain = new Headers(headers);
    plain.delete("host");
    plain.delete("content-length");
    return new Promise((resolve, reject) => {
      const controller = new AbortController();
      const clientSocket = downstream.socket;
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let upstreamResponse: IncomingMessage | undefined;
      const cleanup = () => {
        clearTimeout(timer);
        downstream.removeListener("close", disconnected);
        incoming.removeListener("aborted", disconnected);
        clientSocket?.removeListener("close", disconnected);
        this.upstreamRequests.delete(request);
      };
      const fail = (error: Error) => {
        if (settled) return;
        // Bun can emit end after destroy. Latch failure before closing the
        // request so neither that event nor a client abort can accept a prefix.
        settled = true;
        cleanup();
        reject(error);
        controller.abort(error);
        upstreamResponse?.destroy();
        request.socket?.destroy();
        request.destroy();
      };
      const disconnected = () => fail(new Error("the broker client disconnected"));
      const options = {
        host: address,
        port: Number(parsed.port || (isHttps ? 443 : 80)),
        method,
        path: `${parsed.pathname}${parsed.search}`,
        headers: { ...Object.fromEntries(plain.entries()), host: parsed.host },
        timeout: 30_000,
        signal: controller.signal,
      };
      const request: ClientRequest = isHttps
        ? httpsRequest({ ...options, servername: parsed.hostname }, handle)
        : httpRequest(options, handle);
      function handle(response: IncomingMessage): void {
        upstreamResponse = response;
        if (settled) {
          response.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 5_000_000) {
            fail(new Error("response exceeds the broker limit"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          if (settled) return;
          settled = true;
          cleanup();
          const forwarded: Record<string, string> = {};
          const recorded: Record<string, string> = {};
          for (const [key, value] of Object.entries(response.headers)) {
            if (["content-encoding", "content-length", "transfer-encoding", "connection"].includes(key)) continue;
            const text = Array.isArray(value) ? value.join(", ") : String(value ?? "");
            forwarded[key] = text;
            recorded[key] = SENSITIVE.has(key) ? "[REDACTED]" : text;
          }
          resolve({ status: response.statusCode ?? 0, headers: forwarded, recordedHeaders: recorded, body: Buffer.concat(chunks) });
        });
        response.on("error", fail);
        response.on("aborted", () => fail(new Error("the upstream response was interrupted")));
      }
      this.upstreamRequests.set(request, fail);
      downstream.once("close", disconnected);
      incoming.once("aborted", disconnected);
      clientSocket?.once("close", disconnected);
      request.on("timeout", () => fail(new Error("the broker request timed out")));
      request.on("error", fail);
      timer = setTimeout(() => fail(new Error("the broker request timed out")), Math.max(0, deadline - Date.now()));
      if (this.stopping || incoming.aborted || downstream.destroyed) {
        disconnected();
        return;
      }
      if (body.length > 0) request.write(body);
      request.end();
    });
  }

  private async handleConnect(request: IncomingMessage, socket: Socket, head: Buffer): Promise<void> {
    // Bun's CONNECT event exposes a different socket wrapper from connection.
    // Track it before DNS so shutdown can close a pending tunnel too.
    this.sockets.add(socket);
    socket.once("close", () => this.sockets.delete(socket));
    const started = Date.now();
    const target = request.url ?? "";
    const separator = target.lastIndexOf(":");
    const host = separator >= 0 ? target.slice(0, separator) : target;
    const port = Number(separator >= 0 ? target.slice(separator + 1) : "443");
    const decision = checkTunnel(this.options.policy, host, port);
    if (!decision.allowed) {
      socket.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n${decision.reason ?? "blocked"}\n`);
      void this.record({
        method: "CONNECT",
        url: target,
        identityId: null,
        status: 403,
        scopeDecision: "blocked",
        durationMs: Date.now() - started,
        requestHeaders: {},
        responseHeaders: {},
      });
      return;
    }
    const resolved = await this.resolveTunnelHost(host, port);
    if (this.stopping || socket.destroyed) return;
    if (!resolved.allowed || !resolved.address) {
      socket.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n${resolved.reason ?? "address not allowed"}\n`);
      void this.record({
        method: "CONNECT",
        url: target,
        identityId: null,
        status: 403,
        scopeDecision: "blocked",
        durationMs: Date.now() - started,
        requestHeaders: {},
        responseHeaders: {},
      });
      return;
    }
    const upstream = netConnect(port, resolved.address, () => {
      if (this.stopping || socket.destroyed) {
        upstream.destroy();
        return;
      }
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
      void this.record({
        method: "CONNECT",
        url: target,
        identityId: null,
        status: 200,
        scopeDecision: "allowed",
        durationMs: Date.now() - started,
        requestHeaders: {},
        responseHeaders: {},
      });
    });
    this.sockets.add(upstream);
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
    socket.on("close", () => {
      upstream.destroy();
      this.sockets.delete(socket);
      this.sockets.delete(upstream);
    });
  }

  private async resolveTunnelHost(
    host: string,
    port: number,
  ): Promise<{ allowed: boolean; reason?: string; address?: string }> {
    const name = host.replace(/^\[|\]$/g, "");
    const tunnel = checkTunnel(this.options.policy, name, port);
    if (!tunnel.allowed) return { allowed: false, reason: tunnel.reason };
    const resolved = await resolveAndValidate(this.options.policy, name, this.options.lookup);
    if (!resolved.allowed) return { allowed: false, reason: resolved.reason };
    // Preserve the existing eligibility gate for opaque tunnels. Unlike the
    // forwarding endpoint, CONNECT cannot inspect inner methods or paths.
    const eligible = checkRequest(this.options.policy, { method: "GET", url: `http://${name}/` }, resolved.addresses);
    if (!eligible.allowed) return { allowed: false, reason: eligible.reason };
    const address = resolved.addresses[0];
    if (!address) return { allowed: false, reason: `host ${name} did not resolve` };
    return { allowed: true, address };
  }

  private async reject(
    response: ServerResponse,
    code: string,
    message: string,
    method: string,
    url: string,
    started: number,
  ): Promise<void> {
    response.writeHead(403, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: { code, message } }));
    await this.record({
      method,
      url,
      identityId: null,
      status: 403,
      scopeDecision:
        code === "approval_required" ? "approval_required" : code === "scope_blocked" ? "blocked" : "blocked",
      durationMs: Date.now() - started,
      requestHeaders: {},
      responseHeaders: {},
    });
  }

  private async readBody(request: IncomingMessage): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > 1_000_000) throw new Error("request body exceeds the broker limit");
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }

  private redactHeaders(headers: IncomingMessage["headers"]): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      const name = key.toLowerCase();
      if (SENSITIVE.has(name)) result[name] = "[REDACTED]";
      else if (typeof value === "string") result[name] = value;
    }
    return result;
  }

  private async record(record: ExchangeRecord): Promise<void> {
    await this.options.onExchange?.(record);
  }
}
