import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import { checkRequest, checkTunnel, RateLimiter, type EgressPolicy } from "./egress.ts";
import type { CredentialBroker } from "./credentials.ts";

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
  credentials?: CredentialBroker;
  onExchange?: (record: ExchangeRecord) => void | Promise<void>;
  rateLimiter?: RateLimiter;
};

const SENSITIVE = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "x-argus-identity"]);
const HOP_BY_HOP = new Set(["host", "proxy-connection", "connection", "content-length", "x-argus-identity"]);

export class BrokerServer {
  private server: Server | null = null;
  private readonly sockets = new Set<Socket>();
  private readonly limiter: RateLimiter;

  constructor(private readonly options: BrokerOptions) {
    this.limiter = options.rateLimiter ?? new RateLimiter();
  }

  start(port = 0): Promise<{ port: number }> {
    this.server = createServer((request, response) => {
      void this.handleHttp(request, response).catch((error) => {
        if (!response.headersSent) {
          response.writeHead(502, { "content-type": "application/json" });
        }
        response.end(JSON.stringify({ error: { code: "broker_error", message: String(error) } }));
      });
    });
    this.server.on("connect", (request, socket, head) => {
      this.handleConnect(request, socket as Socket, head);
    });
    return new Promise((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, "127.0.0.1", () => {
        const address = this.server!.address();
        resolve({ port: typeof address === "object" && address ? address.port : port });
      });
    });
  }

  async stop(): Promise<void> {
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
    const url = request.url ?? "";
    const decision = checkRequest(this.options.policy, { method, url });
    if (!decision.allowed) {
      await this.reject(response, "scope_blocked", decision.reason ?? "request blocked", method, url, started);
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

    let upstream: Response;
    try {
      const body = await this.readBody(request);
      upstream = await fetch(url, {
        method,
        headers,
        body: body.length > 0 ? new Uint8Array(body) : undefined,
        redirect: "manual",
      });
    } catch (error) {
      response.writeHead(502, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { code: "upstream_error", message: String(error) } }));
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

    const responseHeaders: Record<string, string> = {};
    upstream.headers.forEach((value, key) => {
      if (!["content-encoding", "content-length", "transfer-encoding", "connection"].includes(key)) {
        responseHeaders[key] = SENSITIVE.has(key) ? "[REDACTED]" : value;
      }
    });
    response.writeHead(upstream.status, responseHeaders);
    response.end(Buffer.from(await upstream.arrayBuffer()));
    await this.record({
      method,
      url,
      identityId,
      status: upstream.status,
      scopeDecision: "allowed",
      durationMs: Date.now() - started,
      requestHeaders: this.redactHeaders(request.headers),
      responseHeaders,
    });
  }

  private handleConnect(request: IncomingMessage, socket: Socket, head: Buffer): void {
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
    const upstream = netConnect(port, host, () => {
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
    this.sockets.add(socket);
    this.sockets.add(upstream);
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
    socket.on("close", () => {
      upstream.destroy();
      this.sockets.delete(socket);
      this.sockets.delete(upstream);
    });
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
