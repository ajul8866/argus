import { BrokerServer, type ExchangeRecord } from "./broker.ts";
import type { EgressPolicy } from "./egress.ts";

/**
 * The broker process that runs inside the audit container. It holds no
 * database and no long-lived secrets: the policy comes from the environment,
 * and identity tokens are supplied once over a private handshake before the
 * worker starts.
 */
export type HandshakeMessage =
  | { type: "hello"; audit_id: string; sha256: string }
  | { type: "identities"; tokens: Record<string, string> }
  | { type: "ready" }
  | { type: "error"; message: string };

export type IdentityTokens = Record<string, string>;

export function policyFromEnvironment(env: Record<string, string | undefined>): EgressPolicy {
  const required = (key: string): string => {
    const value = env[key];
    if (!value) throw new Error(`${key} is required`);
    return value;
  };
  const list = (key: string): string[] =>
    (env[key] ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
  const json = (key: string): Record<string, never> | undefined => {
    const value = env[key];
    if (!value) return undefined;
    return JSON.parse(value) as Record<string, never>;
  };
  return {
    baseUrl: required("ARGUS_TARGET_BASE_URL"),
    allowedHosts: list("ARGUS_ALLOWED_HOSTS"),
    allowedCidrs: list("ARGUS_ALLOWED_CIDRS"),
    allowedMethods: list("ARGUS_ALLOWED_METHODS"),
    maxRps: Number(env.ARGUS_MAX_RPS ?? "5") || 5,
    tls: env.ARGUS_TARGET_TLS !== "0",
    authorizedActions: json("ARGUS_AUTHORIZED_ACTIONS"),
    restrictions: json("ARGUS_RESTRICTIONS"),
  };
}

export type BrokerProcessOptions = {
  port?: number;
  host?: string;
  env?: Record<string, string | undefined>;
  /** Called for each recorded exchange; the caller ships it to Argus. */
  onExchange?: (record: ExchangeRecord) => void | Promise<void>;
};

export type BrokerProcess = {
  port: number;
  stop(): Promise<void>;
  /** Identity tokens are accepted once, before the worker starts. */
  handshake(tokens: IdentityTokens): void;
  ready(): boolean;
};

export async function startBrokerProcess(options: BrokerProcessOptions = {}): Promise<BrokerProcess> {
  const env = options.env ?? process.env;
  const policy = policyFromEnvironment(env);
  let tokens: IdentityTokens = {};
  let handshaken = false;

  const credentials = {
    inject(identityId: string): Record<string, string> {
      if (!handshaken) throw new Error("the identity handshake has not completed");
      const secret = tokens[identityId];
      if (!secret) throw new Error(`identity ${identityId} has no token`);
      return { authorization: /^bearer\s/i.test(secret) ? secret : `Bearer ${secret}` };
    },
  };

  const broker = new BrokerServer({
    policy,
    credentials,
    onExchange: options.onExchange,
    isReady: () => handshaken,
  });
  const port = (
    await broker.start(options.port ?? Number(env.ARGUS_BROKER_PORT ?? "8080"), options.host ?? env.ARGUS_BROKER_HOST ?? "127.0.0.1")
  ).port;
  return {
    port,
    handshake(next: IdentityTokens) {
      // Only the first handshake wins; a worker cannot replace the tokens.
      if (handshaken) throw new Error("the identity handshake already completed");
      tokens = { ...next };
      handshaken = true;
    },
    ready: () => handshaken,
    stop: () => broker.stop(),
  };
}

if (import.meta.main) {
  const port = Number(process.env.ARGUS_BROKER_PORT ?? "8080");
  void startBrokerProcess({ port }).then((process_) => {
    process.stdout.write(`argus-broker listening on ${process_.port}\n`);
  });
}
