import { lookup } from "node:dns/promises";

export type EgressPolicy = {  baseUrl: string;
  allowedHosts: string[];
  allowedCidrs: string[];
  allowedMethods: string[];
  allowedPorts?: number[];
  maxRps: number;
  tls: boolean;
  authorizedActions?: { methods?: string[]; require_approval_for?: string[] };
  restrictions?: { allowed_paths?: string[]; denied_paths?: string[]; notes?: string };
};

export type EgressRequest = { method: string; url: string; identityId?: string | null };
export type EgressDecision = { allowed: boolean; reason?: string };

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

function cidrMatch(ip: string, cidr: string): boolean {
  const [network, prefixRaw] = cidr.trim().split("/");
  if (!network || prefixRaw === undefined) return false;
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const address = ipv4ToInt(ip);
  const base = ipv4ToInt(network);
  if (address === null || base === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (address & mask) === (base & mask);
}

function isBlockedAddress(ip: string): boolean {
  if (ip.includes(":")) {
    const lower = ip.toLowerCase();
    return (
      lower === "::1" ||
      lower === "::" ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") ||
      lower.startsWith("fe80:") ||
      lower.startsWith("::ffff:127.") ||
      lower.startsWith("::ffff:10.") ||
      lower.startsWith("::ffff:192.168.")
    );
  }
  const blocked = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
  ];
  return blocked.some((cidr) => cidrMatch(ip, cidr));
}

function hostAllowed(host: string, allowedHosts: string[]): boolean {
  const target = host.toLowerCase();
  return allowedHosts.some((entry) => {
    const rule = entry.toLowerCase();
    return rule.startsWith("*.") ? target.endsWith(rule.slice(1)) : target === rule;
  });
}

function pathAllowed(path: string, restrictions: EgressPolicy["restrictions"]): boolean {
  const allowed = restrictions?.allowed_paths ?? [];
  const denied = restrictions?.denied_paths ?? [];
  if (denied.some((prefix) => path.startsWith(prefix))) return false;
  if (allowed.length > 0 && !allowed.some((prefix) => path.startsWith(prefix))) return false;
  return true;
}

export function checkRequest(
  policy: EgressPolicy,
  request: EgressRequest,
  resolvedIps: string[] = [],
): EgressDecision {
  const method = request.method.trim().toUpperCase();
  const methods = [
    ...policy.allowedMethods,
    ...(policy.authorizedActions?.methods ?? []),
  ].map((entry) => entry.toUpperCase());
  if (!methods.includes(method)) return { allowed: false, reason: `method ${method} is not allowed` };

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return { allowed: false, reason: "url is invalid" };
  }
  if (policy.tls && url.protocol !== "https:") {
    return { allowed: false, reason: "target requires https" };
  }
  if (!hostAllowed(url.hostname, policy.allowedHosts)) {
    return { allowed: false, reason: `host ${url.hostname} is outside the scope` };
  }
  if (!pathAllowed(url.pathname, policy.restrictions)) {
    return { allowed: false, reason: `path ${url.pathname} is not allowed` };
  }
  if (resolvedIps.length > 0) {
    const cidrs = policy.allowedCidrs.filter(Boolean);
    for (const ip of resolvedIps) {
      if (cidrs.length > 0) {
        if (!cidrs.some((cidr) => cidrMatch(ip, cidr))) {
          return { allowed: false, reason: `address ${ip} is outside the allowed CIDRs` };
        }
      } else if (isBlockedAddress(ip)) {
        return { allowed: false, reason: `address ${ip} is not routable` };
      }
    }
  } else if (!isLoopbackHost(url.hostname) && !policy.allowedCidrs.filter(Boolean).length) {
    // Without a resolution result the address class is unknown, so a request
    // could reach a private or metadata address through DNS. Fail closed.
    return { allowed: false, reason: "the request was not resolved and pinned" };
  }
  return { allowed: true };
}

export function isLoopbackHost(host: string): boolean {
  const name = host.toLowerCase().replace(/^\[|\]$/g, "");
  return name === "localhost" || name === "::1" || name.startsWith("127.");
}

/**
 * Resolves a hostname once and returns every address. The caller must pin one
 * of these addresses for the actual connection so a second, independent
 * resolution cannot land somewhere else (DNS rebinding).
 */
export async function resolveAndValidate(
  policy: EgressPolicy,
  host: string,
): Promise<{ allowed: boolean; reason?: string; addresses: string[] }> {
  if (isLoopbackHost(host)) {
    const address = host === "localhost" || host === "::1" || host === "[::1]" ? "127.0.0.1" : host;
    const decision = checkRequest(policy, { method: "GET", url: `http://${host}/` }, [address]);
    return { allowed: decision.allowed, reason: decision.reason, addresses: [address] };
  }
  let addresses: string[] = [];
  try {
    const records = await lookup(host, { all: true, verbatim: true });
    addresses = records.map((record) => record.address);
  } catch {
    return { allowed: false, reason: `host ${host} did not resolve`, addresses: [] };
  }
  if (addresses.length === 0) {
    return { allowed: false, reason: `host ${host} did not resolve`, addresses: [] };
  }
  const decision = checkRequest(policy, { method: "GET", url: `http://${host}/` }, addresses);
  return { allowed: decision.allowed, reason: decision.reason, addresses };
}

export function checkRedirect(
  fromUrl: string,
  toUrl: string,
  policy: EgressPolicy,
  redirectCount: number,
): EgressDecision {
  if (redirectCount >= 3) return { allowed: false, reason: "redirect limit reached" };
  try {
    new URL(fromUrl);
    new URL(toUrl);
  } catch {
    return { allowed: false, reason: "redirect url is invalid" };
  }
  return checkRequest(policy, { method: "GET", url: toUrl });
}

export function checkTunnel(policy: EgressPolicy, host: string, port: number): EgressDecision {
  if (!hostAllowed(host, policy.allowedHosts)) {
    return { allowed: false, reason: `host ${host} is outside the scope` };
  }
  const allowed = policy.allowedPorts ?? [80, 443];
  if (!allowed.includes(port)) {
    return { allowed: false, reason: `port ${port} is not allowed` };
  }
  return { allowed: true };
}

export class RateLimiter {
  private readonly hits = new Map<string, number[]>();

  allow(key: string, maxRps: number, at = Date.now()): boolean {
    const recent = (this.hits.get(key) ?? []).filter((timestamp) => at - timestamp < 1_000);
    if (recent.length >= maxRps) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(at);
    this.hits.set(key, recent);
    return true;
  }

  reset(key?: string): void {
    if (key) this.hits.delete(key);
    else this.hits.clear();
  }
}
