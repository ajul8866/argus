import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

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

function subnetList(cidrs: string[]): BlockList {
  const list = new BlockList();
  for (const cidr of cidrs) {
    const parts = cidr.trim().split("/");
    const network = parts[0];
    const rawPrefix = parts[1];
    if (parts.length !== 2 || !network || !rawPrefix || !/^\d+$/.test(rawPrefix)) continue;
    const family = isIP(network);
    const prefix = Number(rawPrefix);
    if (!family || !Number.isInteger(prefix) || prefix < 0 || prefix > (family === 6 ? 128 : 32)) continue;
    list.addSubnet(network, prefix, family === 6 ? "ipv6" : "ipv4");
  }
  return list;
}

// BlockList normalizes expanded and IPv4-mapped IPv6 addresses before matching.
const BLOCKED_ADDRESSES = subnetList([
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
  "::/96",
  "fc00::/7",
  "fe80::/10",
  "fec0::/10",
  "ff00::/8",
]);

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

/** Request scope only; forwarding still requires resolved address validation. */
export function checkRequestScope(policy: EgressPolicy, request: EgressRequest): EgressDecision {
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
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { allowed: false, reason: "target requires http or https" };
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
  return { allowed: true };
}

function checkAddresses(policy: EgressPolicy, addresses: string[]): EgressDecision {
  const cidrs = policy.allowedCidrs.filter(Boolean);
  const allowed = cidrs.length ? subnetList(cidrs) : null;
  for (const ip of addresses) {
    const family = isIP(ip);
    if (!family) return { allowed: false, reason: `address ${ip} is invalid` };
    const type = family === 6 ? "ipv6" : "ipv4";
    if (allowed) {
      if (!allowed.check(ip, type)) {
        return { allowed: false, reason: `address ${ip} is outside the allowed CIDRs` };
      }
    } else if (BLOCKED_ADDRESSES.check(ip, type)) {
      return { allowed: false, reason: `address ${ip} is not routable` };
    }
  }
  return { allowed: true };
}

export function checkRequest(
  policy: EgressPolicy,
  request: EgressRequest,
  resolvedIps: string[] = [],
): EgressDecision {
  const scope = checkRequestScope(policy, request);
  if (!scope.allowed) return scope;
  if (resolvedIps.length > 0) {
    return checkAddresses(policy, resolvedIps);
  }
  const url = new URL(request.url);
  if (!isLoopbackHost(url.hostname) && !policy.allowedCidrs.filter(Boolean).length) {
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

export type AddressLookup = (host: string) => Promise<string[]>;

async function lookupAddresses(host: string): Promise<string[]> {
  const records = await lookup(host, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

/**
 * Resolves a hostname once and returns every address. The caller must pin one
 * of these addresses for the actual connection so a second, independent
 * resolution cannot land somewhere else (DNS rebinding).
 */
export async function resolveAndValidate(
  policy: EgressPolicy,
  host: string,
  resolve: AddressLookup = lookupAddresses,
): Promise<{ allowed: boolean; reason?: string; addresses: string[] }> {
  if (!hostAllowed(host, policy.allowedHosts)) {
    return { allowed: false, reason: `host ${host} is outside the scope`, addresses: [] };
  }
  let addresses: string[] = [];
  try {
    addresses = isIP(host) ? [host] : host.toLowerCase() === "localhost" ? ["127.0.0.1"] : await resolve(host);
  } catch {
    return { allowed: false, reason: `host ${host} did not resolve`, addresses: [] };
  }
  if (addresses.length === 0) {
    return { allowed: false, reason: `host ${host} did not resolve`, addresses: [] };
  }
  return { ...checkAddresses(policy, addresses), addresses };
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
