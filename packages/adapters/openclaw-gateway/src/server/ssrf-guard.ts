import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";

function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local & cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function parseIpv4MappedHex(suffix: string): string | null {
  const parts = suffix.split(":");
  if (parts.length !== 2) return null;
  const hi = Number.parseInt(parts[0]!, 16);
  const lo = Number.parseInt(parts[1]!, 16);
  if (!Number.isInteger(hi) || !Number.isInteger(lo) || hi < 0 || hi > 0xffff || lo < 0 || lo > 0xffff) {
    return null;
  }
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.replace(/^\[|\]$/g, "").split("%")[0]!.toLowerCase();
  if (net.isIPv4(ip)) return isPrivateOrReservedIpv4(ip);
  if (net.isIPv6(ip)) {
    if (ip === "::" || ip === "::1") return true;
    if (ip.startsWith("::ffff:")) {
      const mapped = ip.slice("::ffff:".length);
      if (net.isIPv4(mapped)) return isPrivateOrReservedIpv4(mapped);
      const dotted = parseIpv4MappedHex(mapped);
      if (dotted) return isPrivateOrReservedIpv4(dotted);
      return true;
    }
    if (ip.startsWith("fc") || ip.startsWith("fd")) return true; // ULA fc00::/7
    if (ip.startsWith("fe8") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb")) return true; // fe80::/10
    return false;
  }
  return true;
}

export interface PinnedWebSocketTarget {
  url: URL;
  pinnedAddress: string | null;
  family: 4 | 6 | null;
  agent: http.Agent | https.Agent | undefined;
}

export async function resolveAndPinGatewayWebSocket(
  rawUrl: string,
  options?: {
    allowPrivate?: boolean;
    lookupFn?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
  },
): Promise<PinnedWebSocketTarget> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
    throw new Error(`Unsupported WebSocket protocol: ${parsed.protocol}`);
  }
  const allowPrivate =
    options?.allowPrivate === true || process.env.PAPERCLIP_OPENCLAW_GATEWAY_ALLOW_PRIVATE === "true";
  if (allowPrivate) {
    return { url: parsed, pinnedAddress: null, family: null, agent: undefined };
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new Error(`Blocked private/local WebSocket host: ${host}`);
  }

  let pinnedAddress: string;
  let family: 4 | 6;

  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) {
      throw new Error(`Blocked private/reserved WebSocket IP: ${host}`);
    }
    pinnedAddress = host;
    family = net.isIPv6(host) ? 6 : 4;
  } else {
    const lookupFn = options?.lookupFn ?? ((h: string) => dns.lookup(h, { all: true }));
    const resolved = await lookupFn(host);
    if (resolved.length === 0) {
      throw new Error(`Unable to resolve WebSocket host: ${host}`);
    }
    for (const entry of resolved) {
      if (isPrivateOrReservedIp(entry.address)) {
        throw new Error(`Blocked WebSocket host resolving to private/reserved IP (${entry.address}): ${host}`);
      }
    }
    pinnedAddress = resolved[0]!.address;
    family = net.isIPv6(pinnedAddress) ? 6 : 4;
  }

  // Pin socket-level lookup to the already-validated IP so ws never performs a
  // second DNS resolution (eliminating DNS rebinding), while preserving TLS
  // servername (SNI) and Host header verification for wss:.
  const pinnedLookup = (
    _hostname: string,
    opts: unknown,
    cb?: (err: NodeJS.ErrnoException | null, address: string | Array<{ address: string; family: number }>, family?: number) => void,
  ) => {
    const callback = typeof opts === "function" ? (opts as typeof cb) : cb;
    const all = typeof opts === "object" && opts !== null && (opts as { all?: boolean }).all === true;
    if (!callback) return;
    if (all) {
      callback(null, [{ address: pinnedAddress, family }]);
    } else {
      callback(null, pinnedAddress, family);
    }
  };

  const agent =
    parsed.protocol === "wss:"
      ? new https.Agent({
          lookup: pinnedLookup as never,
          servername: net.isIP(host) ? undefined : host,
        })
      : new http.Agent({
          lookup: pinnedLookup as never,
        });

  return { url: parsed, pinnedAddress, family, agent };
}

export async function assertSafeGatewayWebSocketUrl(
  rawUrl: string,
  options?: { allowPrivate?: boolean },
): Promise<URL> {
  const pinned = await resolveAndPinGatewayWebSocket(rawUrl, options);
  return pinned.url;
}
