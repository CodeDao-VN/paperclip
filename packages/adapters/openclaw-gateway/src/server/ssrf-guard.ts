import dns from "node:dns/promises";
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

function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.replace(/^\[|\]$/g, "").split("%")[0]!.toLowerCase();
  if (net.isIPv4(ip)) return isPrivateOrReservedIpv4(ip);
  if (net.isIPv6(ip)) {
    if (ip === "::" || ip === "::1") return true;
    if (ip.startsWith("::ffff:")) {
      const mapped = ip.slice("::ffff:".length);
      if (net.isIPv4(mapped)) return isPrivateOrReservedIpv4(mapped);
    }
    if (ip.startsWith("fc") || ip.startsWith("fd")) return true; // ULA fc00::/7
    if (ip.startsWith("fe8") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb")) return true; // fe80::/10
    return false;
  }
  return true;
}

export async function assertSafeGatewayWebSocketUrl(
  rawUrl: string,
  options?: { allowPrivate?: boolean },
): Promise<URL> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
    throw new Error(`Unsupported WebSocket protocol: ${parsed.protocol}`);
  }
  const allowPrivate =
    options?.allowPrivate === true || process.env.PAPERCLIP_OPENCLAW_GATEWAY_ALLOW_PRIVATE === "true";
  if (allowPrivate) return parsed;

  const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new Error(`Blocked private/local WebSocket host: ${host}`);
  }
  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) {
      throw new Error(`Blocked private/reserved WebSocket IP: ${host}`);
    }
    return parsed;
  }
  const resolved = await dns.lookup(host, { all: true });
  if (resolved.length === 0) {
    throw new Error(`Unable to resolve WebSocket host: ${host}`);
  }
  for (const entry of resolved) {
    if (isPrivateOrReservedIp(entry.address)) {
      throw new Error(`Blocked WebSocket host resolving to private/reserved IP (${entry.address}): ${host}`);
    }
  }
  return parsed;
}
