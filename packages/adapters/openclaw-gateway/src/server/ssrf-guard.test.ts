import https from "node:https";
import { describe, expect, it } from "vitest";
import { assertSafeGatewayWebSocketUrl, resolveAndPinGatewayWebSocket } from "./ssrf-guard.js";

describe("openclaw-gateway WebSocket SSRF & DNS rebinding guard (SEC-P1-4 / H07)", () => {
  it("blocks localhost, loopback, metadata, private RFC1918, and IPv4-mapped IPv6 bypasses", async () => {
    const blocked = [
      "ws://localhost:8080/ws",
      "ws://127.0.0.1:8080/ws",
      "ws://169.254.169.254/latest/meta-data",
      "wss://10.0.0.1:443/ws",
      "wss://192.168.1.10:443/ws",
      "wss://172.16.0.5:443/ws",
      "ws://[::1]:8080/ws",
      "ws://[::ffff:127.0.0.1]:8080/ws",
      "ws://[::ffff:7f00:1]:8080/ws",
      "ws://[::ffff:169.254.169.254]:80/ws",
      "ws://[::ffff:10.0.0.1]:80/ws",
      "http://example.com",
    ];
    for (const url of blocked) {
      await expect(assertSafeGatewayWebSocketUrl(url)).rejects.toThrow();
    }
  });

  it("pins validated IP at socket lookup to defeat DNS rebinding while preserving wss SNI", async () => {
    let calls = 0;
    const pinned = await resolveAndPinGatewayWebSocket("wss://gateway.example.com/ws", {
      lookupFn: async () => {
        calls += 1;
        // First lookup is public; any subsequent lookup would rebind to loopback.
        return calls === 1
          ? [{ address: "93.184.216.34", family: 4 }]
          : [{ address: "127.0.0.1", family: 4 }];
      },
    });

    expect(pinned.pinnedAddress).toBe("93.184.216.34");
    expect(pinned.family).toBe(4);
    expect(pinned.agent).toBeInstanceOf(https.Agent);
    expect((pinned.agent as https.Agent & { options: { servername?: string } }).options.servername).toBe(
      "gateway.example.com",
    );

    // Invoke the agent's pinned lookup directly: must return 93.184.216.34, never 127.0.0.1
    const agentLookup = (pinned.agent as https.Agent & { options: { lookup: Function } }).options.lookup;
    const resolvedIp = await new Promise<string>((resolve, reject) => {
      agentLookup("gateway.example.com", {}, (err: Error | null, addr: string) => {
        if (err) reject(err);
        else resolve(addr);
      });
    });
    expect(resolvedIp).toBe("93.184.216.34");
    expect(calls).toBe(1);
  });

  it("allows public IP WebSocket URLs and explicit allowPrivate override", async () => {
    await expect(assertSafeGatewayWebSocketUrl("wss://93.184.216.34/ws")).resolves.toBeInstanceOf(URL);
    await expect(
      assertSafeGatewayWebSocketUrl("ws://127.0.0.1:8080/ws", { allowPrivate: true }),
    ).resolves.toBeInstanceOf(URL);
  });
});
