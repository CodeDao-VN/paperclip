import { describe, expect, it } from "vitest";
import { assertSafeGatewayWebSocketUrl } from "./ssrf-guard.js";

describe("openclaw-gateway WebSocket SSRF guard (SEC-P1-4 / H07)", () => {
  it("blocks localhost, loopback, metadata, private RFC1918, and IPv6 ULA/loopback URLs", async () => {
    const blocked = [
      "ws://localhost:8080/ws",
      "ws://127.0.0.1:8080/ws",
      "ws://169.254.169.254/latest/meta-data",
      "wss://10.0.0.1:443/ws",
      "wss://192.168.1.10:443/ws",
      "wss://172.16.0.5:443/ws",
      "ws://[::1]:8080/ws",
      "http://example.com",
    ];
    for (const url of blocked) {
      await expect(assertSafeGatewayWebSocketUrl(url)).rejects.toThrow();
    }
  });

  it("allows public IP WebSocket URLs and explicit allowPrivate override", async () => {
    await expect(assertSafeGatewayWebSocketUrl("wss://93.184.216.34/ws")).resolves.toBeInstanceOf(URL);
    await expect(
      assertSafeGatewayWebSocketUrl("ws://127.0.0.1:8080/ws", { allowPrivate: true }),
    ).resolves.toBeInstanceOf(URL);
  });
});
