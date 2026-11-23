import { describe, expect, it } from "vitest";
import { buildSshSpawnTarget } from "./ssh.js";

describe("SSH option injection hardening (SEC-P1-4 / H07)", () => {
  it("rejects leading '-' or whitespace in SSH host or username", async () => {
    await expect(
      buildSshSpawnTarget({
        spec: {
          host: "-oProxyCommand=id",
          port: 22,
          username: "ubuntu",
          remoteCwd: "/tmp",
        },
        command: "echo",
        args: ["ok"],
        env: {},
      }),
    ).rejects.toThrow(/Unsafe SSH host/);

    await expect(
      buildSshSpawnTarget({
        spec: {
          host: "example.com",
          port: 22,
          username: "-oPermitLocalCommand=yes",
          remoteCwd: "/tmp",
        },
        command: "echo",
        args: ["ok"],
        env: {},
      }),
    ).rejects.toThrow(/Unsafe SSH username/);
  });

  it("places '--' end-of-options separator before user@host", async () => {
    const target = await buildSshSpawnTarget({
      spec: {
        host: "example.com",
        port: 2222,
        username: "deploy",
        remoteCwd: "/srv/app",
      },
      command: "node",
      args: ["-v"],
      env: {},
    });
    const idxSep = target.args.indexOf("--");
    expect(idxSep).toBeGreaterThan(-1);
    expect(target.args[idxSep + 1]).toBe("deploy@example.com");
    await target.cleanup();
  });
});
