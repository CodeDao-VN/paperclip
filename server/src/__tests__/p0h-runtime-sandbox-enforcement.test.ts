import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertSandboxDispatchAllowed,
  buildDockerSandboxRunArgs,
  probeDockerSandboxAvailable,
  runCommandInDockerSandbox,
  SandboxEnforcementError,
} from "../services/heartbeat/sandbox-enforcement.js";

const execFileAsync = promisify(execFile);

describe("P0-H H06 Runtime Sandbox Enforcement (10 cases)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
  });

  it("Case 2 & 3: fails closed when Docker is unavailable or probe fails", async () => {
    await expect(
      probeDockerSandboxAvailable(async () => {
        throw new Error("Cannot connect to the Docker daemon");
      }),
    ).rejects.toThrow(SandboxEnforcementError);

    await expect(
      assertSandboxDispatchAllowed({
        adapterType: "claude_local",
        runtimeConfig: {},
        workspaceCwd: "/tmp/wt-1",
        executionTargetDriver: "local",
        env: { PAPERCLIP_ENFORCE_SANDBOX: "true" },
        dockerProbe: async () => {
          throw new SandboxEnforcementError("sandbox_unavailable", "docker down");
        },
      }),
    ).rejects.toThrow(/docker down/);
  });

  it("Case 10: rejects agent bypass flags, ssh fallback, and missing workspace", async () => {
    await expect(
      assertSandboxDispatchAllowed({
        adapterType: "claude_local",
        runtimeConfig: { dangerouslySkipPermissions: true },
        workspaceCwd: "/tmp/wt-1",
        env: { PAPERCLIP_ENFORCE_SANDBOX: "true" },
        dockerProbe: async () => "28.0.2",
      }),
    ).rejects.toThrow(/prohibited/);

    await expect(
      assertSandboxDispatchAllowed({
        adapterType: "claude_local",
        runtimeConfig: { disableSandbox: true },
        workspaceCwd: "/tmp/wt-1",
        env: { PAPERCLIP_ENFORCE_SANDBOX: "true" },
        dockerProbe: async () => "28.0.2",
      }),
    ).rejects.toThrow(/cannot disable/);

    await expect(
      assertSandboxDispatchAllowed({
        adapterType: "claude_local",
        runtimeConfig: {},
        workspaceCwd: "/tmp/wt-1",
        executionTargetDriver: "ssh",
        env: { PAPERCLIP_ENFORCE_SANDBOX: "true" },
        dockerProbe: async () => "28.0.2",
      }),
    ).rejects.toThrow(/SSH execution is forbidden/);
  });

  it("builds non-root, read-only, --network none, --cap-drop=ALL Docker args without host secrets", () => {
    const args = buildDockerSandboxRunArgs({
      worktreePath: "/tmp/wt-1",
      containerName: "tendra-test-c1",
      command: "sh",
      args: ["-c", "echo ok"],
      uid: 1000,
      gid: 1000,
    });
    expect(args).toContain("--network");
    expect(args).toContain("none");
    expect(args).toContain("--read-only");
    expect(args).toContain("--cap-drop=ALL");
    expect(args).toContain("--security-opt=no-new-privileges");
    expect(args).toContain("1000:1000");
    expect(args.join(" ")).not.toContain("docker.sock");
    expect(args.join(" ")).not.toContain(".ssh");
  });

  it("Cases 1, 4, 5, 6, 7, 8, 9: runs real Docker sandboxes with isolation, concurrency, and cancel cleanup", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-h06-rt-"));
    tempDirs.push(root);
    const wt1 = path.join(root, "wt-1");
    const wt2 = path.join(root, "wt-2");
    await fs.mkdir(wt1, { recursive: true });
    await fs.mkdir(wt2, { recursive: true });
    await fs.writeFile(path.join(wt2, "secret.txt"), "agent2-secret");

    await assertSandboxDispatchAllowed({
      adapterType: "claude_local",
      runtimeConfig: { dangerouslySkipPermissions: false },
      workspaceCwd: wt1,
      executionTargetDriver: "local",
      env: { PAPERCLIP_ENFORCE_SANDBOX: "true" },
    });

    // Cases 1, 4, 5, 6, 7, 8: Concurrent runs + cross-workspace/socket/ssh/network denial
    const [res1, res2] = await Promise.all([
      runCommandInDockerSandbox({
        worktreePath: wt1,
        containerName: `tendra-rt-1-${Date.now()}`,
        command: "sh",
        args: [
          "-c",
          [
            "echo agent1 > /workspace/out1.txt",
            `if cat "${wt2}/secret.txt" 2>/dev/null; then exit 11; fi`,
            "if ls /home/ubuntu/.ssh 2>/dev/null; then exit 12; fi",
            "if ls /var/run/docker.sock 2>/dev/null; then exit 13; fi",
            "if nc -z -w1 github.com 443 2>/dev/null; then exit 14; fi",
            "echo ISOLATION_OK",
          ].join(" && "),
        ],
      }),
      runCommandInDockerSandbox({
        worktreePath: wt2,
        containerName: `tendra-rt-2-${Date.now()}`,
        command: "sh",
        args: ["-c", "echo agent2 > /workspace/out2.txt && echo CONCURRENT_OK"],
      }),
    ]);

    expect(res1.exitCode).toBe(0);
    expect(res1.stdout).toContain("ISOLATION_OK");
    expect(res2.exitCode).toBe(0);
    expect(res2.stdout).toContain("CONCURRENT_OK");

    // Case 9: Abort/cancel cleans up container leaving zero orphan containers
    const cancelName = `tendra-rt-cancel-${Date.now()}`;
    const ac = new AbortController();
    const cancelPromise = runCommandInDockerSandbox({
      worktreePath: wt1,
      containerName: cancelName,
      command: "sleep",
      args: ["30"],
      signal: ac.signal,
    });
    setTimeout(() => ac.abort(), 300);
    await cancelPromise;
    const { stdout: psOut } = await execFileAsync("docker", ["ps", "-a", "--filter", `name=${cancelName}`, "--format", "{{.Names}}"]);
    expect(psOut.trim()).toBe("");
  }, 30_000);
});
