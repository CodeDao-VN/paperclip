import { execFile, spawn } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export class SandboxEnforcementError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "SandboxEnforcementError";
    this.code = code;
  }
}

export function isRuntimeSandboxEnforced(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.PAPERCLIP_ENFORCE_SANDBOX === "true";
}

export async function probeDockerSandboxAvailable(
  runner: (file: string, args: string[]) => Promise<{ stdout: string }> = (file, args) =>
    execFileAsync(file, args, { timeout: 5000 }),
): Promise<string> {
  try {
    const { stdout } = await runner("docker", ["info", "--format", "{{.ServerVersion}}"]);
    const version = stdout.trim();
    if (!version) {
      throw new SandboxEnforcementError("sandbox_unavailable", "Docker daemon returned empty server version.");
    }
    return version;
  } catch (err) {
    if (err instanceof SandboxEnforcementError) throw err;
    throw new SandboxEnforcementError(
      "sandbox_unavailable",
      `Docker sandbox unavailable (fail-closed): ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export async function assertSandboxDispatchAllowed(input: {
  adapterType: string;
  runtimeConfig: Record<string, unknown>;
  workspaceCwd?: string | null;
  executionTargetDriver?: string | null;
  env?: NodeJS.ProcessEnv;
  dockerProbe?: () => Promise<string>;
}): Promise<void> {
  if (!isRuntimeSandboxEnforced(input.env)) return;

  // Agent config cannot disable or weaken sandbox enforcement.
  if (input.runtimeConfig.sandboxBypass === true || input.runtimeConfig.disableSandbox === true) {
    throw new SandboxEnforcementError(
      "sandbox_policy_violation",
      "Agent configuration cannot disable runtime sandbox enforcement.",
    );
  }
  if (input.runtimeConfig.dangerouslySkipPermissions === true || input.runtimeConfig.dangerouslyBypassApprovalsAndSandbox === true) {
    throw new SandboxEnforcementError(
      "sandbox_policy_violation",
      "Unsafe permission-bypass flags are prohibited under runtime sandbox enforcement.",
    );
  }

  // Never allow unisolated SSH or raw local host fallback when sandbox is enforced.
  if (input.executionTargetDriver === "ssh") {
    throw new SandboxEnforcementError(
      "sandbox_driver_forbidden",
      "Unisolated SSH execution is forbidden when PAPERCLIP_ENFORCE_SANDBOX=true.",
    );
  }

  const cwd = typeof input.workspaceCwd === "string" ? input.workspaceCwd.trim() : "";
  if (!cwd || path.resolve(cwd) === "/") {
    throw new SandboxEnforcementError(
      "sandbox_workspace_required",
      "A valid isolated task worktree directory is required under sandbox enforcement.",
    );
  }

  const probe = input.dockerProbe ?? (() => probeDockerSandboxAvailable());
  await probe();
}

export function buildDockerSandboxRunArgs(input: {
  worktreePath: string;
  containerName: string;
  image?: string;
  command: string;
  args?: string[];
  uid?: number;
  gid?: number;
  memoryLimit?: string;
  cpus?: string;
  pidsLimit?: number;
}): string[] {
  const uid = input.uid ?? (typeof process.getuid === "function" ? process.getuid() : 1000);
  const gid = input.gid ?? (typeof process.getgid === "function" ? process.getgid() : 1000);
  const resolvedWorktree = path.resolve(input.worktreePath);
  if (resolvedWorktree === "/") {
    throw new SandboxEnforcementError("sandbox_workspace_required", "Refusing to mount '/' into sandbox.");
  }

  return [
    "run",
    "--rm",
    "--name",
    input.containerName,
    "--user",
    `${uid}:${gid}`,
    "--network",
    "none",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=64m",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    `--pids-limit=${input.pidsLimit ?? 128}`,
    `--memory=${input.memoryLimit ?? "512m"}`,
    `--cpus=${input.cpus ?? "1"}`,
    "-v",
    `${resolvedWorktree}:/workspace:rw`,
    "-w",
    "/workspace",
    input.image ?? "alpine:3.20",
    input.command,
    ...(input.args ?? []),
  ];
}

export async function runCommandInDockerSandbox(input: {
  worktreePath: string;
  containerName: string;
  image?: string;
  command: string;
  args?: string[];
  signal?: AbortSignal;
  timeoutMs?: number;
}): Promise<{ exitCode: number; stdout: string; stderr: string; containerName: string }> {
  const dockerArgs = buildDockerSandboxRunArgs(input);
  return await new Promise((resolve, reject) => {
    const child = spawn("docker", dockerArgs, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;

    const cleanupContainer = () => {
      execFile("docker", ["rm", "-f", input.containerName], { timeout: 5000 }, () => {});
    };

    const onAbort = () => {
      child.kill("SIGTERM");
      cleanupContainer();
    };
    input.signal?.addEventListener("abort", onAbort, { once: true });

    const timer =
      input.timeoutMs && input.timeoutMs > 0
        ? setTimeout(() => {
            child.kill("SIGTERM");
            cleanupContainer();
          }, input.timeoutMs)
        : null;

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      input.signal?.removeEventListener("abort", onAbort);
      cleanupContainer();
      reject(new SandboxEnforcementError("sandbox_spawn_failed", err.message));
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      input.signal?.removeEventListener("abort", onAbort);
      cleanupContainer();
      resolve({ exitCode: code ?? 1, stdout, stderr, containerName: input.containerName });
    });
  });
}
