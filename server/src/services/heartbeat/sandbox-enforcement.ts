import { execFile, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { sanitizeRuntimeServiceBaseEnv } from "../runtime-service-env.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_PINNED_SANDBOX_IMAGE =
  "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

export class SandboxEnforcementError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "SandboxEnforcementError";
    this.code = code;
  }
}

/**
 * Trusted deployment policy check (env-only, never mutable by agent config).
 */
export function isRuntimeSandboxEnforced(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.PAPERCLIP_ENFORCE_SANDBOX === "true";
}

export function resolvePinnedSandboxImage(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.PAPERCLIP_SANDBOX_IMAGE?.trim() || DEFAULT_PINNED_SANDBOX_IMAGE;
  const requireDigest = env.PAPERCLIP_SANDBOX_REQUIRE_DIGEST !== "false";
  if (requireDigest && !/@sha256:[a-f0-9]{64}$/i.test(configured)) {
    throw new SandboxEnforcementError(
      "sandbox_image_unpinned",
      `Sandbox image must be pinned by @sha256 digest (got "${configured}").`,
    );
  }
  return configured;
}

export function assertAllowedSandboxWorktreeRoot(
  workspaceCwd: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const trimmed = workspaceCwd.trim();
  if (!trimmed || path.resolve(trimmed) === "/") {
    throw new SandboxEnforcementError(
      "sandbox_workspace_required",
      "A valid isolated task worktree directory is required under sandbox enforcement.",
    );
  }
  const realCwd = fs.existsSync(trimmed) ? fs.realpathSync(trimmed) : path.resolve(trimmed);
  if (realCwd === "/") {
    throw new SandboxEnforcementError("sandbox_workspace_required", "Refusing to mount '/' into sandbox.");
  }

  const allowedRootsRaw = env.PAPERCLIP_SANDBOX_ALLOWED_ROOTS?.trim();
  if (allowedRootsRaw) {
    const allowedRoots = allowedRootsRaw
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean)
      .map((r) => (fs.existsSync(r) ? fs.realpathSync(r) : path.resolve(r)));
    const insideAllowed = allowedRoots.some((root) => {
      const rel = path.relative(root, realCwd);
      return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
    });
    if (!insideAllowed) {
      throw new SandboxEnforcementError(
        "sandbox_workspace_outside_allowed_roots",
        `Worktree "${realCwd}" is outside PAPERCLIP_SANDBOX_ALLOWED_ROOTS.`,
      );
    }
  }
  return realCwd;
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
}): Promise<{ worktreePath: string; image: string } | null> {
  const env = input.env ?? process.env;
  if (!isRuntimeSandboxEnforced(env)) return null;

  if (input.runtimeConfig.sandboxBypass === true || input.runtimeConfig.disableSandbox === true) {
    throw new SandboxEnforcementError(
      "sandbox_policy_violation",
      "Agent configuration cannot disable runtime sandbox enforcement.",
    );
  }
  if (
    input.runtimeConfig.dangerouslySkipPermissions === true ||
    input.runtimeConfig.dangerouslyBypassApprovalsAndSandbox === true
  ) {
    throw new SandboxEnforcementError(
      "sandbox_policy_violation",
      "Unsafe permission-bypass flags are prohibited under runtime sandbox enforcement.",
    );
  }

  if (input.executionTargetDriver === "ssh") {
    throw new SandboxEnforcementError(
      "sandbox_driver_forbidden",
      "Unisolated SSH execution is forbidden when PAPERCLIP_ENFORCE_SANDBOX=true.",
    );
  }

  const worktreePath = assertAllowedSandboxWorktreeRoot(input.workspaceCwd ?? "", env);
  const image = resolvePinnedSandboxImage(env);

  const probe = input.dockerProbe ?? (() => probeDockerSandboxAvailable());
  await probe();

  return { worktreePath, image };
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
  env?: NodeJS.ProcessEnv;
}): string[] {
  const uid = input.uid ?? (typeof process.getuid === "function" ? process.getuid() : 1000);
  const gid = input.gid ?? (typeof process.getgid === "function" ? process.getgid() : 1000);
  if (uid === 0 || gid === 0) {
    throw new SandboxEnforcementError("sandbox_root_forbidden", "Refusing to run sandbox container as root (UID 0).");
  }
  const resolvedWorktree = path.resolve(input.worktreePath);
  if (resolvedWorktree === "/") {
    throw new SandboxEnforcementError("sandbox_workspace_required", "Refusing to mount '/' into sandbox.");
  }

  const sanitizedEnv = sanitizeRuntimeServiceBaseEnv(input.env ?? {});
  const envArgs: string[] = [];
  for (const [k, v] of Object.entries(sanitizedEnv)) {
    if (typeof v === "string") {
      envArgs.push("-e", `${k}=${v}`);
    }
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
    ...envArgs,
    input.image ?? DEFAULT_PINNED_SANDBOX_IMAGE,
    input.command,
    ...(input.args ?? []),
  ];
}

export interface InspectedContainerSecurity {
  containerId: string;
  user: string;
  readonlyRootfs: boolean;
  networkMode: string;
  capDrop: string[];
  securityOpt: string[];
}

export async function verifyRunningContainerSecurityOptions(
  containerName: string,
  runner: (file: string, args: string[]) => Promise<{ stdout: string }> = (file, args) =>
    execFileAsync(file, args, { timeout: 5000 }),
): Promise<InspectedContainerSecurity> {
  const { stdout } = await runner("docker", ["inspect", containerName]);
  const parsed = JSON.parse(stdout) as Array<{
    Id?: string;
    Config?: { User?: string };
    HostConfig?: {
      ReadonlyRootfs?: boolean;
      NetworkMode?: string;
      CapDrop?: string[];
      SecurityOpt?: string[];
    };
  }>;
  const info = parsed[0];
  if (!info) {
    throw new SandboxEnforcementError("sandbox_inspect_failed", `Container ${containerName} not found during inspect.`);
  }
  const user = info.Config?.User ?? "";
  const readonlyRootfs = info.HostConfig?.ReadonlyRootfs === true;
  const networkMode = info.HostConfig?.NetworkMode ?? "";
  const capDrop = info.HostConfig?.CapDrop ?? [];
  const securityOpt = info.HostConfig?.SecurityOpt ?? [];

  if (!user || user === "0" || user === "0:0" || user === "root") {
    throw new SandboxEnforcementError("sandbox_policy_violation", `Container running as forbidden user: "${user}"`);
  }
  if (!readonlyRootfs || networkMode !== "none" || !capDrop.includes("ALL") || !securityOpt.includes("no-new-privileges")) {
    throw new SandboxEnforcementError(
      "sandbox_policy_violation",
      `Container security options do not meet policy: readonly=${readonlyRootfs}, net=${networkMode}, capDrop=${capDrop.join(",")}, secOpt=${securityOpt.join(",")}`,
    );
  }
  return {
    containerId: info.Id ?? containerName,
    user,
    readonlyRootfs,
    networkMode,
    capDrop,
    securityOpt,
  };
}

export async function runCommandInDockerSandbox(input: {
  worktreePath: string;
  containerName: string;
  image?: string;
  command: string;
  args?: string[];
  signal?: AbortSignal;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  inspectSecurity?: boolean;
}): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
  containerName: string;
  inspectedSecurity?: InspectedContainerSecurity;
}> {
  const dockerArgs = buildDockerSandboxRunArgs(input);
  return await new Promise((resolve, reject) => {
    const child = spawn("docker", dockerArgs, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let inspectedSecurity: InspectedContainerSecurity | undefined;

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

    if (input.inspectSecurity) {
      setTimeout(() => {
        if (!settled) {
          verifyRunningContainerSecurityOptions(input.containerName)
            .then((sec) => {
              inspectedSecurity = sec;
            })
            .catch(() => {});
        }
      }, 250);
    }

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
      resolve({ exitCode: code ?? 1, stdout, stderr, containerName: input.containerName, inspectedSecurity });
    });
  });
}

/**
 * Enforces that under PAPERCLIP_ENFORCE_SANDBOX=true, local/unisolated adapter
 * execution NEVER runs directly on the host OS: it executes inside the Docker
 * sandbox or fails closed if no containerizable command spec is available.
 */
export async function executeInEnforcedSandbox(input: {
  runId: string;
  adapterType: string;
  runtimeConfig: Record<string, unknown>;
  workspaceCwd: string;
  commandSpec: { command: string; args?: string[]; env?: Record<string, string> } | null;
  signal?: AbortSignal;
  onLog?: (stream: "stdout" | "stderr", chunk: string) => Promise<void> | void;
}): Promise<{ exitCode: number; signal: string | null; timedOut: boolean; containerName: string }> {
  const verified = await assertSandboxDispatchAllowed({
    adapterType: input.adapterType,
    runtimeConfig: input.runtimeConfig,
    workspaceCwd: input.workspaceCwd,
    executionTargetDriver: "local",
  });
  if (!verified) {
    throw new SandboxEnforcementError("sandbox_not_enforced", "executeInEnforcedSandbox called when sandbox not enforced.");
  }
  if (!input.commandSpec || !input.commandSpec.command) {
    throw new SandboxEnforcementError(
      "sandbox_host_fallback_forbidden",
      `Adapter "${input.adapterType}" has no containerizable commandSpec; host execution fallback is forbidden.`,
    );
  }

  const containerName = `tendra-sbx-${input.runId.replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 32)}-${Date.now()}`;
  const res = await runCommandInDockerSandbox({
    worktreePath: verified.worktreePath,
    containerName,
    image: verified.image,
    command: input.commandSpec.command,
    args: input.commandSpec.args,
    env: input.commandSpec.env,
    signal: input.signal,
  });
  if (res.stdout) await input.onLog?.("stdout", res.stdout);
  if (res.stderr) await input.onLog?.("stderr", res.stderr);
  return {
    exitCode: res.exitCode,
    signal: input.signal?.aborted ? "SIGTERM" : null,
    timedOut: false,
    containerName: res.containerName,
  };
}
