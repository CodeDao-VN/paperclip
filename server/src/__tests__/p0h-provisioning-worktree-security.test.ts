import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  resolveRuntimeProvisionCommand,
  sanitizeRuntimeServiceBaseEnv,
  realizeExecutionWorkspace,
  WorkspaceRuntimeValidationFailure,
} from "../services/workspace-runtime.js";

const execFileAsync = promisify(execFile);

describe("P0-H H05 provisioning & worktree security (SEC-P1-1, SEC-P1-2)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
  });

  it("strips synthetic server secrets via sanitizeRuntimeServiceBaseEnv (SEC-P1-1)", () => {
    const sanitized = sanitizeRuntimeServiceBaseEnv({
      PATH: "/usr/bin:/bin",
      PAPERCLIP_SECRETS_MASTER_KEY: "synthetic-master-key-000",
      BETTER_AUTH_SECRET: "synthetic-auth-secret-000",
      PAPERCLIP_AGENT_JWT_SECRET: "synthetic-jwt-secret-000",
      DATABASE_URL: "postgres://user:pass@localhost:5432/db",
    });

    expect(sanitized.PATH).toBe("/usr/bin:/bin");
    expect(sanitized.PAPERCLIP_SECRETS_MASTER_KEY).toBeUndefined();
    expect(sanitized.BETTER_AUTH_SECRET).toBeUndefined();
    expect(sanitized.PAPERCLIP_AGENT_JWT_SECRET).toBeUndefined();
    expect(sanitized.DATABASE_URL).toBeUndefined();
  });

  it("does not auto-execute repo ./scripts/provision-worktree-runtime.sh without explicit opt-in (SEC-P1-1)", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-h05-seed-"));
    tempDirs.push(dir);
    await fs.mkdir(path.join(dir, "scripts"), { recursive: true });
    await fs.writeFile(path.join(dir, "scripts", "provision-worktree-runtime.sh"), "#!/usr/bin/env bash\nid\n");

    const cmdDefault = resolveRuntimeProvisionCommand(
      { workspaceStrategy: { type: "git_worktree" } },
      {
        mode: "isolated_workspace",
        strategy: "git_worktree",
        cwd: dir,
        repoRoot: dir,
        providerType: "git_worktree",
        providerRef: dir,
        branchName: "test-branch",
        baseRef: "main",
        created: true,
        warnings: [],
      },
    );
    expect(cmdDefault).toBe("");

    const cmdOptIn = resolveRuntimeProvisionCommand(
      { workspaceStrategy: { type: "git_worktree", allowRepoProvisionScript: true } },
      {
        mode: "isolated_workspace",
        strategy: "git_worktree",
        cwd: dir,
        repoRoot: dir,
        providerType: "git_worktree",
        providerRef: dir,
        branchName: "test-branch",
        baseRef: "main",
        created: true,
        warnings: [],
      },
    );
    expect(cmdOptIn).toBe("bash ./scripts/provision-worktree-runtime.sh");
  });

  it("rejects worktreeParentDir path traversal and symlink escapes outside repoRoot (SEC-P1-2)", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-h05-wt-"));
    tempDirs.push(root);
    const repo = path.join(root, "repo");
    const outside = path.join(root, "outside");
    await fs.mkdir(repo, { recursive: true });
    await fs.mkdir(outside, { recursive: true });
    await execFileAsync("git", ["init"], { cwd: repo });
    await execFileAsync("git", ["config", "user.email", "qa@tendra.local"], { cwd: repo });
    await execFileAsync("git", ["config", "user.name", "Tendra QA"], { cwd: repo });
    await fs.writeFile(path.join(repo, "README.md"), "init\n");
    await execFileAsync("git", ["add", "."], { cwd: repo });
    await execFileAsync("git", ["commit", "-m", "init"], { cwd: repo });

    await expect(
      realizeExecutionWorkspace({
        base: {
          baseCwd: repo,
          source: "project_primary",
          projectId: "proj-1",
          workspaceId: "ws-1",
          repoUrl: null,
          repoRef: "HEAD",
        },
        config: {
          workspaceStrategy: {
            type: "git_worktree",
            worktreeParentDir: "../outside",
          },
        },
        issue: null,
        agent: { id: "agent-1", name: "Dev", companyId: "company-1" },
      }),
    ).rejects.toThrow(WorkspaceRuntimeValidationFailure);

    await fs.symlink(outside, path.join(repo, "symlink-escape"));
    await expect(
      realizeExecutionWorkspace({
        base: {
          baseCwd: repo,
          source: "project_primary",
          projectId: "proj-1",
          workspaceId: "ws-1",
          repoUrl: null,
          repoRef: "HEAD",
        },
        config: {
          workspaceStrategy: {
            type: "git_worktree",
            worktreeParentDir: "symlink-escape/sub",
          },
        },
        issue: null,
        agent: { id: "agent-1", name: "Dev", companyId: "company-1" },
      }),
    ).rejects.toThrow(WorkspaceRuntimeValidationFailure);
  });
});
