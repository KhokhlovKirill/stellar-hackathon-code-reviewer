import * as vscode from "vscode";
import * as cp from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import {
  extractPatchPaths,
  isSingleFilePatch,
  retargetSingleFilePatch,
  sanitizePatch,
  stripAB,
} from "./patch";

const execFile = util.promisify(cp.execFile);

function getWorkspaceRoot(): string | null {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return null;
  }
  return folders[0].uri.fsPath;
}

function getAllWorkspaceRoots(): string[] {
  return (vscode.workspace.workspaceFolders ?? []).map((f) => f.uri.fsPath);
}

/**
 * Thrown by GitProvider.applyPatch when the patch target file cannot be
 * located in any open workspace folder. Callers (commands/index.ts) catch
 * this to offer interactive recovery (open folder / save / copy).
 */
export class PatchTargetNotFoundError extends Error {
  constructor(
    public readonly targetPath: string,
    public readonly sanitizedPatch: string,
    public readonly searchedRoots: string[]
  ) {
    super(
      `patch target "${targetPath}" not found in any open workspace folder ` +
        `(searched: ${searchedRoots.join(", ") || "<none>"})`
    );
    this.name = "PatchTargetNotFoundError";
  }
}

async function git(
  cwd: string,
  ...args: string[]
): Promise<string> {
  try {
    const { stdout } = await execFile("git", args, { cwd, maxBuffer: 10 * 1024 * 1024 });
    return stdout;
  } catch (err: unknown) {
    const execErr = err as { stderr?: string; message?: string };
    throw new Error(
      `git ${args.join(" ")} failed: ${execErr.stderr ?? execErr.message ?? String(err)}`
    );
  }
}

function runStdin(
  cmd: string,
  root: string,
  args: string[],
  patch: string
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const proc = cp.spawn(cmd, args, { cwd: root });
    let stderr = "";

    proc.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    proc.stdout.on("data", () => {
      /* drained */
    });

    proc.on("close", (code: number | null) => {
      if (code === 0) {
        resolve();
      } else {
        reject(
          new Error(stderr.trim() || `${cmd} ${args.join(" ")} exited with ${code}`)
        );
      }
    });

    proc.on("error", (err: Error) => {
      reject(new Error(`${cmd} spawn error: ${err.message}`));
    });

    proc.stdin.on("error", () => {
      /* EPIPE if the tool rejected the patch before reading stdin */
    });
    proc.stdin.write(patch);
    proc.stdin.end();
  });
}

const runGitApply = (root: string, args: string[], patch: string) =>
  runStdin("git", root, args, patch);

type ParsedHunk = {
  oldStart: number;
  oldLines: string[];
  newLines: string[];
  removedLines: string[];
  addedLines: string[];
};

function parseHunksForDirectApply(patch: string): ParsedHunk[] {
  const hunks: ParsedHunk[] = [];
  let current: ParsedHunk | null = null;
  for (const line of patch.split("\n")) {
    const h = line.match(/^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/);
    if (h) {
      current = {
        oldStart: parseInt(h[1], 10),
        oldLines: [],
        newLines: [],
        removedLines: [],
        addedLines: [],
      };
      hunks.push(current);
      continue;
    }
    if (!current || line.length === 0) continue;
    const prefix = line[0];
    const text = line.slice(1);
    if (prefix === " ") {
      current.oldLines.push(text);
      current.newLines.push(text);
    } else if (prefix === "-") {
      current.oldLines.push(text);
      current.removedLines.push(text);
    } else if (prefix === "+") {
      current.newLines.push(text);
      current.addedLines.push(text);
    }
  }
  return hunks;
}

function findBlock(lines: string[], block: string[], preferredLine: number): number {
  if (block.length === 0 || block.length > lines.length) return -1;
  const matchesAt = (idx: number) =>
    block.every((line, offset) => lines[idx + offset] === line);
  const preferred = Math.max(preferredLine - 1, 0);
  const windowStart = Math.max(preferred - 80, 0);
  const windowEnd = Math.min(preferred + 80, lines.length - block.length);
  for (let i = windowStart; i <= windowEnd; i++) {
    if (matchesAt(i)) return i;
  }
  for (let i = 0; i <= lines.length - block.length; i++) {
    if (matchesAt(i)) return i;
  }
  return -1;
}

export class GitProvider {
  private async getOriginUrl(): Promise<string | null> {
    const root = getWorkspaceRoot();
    if (!root) return null;
    try {
      return (await git(root, "remote", "get-url", "origin")).trim();
    } catch {
      return null;
    }
  }

  async getCurrentBranch(): Promise<string | null> {
    const root = getWorkspaceRoot();
    if (!root) return null;
    try {
      const out = await git(root, "rev-parse", "--abbrev-ref", "HEAD");
      const branch = out.trim();
      return branch === "HEAD" ? null : branch;
    } catch {
      return null;
    }
  }

  async getDiffVsMain(): Promise<string> {
    const root = getWorkspaceRoot();
    if (!root) throw new Error("No workspace folder open");

    // Try common main branch names
    const mainCandidates = ["main", "master", "develop"];
    for (const base of mainCandidates) {
      try {
        const diff = await git(root, "diff", `${base}...HEAD`);
        if (diff.trim()) {
          return diff;
        }
      } catch {
        // Try next candidate
      }
    }

    // Fall back to diff of staged + unstaged changes
    const staged = await git(root, "diff", "--cached").catch(() => "");
    const unstaged = await git(root, "diff").catch(() => "");
    return staged + unstaged;
  }

  async getDiffCurrentFile(filePath: string): Promise<string> {
    const root = getWorkspaceRoot();
    if (!root) throw new Error("No workspace folder open");

    const relPath = path.relative(root, filePath);
    // Try diff vs main first
    const mainCandidates = ["main", "master", "develop"];
    for (const base of mainCandidates) {
      try {
        const diff = await git(root, "diff", `${base}...HEAD`, "--", relPath);
        if (diff.trim()) return diff;
      } catch {
        // continue
      }
    }
    // Fall back to working tree diff
    const staged = await git(root, "diff", "--cached", "--", relPath).catch(() => "");
    const unstaged = await git(root, "diff", "--", relPath).catch(() => "");
    return staged + unstaged;
  }

  async getRepoSlug(): Promise<string | null> {
    const info = await this.getRepoRemoteInfo();
    return info?.slug ?? null;
  }

  async getRepoRemoteInfo(): Promise<{
    provider: "github" | "gitlab" | "unknown";
    slug: string;
    url: string;
    host: string;
  } | null> {
    const remoteUrl = await this.getOriginUrl();
    if (!remoteUrl) return null;

    const ssh = remoteUrl.match(/^git@([^:]+):(.+?)(?:\.git)?$/);
    if (ssh) {
      const host = ssh[1];
      const slug = ssh[2].replace(/\.git$/, "");
      return {
        provider: host === "github.com" ? "github" : "gitlab",
        slug,
        url: remoteUrl,
        host,
      };
    }

    const https = remoteUrl.match(/^https?:\/\/([^/]+)\/(.+?)(?:\.git)?$/);
    if (https) {
      const host = https[1];
      const slug = https[2].replace(/\.git$/, "");
      return {
        provider: host === "github.com" ? "github" : "gitlab",
        slug,
        url: remoteUrl,
        host,
      };
    }
    return null;
  }

  /** All repo files (tracked + untracked, excluding ignored). */
  private async listRepoFiles(root: string): Promise<string[]> {
    try {
      const out = await git(
        root,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard"
      );
      return out.split("\n").map((l) => l.trim()).filter(Boolean);
    } catch {
      return [];
    }
  }

  /**
   * Resolve a patch target path to a real repo-relative file. LLMs frequently
   * emit a bare or wrong path (e.g. `auth_test.py`) while the finding knows
   * the true path. Order: caller hints → literal path → unique basename match.
   */
  private async resolveTargetPath(
    root: string,
    target: string,
    hintFiles: string[]
  ): Promise<string | null> {
    const exists = (rel: string) => {
      try {
        return fs.existsSync(path.join(root, rel)) &&
          fs.statSync(path.join(root, rel)).isFile();
      } catch {
        return false;
      }
    };

    for (const h of hintFiles) {
      const rel = stripAB(h.trim());
      if (rel && exists(rel)) return rel;
    }
    if (exists(target)) return target;

    const base = target.split("/").pop() ?? target;
    const files = await this.listRepoFiles(root);
    const suffix = files.filter(
      (f) => f === target || f.endsWith(`/${target}`)
    );
    if (suffix.length === 1) return suffix[0];
    const byBase = files.filter((f) => (f.split("/").pop() ?? f) === base);
    if (byBase.length === 1) return byBase[0];
    return null;
  }

  /**
   * Apply an LLM-proposed unified diff robustly.
   *
   * Pipeline: sanitize/recount → for each open workspace folder try to
   * resolve the target file (rewriting bare/incorrect paths to the finding's
   * actual path), then run a chain of progressively more lenient apply
   * strategies, each dry-run before mutating the tree so a failure never
   * leaves a partial patch.
   *
   * If no open folder contains the target file, throws
   * `PatchTargetNotFoundError` so the caller can offer interactive recovery.
   *
   * `opts.hintFiles` should carry the finding's real repo-relative path(s).
   * `opts.rootOverride` forces a specific root (used by the recovery flow
   * after the user picks a folder).
   */
  async applyPatch(
    patch: string,
    opts: { hintFiles?: string[]; rootOverride?: string } = {}
  ): Promise<void> {
    const sanitized = sanitizePatch(patch);
    const roots = opts.rootOverride
      ? [opts.rootOverride]
      : getAllWorkspaceRoots();
    if (roots.length === 0) throw new Error("No workspace folder open");

    let lastNotFound: PatchTargetNotFoundError | null = null;
    for (const root of roots) {
      try {
        await this.applyPatchInRoot(root, sanitized, opts);
        return;
      } catch (err) {
        if (err instanceof PatchTargetNotFoundError) {
          lastNotFound = err;
          continue; // try the next workspace folder
        }
        throw err; // genuine apply error in a matched folder — surface it
      }
    }
    throw (
      lastNotFound ??
      new Error("git apply failed: no candidate workspace folder")
    );
  }

  /**
   * Apply an already-sanitized patch within a specific root, resolving the
   * target file against that root's filesystem and `git ls-files`.
   */
  async applyPatchInRoot(
    root: string,
    sanitizedInput: string,
    opts: { hintFiles?: string[] } = {}
  ): Promise<void> {
    let sanitized = sanitizedInput;

    // Path resolution — only for single-file modification patches. New-file
    // patches (`--- /dev/null`) are applied with their declared path.
    const isNewFile = /^--- \/dev\/null/m.test(sanitized);
    const targets = extractPatchPaths(sanitized);
    if (!isNewFile && isSingleFilePatch(sanitized) && targets.length === 1) {
      const target = targets[0];
      const resolved = await this.resolveTargetPath(
        root,
        target,
        opts.hintFiles ?? []
      );
      if (!resolved) {
        throw new PatchTargetNotFoundError(
          target,
          sanitized,
          getAllWorkspaceRoots()
        );
      }
      if (resolved !== target) {
        sanitized = sanitizePatch(retargetSingleFilePatch(sanitized, resolved));
      }
    }
    const directTarget = !isNewFile && targets.length === 1
      ? await this.resolveTargetPath(root, targets[0], opts.hintFiles ?? [])
      : null;

    type Strategy = {
      label: string;
      check: () => Promise<void>;
      apply: () => Promise<void>;
    };

    const gitStrategy = (
      label: string,
      applyArgs: string[]
    ): Strategy => ({
      label,
      check: () =>
        runGitApply(root, ["apply", "--check", ...applyArgs, "-"], sanitized),
      apply: () => runGitApply(root, ["apply", ...applyArgs, "-"], sanitized),
    });

    const patchStrategy = (label: string, p: string): Strategy => ({
      label,
      check: () =>
        runStdin(
          "patch",
          root,
          [p, "--dry-run", "--forward", "--fuzz=3", "--no-backup-if-mismatch"],
          sanitized
        ),
      apply: () =>
        runStdin(
          "patch",
          root,
          [p, "--forward", "--fuzz=3", "--no-backup-if-mismatch"],
          sanitized
        ),
    });

    const strategies: Strategy[] = [
      gitStrategy("git apply -p1 --recount", [
        "-p1",
        "--recount",
        "--whitespace=fix",
      ]),
      gitStrategy("git apply -p0 --recount", [
        "-p0",
        "--recount",
        "--whitespace=fix",
      ]),
      gitStrategy("git apply --3way", [
        "-p1",
        "--3way",
        "--recount",
        "--whitespace=fix",
      ]),
      gitStrategy("git apply --unidiff-zero", [
        "-p1",
        "--recount",
        "--unidiff-zero",
        "--whitespace=fix",
      ]),
      patchStrategy("patch -p1 --fuzz=3", "-p1"),
      patchStrategy("patch -p0 --fuzz=3", "-p0"),
    ];

    const errors: string[] = [];
    for (const s of strategies) {
      try {
        await s.check();
      } catch (err) {
        errors.push(`[${s.label}] ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      try {
        await s.apply();
        return;
      } catch (err) {
        // Dry-run passed but apply failed — surface immediately, the tree
        // state is now uncertain and retrying other strategies is unsafe.
        throw new Error(
          `git apply failed during '${s.label}': ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    if (directTarget) {
      try {
        await this.applySingleFilePatchBySearch(root, directTarget, sanitized);
        return;
      } catch (err) {
        errors.push(`[direct search apply] ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    throw new Error(
      "git apply failed: the patch did not match the current contents of " +
        `${targets.join(", ") || "the target file"}. The file exists but has ` +
        "changed since the fix was generated — ask Aegis to regenerate the " +
        "fix against the latest code, or use Copy/Download to apply it " +
        "manually.\n\n" +
        errors.join("\n")
    );
  }

  private async applySingleFilePatchBySearch(
    root: string,
    relPath: string,
    sanitized: string
  ): Promise<void> {
    const filePath = path.join(root, relPath);
    const original = fs.readFileSync(filePath, "utf8");
    const newline = original.includes("\r\n") ? "\r\n" : "\n";
    let lines = original.replace(/\r\n/g, "\n").split("\n");
    const hadFinalNewline = lines.length > 0 && lines[lines.length - 1] === "";
    if (hadFinalNewline) lines = lines.slice(0, -1);

    for (const hunk of parseHunksForDirectApply(sanitized)) {
      let idx = findBlock(lines, hunk.oldLines, hunk.oldStart);
      let replaceLen = hunk.oldLines.length;
      let replacement = hunk.newLines;

      if (idx < 0 && hunk.removedLines.length > 0) {
        idx = findBlock(lines, hunk.removedLines, hunk.oldStart);
        replaceLen = hunk.removedLines.length;
        replacement = hunk.addedLines;
      }
      if (idx < 0) {
        throw new Error(`could not locate hunk near line ${hunk.oldStart}`);
      }
      lines.splice(idx, replaceLen, ...replacement);
    }

    const next = lines.join(newline) + (hadFinalNewline ? newline : "");
    fs.writeFileSync(filePath, next, "utf8");
  }
}
