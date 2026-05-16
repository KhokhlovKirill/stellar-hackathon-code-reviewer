/**
 * Pure unified-diff sanitization. No `vscode` dependency so it can be unit
 * tested in isolation. Used by GitProvider.applyPatch.
 */

export const HUNK_HEADER_RE =
  /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$/;

export function isFileHeaderLine(line: string): boolean {
  return (
    line.startsWith("diff --git ") ||
    line.startsWith("index ") ||
    line.startsWith("--- ") ||
    line.startsWith("+++ ") ||
    line.startsWith("new file mode ") ||
    line.startsWith("deleted file mode ") ||
    line.startsWith("old mode ") ||
    line.startsWith("new mode ") ||
    line.startsWith("rename from ") ||
    line.startsWith("rename to ") ||
    line.startsWith("copy from ") ||
    line.startsWith("copy to ") ||
    line.startsWith("similarity index ") ||
    line.startsWith("dissimilarity index ") ||
    line.startsWith("GIT binary patch")
  );
}

/**
 * Strip markdown fences / leading prose and isolate the unified diff payload.
 */
export function stripToDiff(rawPatch: string): string {
  let patch = rawPatch.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();

  const fenced = patch.match(/^```(?:diff|patch)?\s*\n([\s\S]*?)\n?```\s*$/i);
  if (fenced) {
    patch = fenced[1].trim();
  } else {
    // Fenced block somewhere in the middle of prose.
    const inner = patch.match(/```(?:diff|patch)\s*\n([\s\S]*?)```/i);
    if (inner) patch = inner[1].trim();
  }

  if (patch.startsWith("*** Begin Patch") || patch.includes("\n*** Begin Patch")) {
    throw new Error(
      "The proposed fix is an apply_patch transcript, not a git unified diff. " +
        "Ask Aegis to regenerate it as a ```diff``` block."
    );
  }

  const lines = patch.split("\n");
  const start = lines.findIndex(
    (line) =>
      line.startsWith("diff --git ") ||
      line.startsWith("--- ") ||
      HUNK_HEADER_RE.test(line)
  );
  if (start > 0) {
    patch = lines.slice(start).join("\n").trim();
  }

  if (!patch.includes("@@")) {
    throw new Error(
      "The proposed fix does not contain a unified-diff hunk header (@@)."
    );
  }
  return patch;
}

/**
 * Sanitize and recount a (possibly LLM-malformed) unified diff so that
 * `git apply` can parse it.
 *
 * Fixes the two dominant failure modes behind "corrupt patch at line N":
 *  1. Blank context lines emitted as truly empty lines (no leading space).
 *  2. `@@ -a,b +c,d @@` line counts that don't match the hunk body.
 *
 * It also synthesizes missing `---`/`+++` headers from `diff --git` and
 * drops `\ No newline at end of file` markers that confuse fuzzy fallbacks.
 */
export function sanitizePatch(rawPatch: string): string {
  const src = stripToDiff(rawPatch).split("\n");
  const out: string[] = [];

  // Pending hunk being collected (header recomputed on flush).
  let oldStart = 0;
  let newStart = 0;
  let section = "";
  let body: string[] | null = null;

  const flush = () => {
    if (body === null) return;
    let oldCount = 0;
    let newCount = 0;
    for (const l of body) {
      const c = l[0];
      if (c === "+") newCount++;
      else if (c === "-") oldCount++;
      else if (c === "\\") {
        /* "\ No newline" — no count */
      } else {
        oldCount++;
        newCount++;
      }
    }
    const oS = oldCount === 0 ? Math.max(oldStart, 0) : oldStart || 1;
    const nS = newCount === 0 ? Math.max(newStart, 0) : newStart || 1;
    out.push(`@@ -${oS},${oldCount} +${nS},${newCount} @@${section}`);
    out.push(...body);
    body = null;
  };

  // Track diff --git path so we can synthesize missing ---/+++ headers.
  let pendingGitA: string | null = null;
  let pendingGitB: string | null = null;
  let sawMinus = false;
  let sawPlus = false;

  const emitSynthHeadersIfNeeded = () => {
    if (pendingGitA && pendingGitB && !sawMinus && !sawPlus) {
      out.push(`--- ${pendingGitA}`);
      out.push(`+++ ${pendingGitB}`);
    }
    pendingGitA = pendingGitB = null;
    sawMinus = sawPlus = false;
  };

  for (let i = 0; i < src.length; i++) {
    const line = src[i];

    if (isFileHeaderLine(line)) {
      // A new file-level header ends any open hunk.
      if (body !== null) flush();

      const gitMatch = line.match(/^diff --git (\S+) (\S+)/);
      if (gitMatch) {
        emitSynthHeadersIfNeeded();
        pendingGitA = gitMatch[1];
        pendingGitB = gitMatch[2];
        sawMinus = sawPlus = false;
        out.push(line);
        continue;
      }
      if (line.startsWith("--- ")) sawMinus = true;
      if (line.startsWith("+++ ")) sawPlus = true;
      out.push(line);
      continue;
    }

    const hunk = line.match(HUNK_HEADER_RE);
    if (hunk) {
      if (body !== null) flush();
      emitSynthHeadersIfNeeded();
      oldStart = parseInt(hunk[1], 10);
      newStart = parseInt(hunk[3], 10);
      section = hunk[5] ?? "";
      body = [];
      continue;
    }

    if (body !== null) {
      const c = line[0];
      if (c === "+" || c === "-" || c === " " || c === "\\") {
        if (c === "\\") continue; // drop "\ No newline at end of file"
        body.push(line);
      } else if (line.length === 0) {
        // The classic corruption: a blank context line with no leading space.
        body.push(" ");
      } else {
        // Stray line inside a hunk (LLM prose / unprefixed code).
        // Best-effort: treat as context so --recount + fuzzy fallback can cope.
        body.push(` ${line}`);
      }
      continue;
    }

    // Outside any hunk and not a recognized header — skip noise.
  }

  if (body !== null) flush();
  emitSynthHeadersIfNeeded();

  const result = out.join("\n");
  return result.endsWith("\n") ? result : `${result}\n`;
}

/** Strip a leading `a/` or `b/` prefix (git's default `-p1` convention). */
export function stripAB(p: string): string {
  return p.replace(/^[ab]\//, "");
}

/**
 * Collect the file path(s) a patch targets, taking the post-image (`+++`/
 * `diff --git` b-side) and ignoring `/dev/null`. Deduplicated, prefix-stripped.
 */
export function extractPatchPaths(patch: string): string[] {
  const paths: string[] = [];
  for (const line of patch.split("\n")) {
    let p: string | null = null;
    if (line.startsWith("+++ ")) {
      p = line.slice(4).split("\t")[0].trim();
    } else if (line.startsWith("--- ")) {
      p = line.slice(4).split("\t")[0].trim();
    } else {
      const g = line.match(/^diff --git \S+ (\S+)/);
      if (g) p = g[1];
    }
    if (!p || p === "/dev/null") continue;
    const clean = stripAB(p);
    if (clean && !paths.includes(clean)) paths.push(clean);
  }
  return paths;
}

/** True when the patch touches exactly one file. */
export function isSingleFilePatch(patch: string): boolean {
  const headers = patch
    .split("\n")
    .filter((l) => l.startsWith("diff --git ") || l.startsWith("+++ "));
  if (headers.length === 0) return extractPatchPaths(patch).length === 1;
  return extractPatchPaths(patch).length <= 1;
}

/**
 * Rewrite every file-header path in a single-file patch to `realRel`, keeping
 * `/dev/null` (new-file) markers intact. Fixes patches where the LLM used a
 * bare/incorrect path (e.g. `auth_test.py`) instead of the real repo-relative
 * path the finding points at.
 */
export function retargetSingleFilePatch(patch: string, realRel: string): string {
  const rel = stripAB(realRel);
  return patch
    .split("\n")
    .map((line) => {
      const g = line.match(/^diff --git \S+ \S+(.*)$/);
      if (g) return `diff --git a/${rel} b/${rel}${g[1] ?? ""}`;
      if (line.startsWith("--- ")) {
        const p = line.slice(4).split("\t")[0].trim();
        return p === "/dev/null" ? line : `--- a/${rel}`;
      }
      if (line.startsWith("+++ ")) {
        const p = line.slice(4).split("\t")[0].trim();
        return p === "/dev/null" ? line : `+++ b/${rel}`;
      }
      return line;
    })
    .join("\n");
}
