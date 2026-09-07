// CrackScope Part 2 — code intake.
// Normalizes every intake channel (paste, files, folders, zip archives,
// GitHub repos) into the ScanInput[] the scanner engine consumes.
import { unzipSync, strFromU8 } from "fflate";
import type { ScanInput } from "@/lib/scanner";

export const MAX_FILES = 40;
export const MAX_FILE_BYTES = 200 * 1024; // 200 KB per source file

const SCANNABLE_EXT = new Set([
  "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "rb", "go", "java", "php",
  "cs", "cpp", "cc", "c", "h", "hpp", "rs", "kt", "swift", "sql", "yml",
  "yaml", "env", "ini", "toml", "sh", "bash", "html", "vue", "svelte",
  "properties", "conf", "json",
]);

const SKIP_DIR_PARTS = [
  "node_modules/", "vendor/", "dist/", "build/", ".min.", "__tests__",
  "__pycache__/", ".git/", "coverage/", "target/release",
];

export function extOf(name: string): string {
  return name.split(".").pop()?.toLowerCase() ?? "";
}

export function isScannableFile(name: string, size?: number): boolean {
  if (size !== undefined && size > MAX_FILE_BYTES) return false;
  if (!SCANNABLE_EXT.has(extOf(name))) return false;
  if (name.includes(".min.")) return false;
  const lower = `/${name.replace(/\\/g, "/").toLowerCase()}`;
  return !SKIP_DIR_PARTS.some((p) => lower.includes(p));
}

function looksBinary(text: string): boolean {
  if (text.includes("\u0000")) return true;
  // Heuristic: high ratio of control characters in the first slice.
  const slice = text.slice(0, 2000);
  let ctrl = 0;
  for (let i = 0; i < slice.length; i++) {
    const c = slice.charCodeAt(i);
    if (c < 9 || (c > 13 && c < 32)) ctrl++;
  }
  return slice.length > 0 && ctrl / slice.length > 0.1;
}

/** Decode a File (from <input> or drag-and-drop) into a ScanInput, or null if unsuitable. */
export async function fileToInput(file: File): Promise<ScanInput | null> {
  const name = (file as { webkitRelativePath?: string }).webkitRelativePath || file.name;
  if (!isScannableFile(name, file.size)) return null;
  const text = await file.text();
  if (looksBinary(text)) return null;
  return { name, content: text };
}

/** Extract scannable text files from a .zip archive. */
export async function zipToInputs(file: File): Promise<ScanInput[]> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const entries = unzipSync(bytes);
  const inputs: ScanInput[] = [];
  for (const [path, data] of Object.entries(entries)) {
    if (path.endsWith("/")) continue;
    if (!isScannableFile(path, data.length)) continue;
    const text = strFromU8(data);
    if (looksBinary(text)) continue;
    inputs.push({ name: path, content: text });
    if (inputs.length >= MAX_FILES) break;
  }
  return inputs;
}

/** Handle any dropped/uploaded file: zips get unpacked, sources pass through. */
export async function intakeFiles(fileList: File[]): Promise<ScanInput[]> {
  const out: ScanInput[] = [];
  for (const file of fileList) {
    if (extOf(file.name) === "zip") {
      out.push(...(await zipToInputs(file)));
    } else {
      const input = await fileToInput(file);
      if (input) out.push(input);
    }
  }
  return out.slice(0, MAX_FILES);
}

// ---------- GitHub intake ----------

export interface GithubTarget {
  owner: string;
  repo: string;
  branch?: string;
}

/** Accepts full URLs, `owner/repo`, or `owner/repo/tree/branch`. */
export function parseGithubTarget(input: string): GithubTarget | null {
  const raw = input.trim().replace(/^git@github\.com:/, "https://github.com/").replace(/\.git$/, "");
  const m = raw.match(/github\.com\/([^/\s]+)\/([^/\s?#]+)(?:\/tree\/([^/\s?#]+))?/i);
  if (m) return { owner: m[1], repo: m[2], branch: m[3] };
  const short = raw.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (short) return { owner: short[1], repo: short[2] };
  return null;
}

async function ghJson(url: string): Promise<unknown> {
  const res = await fetch(url, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (res.status === 403 || res.status === 429) {
    throw new Error("GitHub rate limit reached (unauthenticated). Try again in an hour or paste the files directly.");
  }
  if (res.status === 404) {
    throw new Error("GitHub repo not found — check the URL (private repos need to be public for now).");
  }
  if (!res.ok) throw new Error(`GitHub request failed (${res.status})`);
  return res.json();
}

/**
 * Fetch a public GitHub repo and return its scannable source files.
 * Uses the tree API (1 request) + raw.githubusercontent.com for contents
 * (no API rate limit) with a hard file cap for Part 2.
 */
export async function fetchGithubRepo(target: GithubTarget): Promise<ScanInput[]> {
  const { owner, repo } = target;
  let branch = target.branch;
  if (!branch) {
    const info = (await ghJson(`https://api.github.com/repos/${owner}/${repo}`)) as {
      default_branch?: string;
    };
    branch = info.default_branch || "main";
  }

  const tree = (await ghJson(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
  )) as { tree?: Array<{ path: string; type: string; size?: number }> };

  const candidates = (tree.tree ?? [])
    .filter((e) => e.type === "blob" && isScannableFile(e.path, e.size))
    .slice(0, MAX_FILES * 3);

  const inputs: ScanInput[] = [];
  const base = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/`;
  for (const entry of candidates) {
    if (inputs.length >= MAX_FILES) break;
    try {
      const res = await fetch(base + entry.path.split("/").map(encodeURIComponent).join("/"));
      if (!res.ok) continue;
      const text = await res.text();
      if (looksBinary(text)) continue;
      inputs.push({ name: entry.path, content: text });
    } catch {
      // Skip unreachable blobs; report what we gathered.
    }
  }
  if (inputs.length === 0) {
    throw new Error("No scannable source files found in that repo.");
  }
  return inputs;
}

/** Summary line helper: "6 files · 3 languages · 1,240 lines". */
export function summarizeInputs(inputs: ScanInput[]): string {
  const langs = new Set<string>();
  let lines = 0;
  for (const f of inputs) {
    lines += f.content.split("\n").length;
    const ext = extOf(f.name);
    const langMap: Record<string, string> = {
      ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript",
      mjs: "JavaScript", cjs: "JavaScript", py: "Python", rb: "Ruby", go: "Go",
      java: "Java", php: "PHP", cs: "C#", cpp: "C++", c: "C", rs: "Rust",
    };
    if (langMap[ext]) langs.add(langMap[ext]);
  }
  return `${inputs.length} file${inputs.length === 1 ? "" : "s"} · ${langs.size || 0} language${langs.size === 1 ? "" : "s"} · ${lines.toLocaleString()} lines`;
}
