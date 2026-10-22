import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { parseLockfile } from "./lockfile.js";
import { analyze } from "./rules/index.js";
import type { AnalyzeOptions } from "./rules/index.js";
import type { Finding } from "./types.js";

const lockfileNames = new Set(["package-lock.json", "npm-shrinkwrap.json"]);
const skipDirs = new Set(["node_modules", ".git", "dist", "testdata", "fixtures"]);

/** Finds lockfiles: a file path as is, or every lockfile below a directory. */
export async function findLockfiles(root: string): Promise<string[]> {
  if ((await stat(root)).isFile()) return [root];
  const out: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!skipDirs.has(e.name)) await walk(path.join(dir, e.name));
      } else if (lockfileNames.has(e.name)) {
        out.push(path.join(dir, e.name));
      }
    }
  };
  await walk(root);
  return out;
}

export interface ScanResult {
  findings: Finding[];
  files: number;
  packages: number;
}

export async function scan(paths: string[], cwd: string, opt: AnalyzeOptions): Promise<ScanResult> {
  const result: ScanResult = { findings: [], files: 0, packages: 0 };
  for (const p of paths) {
    for (const file of await findLockfiles(p)) {
      const rel = path.relative(cwd, file).split(path.sep).join("/") || file;
      const lock = parseLockfile(rel, await readFile(file, "utf8"));
      result.files++;
      result.packages += lock.packages.length;
      result.findings.push(...(await analyze(lock, opt)));
    }
  }
  return result;
}
