import type { Lockfile } from "../lockfile.js";
import type { Finding } from "../types.js";
import { popular } from "./popular.js";

const popularSet = new Set(popular);

/** Optimal string alignment distance: insertions, deletions, substitutions and adjacent swaps. */
export function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  const at = (i: number, j: number) => d[i]?.[j] ?? Number.POSITIVE_INFINITY;
  for (let i = 1; i <= a.length; i++) {
    const row = d[i] ?? [];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(at(i - 1, j) + 1, at(i, j - 1) + 1, at(i - 1, j - 1) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1])
        v = Math.min(v, at(i - 2, j - 2) + 1);
      row[j] = v;
    }
  }
  return at(a.length, b.length);
}

/** Separators npm treats as different but people read as the same. */
function normalise(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, "");
}

/** Returns the popular package a name imitates, or undefined. */
export function imitates(name: string): string | undefined {
  if (popularSet.has(name)) return undefined;
  const n = normalise(name);
  for (const p of popular) {
    if (normalise(p) === n) return p;
    // Short names have too many legitimate one-letter neighbours.
    if (name.length >= 5 && editDistance(name, p) === 1) return p;
  }
  return undefined;
}

export function checkTyposquat(lock: Lockfile): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const p of lock.packages) {
    if (p.link || seen.has(p.name)) continue;
    seen.add(p.name);
    const target = imitates(p.name);
    if (target === undefined) continue;
    out.push({
      ruleId: "LG006",
      severity: "medium",
      package: `${p.name}@${p.version}`,
      file: lock.file,
      line: p.line,
      message: `${p.name} looks like a typo of the popular package ${target}`,
      help: `Check that ${p.name} is really intended; typosquats imitate popular names to get installed by mistake.`,
    });
  }
  return out;
}
