import type { Lockfile } from "../lockfile.js";
import type { Packument, Registry } from "../registry.js";
import type { Finding } from "../types.js";

export interface OnlineOptions {
  /** Versions younger than this are reported (supply-chain "cooldown"). */
  minAgeDays: number;
  now: Date;
  /** Parallel registry requests. */
  concurrency: number;
}

/** Runs fn over items with at most `limit` promises in flight. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

const day = 24 * 60 * 60 * 1000;

export async function checkOnline(lock: Lockfile, registry: Registry, opt: OnlineOptions): Promise<Finding[]> {
  const installable = lock.packages.filter((p) => !p.link && p.resolved !== undefined && p.version !== "");
  const names = [...new Set(installable.map((p) => p.name))];
  const docs = new Map<string, Packument | null>();
  await mapLimit(names, opt.concurrency, async (name) => {
    docs.set(name, await registry.packument(name));
  });

  const out: Finding[] = [];
  for (const p of installable) {
    const doc = docs.get(p.name);
    const pkg = `${p.name}@${p.version}`;
    const base = { package: pkg, file: lock.file, line: p.line };
    if (!doc) continue; // private or missing packages are covered by LG002

    const published = doc.time[p.version];
    if (published !== undefined) {
      const ageDays = (opt.now.getTime() - Date.parse(published)) / day;
      if (ageDays < opt.minAgeDays) {
        // A brand-new version that also runs code on install is how npm worms spread.
        const severity = p.hasInstallScript ? "high" : "medium";
        out.push({
          ...base,
          ruleId: "LG005",
          severity,
          message: `${pkg} was published ${ageDays < 1 ? "less than a day" : `${String(Math.floor(ageDays))} day(s)`} ago${p.hasInstallScript ? " and runs an install script" : ""}`,
          help: `Most hijacked releases are found and pulled within days. Pin the previous version until it is ${String(opt.minAgeDays)} days old.`,
        });
      }
    }

    const deprecated = doc.versions[p.version]?.deprecated;
    if (deprecated) {
      out.push({
        ...base,
        ruleId: "LG007",
        severity: "low",
        message: `${pkg} is deprecated: ${deprecated}`,
        help: "Move to the replacement the maintainers recommend.",
      });
    }
  }
  return out;
}
