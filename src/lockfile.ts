/** One installed package from package-lock.json (lockfile v2/v3 "packages"). */
export interface LockedPackage {
  /** Key in "packages", e.g. node_modules/a/node_modules/@scope/b. */
  path: string;
  /** Registry name; differs from the folder name for npm: aliases. */
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  dev: boolean;
  optional: boolean;
  hasInstallScript: boolean;
  /** Workspace links have no tarball. */
  link: boolean;
  /** 1-based line of the entry in the lockfile, for annotations. */
  line: number;
}

export interface Lockfile {
  file: string;
  lockfileVersion: number;
  packages: LockedPackage[];
}

function folderName(path: string): string {
  const i = path.lastIndexOf("node_modules/");
  return i < 0 ? path : path.slice(i + "node_modules/".length);
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/** Parses package-lock.json or npm-shrinkwrap.json. Lockfile v1 (npm 6) is rejected. */
export function parseLockfile(file: string, source: string): Lockfile {
  let raw: unknown;
  try {
    raw = JSON.parse(source);
  } catch (err) {
    throw new Error(`${file}: invalid JSON: ${(err as Error).message}`);
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new Error(`${file}: not a lockfile`);
  const doc = raw as Record<string, unknown>;
  const version = typeof doc.lockfileVersion === "number" ? doc.lockfileVersion : 0;
  if (version < 2 || typeof doc.packages !== "object" || doc.packages === null) {
    throw new Error(`${file}: lockfileVersion ${String(version)} is not supported; regenerate it with npm 7 or later`);
  }

  // Precompute line numbers of every "packages" key.
  const lineOf = new Map<string, number>();
  source.split("\n").forEach((line, i) => {
    const m = /^\s*"(node_modules\/[^"]+)":\s*\{/.exec(line);
    if (m?.[1] && !lineOf.has(m[1])) lineOf.set(m[1], i + 1);
  });

  const packages: LockedPackage[] = [];
  for (const [path, value] of Object.entries(doc.packages as Record<string, unknown>)) {
    if (path === "" || !path.includes("node_modules/")) continue; // the root project and workspace sources
    if (typeof value !== "object" || value === null) continue;
    const p = value as Record<string, unknown>;
    const pkg: LockedPackage = {
      path,
      name: str(p.name) ?? folderName(path),
      version: str(p.version) ?? "",
      dev: p.dev === true,
      optional: p.optional === true || p.devOptional === true,
      hasInstallScript: p.hasInstallScript === true,
      link: p.link === true,
      line: lineOf.get(path) ?? 1,
    };
    const resolved = str(p.resolved);
    const integrity = str(p.integrity);
    if (resolved !== undefined) pkg.resolved = resolved;
    if (integrity !== undefined) pkg.integrity = integrity;
    packages.push(pkg);
  }
  return { file, lockfileVersion: version, packages };
}
