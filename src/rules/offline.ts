import type { LockedPackage, Lockfile } from "../lockfile.js";
import type { Finding } from "../types.js";

export interface OfflineOptions {
  /** Registry URL prefixes tarballs may come from. */
  registries: string[];
  /** Packages allowed to run install scripts (e.g. esbuild, sharp). */
  allowScripts: string[];
}

function id(p: LockedPackage): string {
  return `${p.name}@${p.version}`;
}

function finding(lock: Lockfile, p: LockedPackage, f: Omit<Finding, "file" | "line" | "package">): Finding {
  return { ...f, file: lock.file, line: p.line, package: id(p) };
}

export function checkOffline(lock: Lockfile, opt: OfflineOptions): Finding[] {
  const out: Finding[] = [];
  for (const p of lock.packages) {
    if (p.link) continue;

    // LG001: preinstall/install/postinstall scripts run with the developer's
    // and CI's credentials; the 2025 npm worms spread exactly this way.
    if (p.hasInstallScript && !opt.allowScripts.includes(p.name)) {
      out.push(
        finding(lock, p, {
          ruleId: "LG001",
          severity: "medium",
          message: `${id(p)} runs an install script`,
          help: "Install with --ignore-scripts, or add it to --allow-scripts after reviewing what the script does.",
        }),
      );
    }

    // Bundled dependencies have neither resolved nor integrity; they ship inside their parent.
    if (p.resolved === undefined) continue;

    if (p.resolved.startsWith("http://")) {
      out.push(
        finding(lock, p, {
          ruleId: "LG003",
          severity: "high",
          message: `${id(p)} is downloaded over plain HTTP (${p.resolved})`,
          help: "Use an https:// registry so the tarball cannot be swapped in transit.",
        }),
      );
    } else if (!opt.registries.some((r) => p.resolved?.startsWith(r))) {
      out.push(
        finding(lock, p, {
          ruleId: "LG002",
          severity: "high",
          message: `${id(p)} comes from outside the allowed registries: ${p.resolved}`,
          help: "Git URLs and arbitrary tarballs bypass registry signatures and can change without notice. Publish it to your registry or add it to --registry.",
        }),
      );
    }

    if (p.integrity === undefined) {
      out.push(
        finding(lock, p, {
          ruleId: "LG004",
          severity: "medium",
          message: `${id(p)} has no integrity hash, so npm cannot detect a tampered tarball`,
          help: "Delete node_modules and the lockfile entry, then reinstall so npm records the sha512 integrity.",
        }),
      );
    }
  }
  return out;
}
