import type { Lockfile } from "../lockfile.js";
import type { Registry } from "../registry.js";
import type { Finding, Rule } from "../types.js";
import { severityRank } from "../types.js";
import { checkOffline } from "./offline.js";
import type { OfflineOptions } from "./offline.js";
import { checkOnline } from "./online.js";
import type { OnlineOptions } from "./online.js";
import { checkTyposquat } from "./typosquat.js";

export const rules: Rule[] = [
  {
    id: "LG001",
    severity: "medium",
    online: false,
    title: "Install script",
    description: "The package runs a preinstall, install or postinstall script.",
  },
  {
    id: "LG002",
    severity: "high",
    online: false,
    title: "Untrusted source",
    description: "The tarball comes from a git URL or a host outside the allowed registries.",
  },
  {
    id: "LG003",
    severity: "high",
    online: false,
    title: "Plain HTTP",
    description: "The tarball is downloaded without TLS.",
  },
  {
    id: "LG004",
    severity: "medium",
    online: false,
    title: "Missing integrity",
    description: "No integrity hash, so a tampered tarball is not detected.",
  },
  {
    id: "LG005",
    severity: "medium",
    online: true,
    title: "Freshly published",
    description: "The version is younger than the cooldown period; high when it also runs an install script.",
  },
  {
    id: "LG006",
    severity: "medium",
    online: false,
    title: "Possible typosquat",
    description: "The name is one edit away from, or a separator variant of, a popular package.",
  },
  {
    id: "LG007",
    severity: "low",
    online: true,
    title: "Deprecated",
    description: "The maintainers deprecated this version.",
  },
];

export interface AnalyzeOptions extends OfflineOptions, OnlineOptions {
  /** null runs only the offline rules. */
  registry: Registry | null;
}

export async function analyze(lock: Lockfile, opt: AnalyzeOptions): Promise<Finding[]> {
  const findings = [...checkOffline(lock, opt), ...checkTyposquat(lock)];
  if (opt.registry) findings.push(...(await checkOnline(lock, opt.registry, opt)));
  return findings.sort(
    (a, b) =>
      severityRank[b.severity] - severityRank[a.severity] ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId),
  );
}
