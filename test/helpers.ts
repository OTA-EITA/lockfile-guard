import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Packument, Registry } from "../src/registry.js";

export const fixture = (name: string): string =>
  fileURLToPath(new URL(`./fixtures/${name}/package-lock.json`, import.meta.url));

export const readFixture = (name: string): string => readFileSync(fixture(name), "utf8");

export const NOW = new Date("2026-10-20T00:00:00Z");

/** In-memory registry: published a long time ago unless listed in `fresh`. */
export class FakeRegistry implements Registry {
  readonly requested: string[] = [];

  constructor(
    private readonly docs: Record<string, Packument | null> = {
      "fresh-dep": { time: { "1.0.1": "2026-10-19T12:00:00Z" }, versions: { "1.0.1": {} } },
      "old-dep": {
        time: { "0.9.0": "2019-01-01T00:00:00Z" },
        versions: { "0.9.0": { deprecated: "use new-dep instead" } },
      },
      "no-integrity": { time: { "3.1.0": "2026-10-15T00:00:00Z" }, versions: { "3.1.0": {} } },
    },
  ) {}

  packument(name: string): Promise<Packument | null> {
    this.requested.push(name);
    if (name in this.docs) return Promise.resolve(this.docs[name] ?? null);
    return Promise.resolve({ time: {}, versions: {} });
  }
}
