import { describe, expect, it } from "vitest";
import { parseLockfile } from "../src/lockfile.js";
import { readFixture } from "./helpers.js";

describe("parseLockfile", () => {
  const lock = parseLockfile("package-lock.json", readFixture("risky"));
  const byPath = (p: string) => lock.packages.find((x) => x.path === p);

  it("reads installed packages and skips the root and workspace sources", () => {
    expect(lock.lockfileVersion).toBe(3);
    expect(lock.packages.map((p) => p.path)).not.toContain("");
    expect(lock.packages.map((p) => p.path)).not.toContain("packages/local-pkg");
    expect(lock.packages).toHaveLength(13);
  });

  it("takes the name from the folder, or from the name field for npm: aliases", () => {
    expect(byPath("node_modules/express/node_modules/fresh-dep")?.name).toBe("fresh-dep");
    expect(byPath("node_modules/aliased")?.name).toBe("@scope/real-name");
  });

  it("records flags, resolved, integrity and line numbers", () => {
    const esbuild = byPath("node_modules/esbuild");
    expect(esbuild).toMatchObject({ version: "0.28.2", dev: true, hasInstallScript: true, line: 12 });
    expect(esbuild?.integrity).toMatch(/^sha512-/);
    expect(byPath("node_modules/no-integrity")?.integrity).toBeUndefined();
    expect(byPath("node_modules/bundled-child")?.resolved).toBeUndefined();
    expect(byPath("node_modules/local-pkg")?.link).toBe(true);
  });

  it("rejects invalid JSON, non-objects and lockfile v1", () => {
    expect(() => parseLockfile("a.json", "{")).toThrow(/a.json: invalid JSON/);
    expect(() => parseLockfile("a.json", "[]")).toThrow(/not a lockfile/);
    expect(() => parseLockfile("a.json", JSON.stringify({ lockfileVersion: 1, dependencies: {} }))).toThrow(
      /lockfileVersion 1 is not supported/,
    );
  });

  it("ignores malformed entries and defaults missing fields", () => {
    const lock = parseLockfile(
      "x",
      JSON.stringify({
        lockfileVersion: 2,
        packages: { "node_modules/a": null, "node_modules/b": { version: 1 } },
      }),
    );
    expect(lock.packages).toEqual([
      {
        path: "node_modules/b",
        name: "b",
        version: "",
        dev: false,
        optional: false,
        hasInstallScript: false,
        link: false,
        line: 1,
      },
    ]);
  });
});
