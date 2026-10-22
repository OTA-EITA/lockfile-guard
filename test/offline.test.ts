import { describe, expect, it } from "vitest";
import { parseLockfile } from "../src/lockfile.js";
import { checkOffline } from "../src/rules/offline.js";
import { readFixture } from "./helpers.js";

const lock = parseLockfile("package-lock.json", readFixture("risky"));
const registries = ["https://registry.npmjs.org/"];

function ids(allowScripts: string[] = []) {
  return checkOffline(lock, { registries, allowScripts }).map((f) => `${f.ruleId} ${f.package}`);
}

describe("checkOffline", () => {
  it("reports install scripts, untrusted sources, plain HTTP and missing integrity", () => {
    expect(ids().sort()).toEqual(
      [
        "LG001 esbuild@0.28.2",
        "LG001 postinstall-thing@2.0.0",
        "LG001 fresh-dep@1.0.1",
        "LG002 from-git@1.2.3",
        "LG003 plain-http@1.0.0",
        "LG004 no-integrity@3.1.0",
      ].sort(),
    );
  });

  it("skips install scripts of allowed packages", () => {
    expect(ids(["esbuild", "fresh-dep"]).filter((s) => s.startsWith("LG001"))).toEqual([
      "LG001 postinstall-thing@2.0.0",
    ]);
  });

  it("accepts any tarball under an allowed registry prefix", () => {
    const all = checkOffline(lock, {
      registries: ["https://registry.npmjs.org/", "git+ssh://git@github.com/someone/"],
      allowScripts: [],
    });
    expect(all.map((f) => f.ruleId)).not.toContain("LG002");
  });

  it("flags tarballs from a host that only shares a prefix with the registry", () => {
    const evil = parseLockfile(
      "x",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/a": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org.evil.example/a/-/a-1.0.0.tgz",
            integrity: "sha512-x",
          },
        },
      }),
    );
    expect(checkOffline(evil, { registries, allowScripts: [] }).map((f) => f.ruleId)).toEqual(["LG002"]);
  });

  it("points findings at the lockfile line of the package", () => {
    const f = checkOffline(lock, { registries, allowScripts: [] }).find((x) => x.ruleId === "LG003");
    expect(f).toMatchObject({ file: "package-lock.json", severity: "high" });
    expect(readFixture("risky").split("\n")[(f?.line ?? 0) - 1]).toContain('"node_modules/plain-http"');
  });
});
