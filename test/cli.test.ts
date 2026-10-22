import { mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { isEntryPoint, main } from "../src/cli.js";
import { FakeRegistry, NOW, fixture } from "./helpers.js";

const root = fileURLToPath(new URL("..", import.meta.url));

async function run(args: string[], env: Record<string, string | undefined> = {}) {
  let stdout = "";
  let stderr = "";
  const registries: [string, string | undefined][] = [];
  const code = await main(args, {
    stdout: (s) => (stdout += s),
    stderr: (s) => (stderr += s),
    cwd: root,
    env,
    now: () => NOW,
    registry: (url, token) => {
      registries.push([url, token]);
      return new FakeRegistry();
    },
  });
  return { code, stdout, stderr, registries };
}

describe("main", () => {
  it("fails on the risky lockfile and reports relative paths", async () => {
    const r = await run([fixture("risky")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("test/fixtures/risky/package-lock.json:");
    expect(r.stdout).toContain("LG005");
    expect(r.stdout).toMatch(/1 lockfile\(s\), \d+ finding\(s\)/);
  });

  it("passes the clean lockfile", async () => {
    const r = await run([fixture("clean")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("No problems found.");
  });

  it("--offline does not build a registry client", async () => {
    const r = await run(["--offline", fixture("risky")]);
    expect(r.registries).toEqual([]);
    expect(r.stdout).not.toContain("LG005");
  });

  it("uses npm_config_registry and NPM_TOKEN, normalising the trailing slash", async () => {
    const r = await run([fixture("clean")], {
      npm_config_registry: "https://npm.example.com",
      NPM_TOKEN: "t",
    });
    expect(r.registries).toEqual([["https://npm.example.com/", "t"]]);
    // every tarball in the fixture now comes from outside the allowed registry
    expect(r.stdout).toContain("LG002");
  });

  it("--fail-on decides the exit code", async () => {
    expect((await run(["--offline", "--fail-on", "none", fixture("risky")])).code).toBe(0);
    expect((await run(["--offline", "--fail-on", "high", fixture("risky")])).code).toBe(1);
  });

  it("--allow-scripts accepts repeats and comma lists", async () => {
    const r = await run([
      "--offline",
      "--format",
      "json",
      "--allow-scripts",
      "esbuild, postinstall-thing",
      "--allow-scripts",
      "fresh-dep",
      fixture("risky"),
    ]);
    const out = JSON.parse(r.stdout) as { findings: { ruleId: string }[] };
    expect(out.findings.map((f) => f.ruleId)).not.toContain("LG001");
  });

  it("searches directories and skips fixture folders", async () => {
    const r = await run(["--offline", path.join(root, "test")]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("no package-lock.json");
  });

  it("prints help, version and rules", async () => {
    expect((await run(["-h"])).stdout).toContain("usage: lockfile-guard");
    expect((await run(["--version"])).stdout).toBe("lockfile-guard dev\n");
    const rules = await run(["--list-rules"]);
    expect(rules.stdout).toContain("LG005  medium  Freshly published (registry)");
    expect(rules.stdout.trim().split("\n")).toHaveLength(7);
  });

  it.each([
    [["--bogus"], /Unknown option/],
    [["--format", "xml"], /unknown format "xml"/],
    [["--fail-on", "critical"], /--fail-on must be/],
    [["--min-age=-1"], /--min-age must be/],
    [["--min-age", "abc"], /--min-age must be/],
    [["/does/not/exist"], /ENOENT/],
  ])("rejects %j", async (args, msg) => {
    const r = await run(args);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(msg);
  });
});

describe("isEntryPoint", () => {
  const self = new URL("../src/cli.ts", import.meta.url).href;

  it("matches the module itself and a symlink to it", () => {
    const file = fileURLToPath(self);
    const link = path.join(mkdtempSync(path.join(tmpdir(), "lg-")), "lockfile-guard");
    symlinkSync(file, link);
    expect(isEntryPoint(file, self)).toBe(true);
    expect(isEntryPoint(link, self)).toBe(true);
  });

  it("rejects other files and missing paths", () => {
    expect(isEntryPoint(undefined, self)).toBe(false);
    expect(isEntryPoint(fileURLToPath(import.meta.url), self)).toBe(false);
    expect(isEntryPoint("/no/such/file", pathToFileURL("/no/such/file").href)).toBe(false);
  });
});
