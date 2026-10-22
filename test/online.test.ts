import { describe, expect, it } from "vitest";
import { parseLockfile } from "../src/lockfile.js";
import { analyze } from "../src/rules/index.js";
import { checkOnline, mapLimit } from "../src/rules/online.js";
import { severityRank } from "../src/types.js";
import { FakeRegistry, NOW, readFixture } from "./helpers.js";

const lock = parseLockfile("package-lock.json", readFixture("risky"));
const opt = { minAgeDays: 7, now: NOW, concurrency: 4 };

describe("checkOnline", () => {
  it("reports fresh versions, high when they also run an install script", async () => {
    const found = await checkOnline(lock, new FakeRegistry(), opt);
    const fresh = found.filter((f) => f.ruleId === "LG005");
    expect(fresh.map((f) => [f.package, f.severity])).toEqual([
      ["no-integrity@3.1.0", "medium"],
      ["fresh-dep@1.0.1", "high"],
    ]);
    expect(fresh[0]?.message).toContain("published 5 day(s) ago");
    expect(fresh[1]?.message).toContain("less than a day ago and runs an install script");
  });

  it("reports deprecated versions with the maintainers' message", async () => {
    const found = await checkOnline(lock, new FakeRegistry(), opt);
    expect(found.find((f) => f.ruleId === "LG007")).toMatchObject({
      package: "old-dep@0.9.0",
      severity: "low",
      message: "old-dep@0.9.0 is deprecated: use new-dep instead",
    });
  });

  it("respects the cooldown period", async () => {
    const found = await checkOnline(lock, new FakeRegistry(), { ...opt, minAgeDays: 1 });
    expect(found.filter((f) => f.ruleId === "LG005").map((f) => f.package)).toEqual(["fresh-dep@1.0.1"]);
  });

  it("asks the registry once per name and skips links and bundled packages", async () => {
    const registry = new FakeRegistry();
    await checkOnline(lock, registry, opt);
    expect(new Set(registry.requested).size).toBe(registry.requested.length);
    expect(registry.requested).toContain("@scope/real-name");
    expect(registry.requested).not.toContain("local-pkg");
    expect(registry.requested).not.toContain("bundled-child");
  });

  it("skips packages the registry does not know", async () => {
    const found = await checkOnline(lock, new FakeRegistry({ "fresh-dep": null }), opt);
    expect(found).toEqual([]);
  });
});

describe("mapLimit", () => {
  it("keeps order and never exceeds the limit", async () => {
    let running = 0;
    let peak = 0;
    const out = await mapLimit([5, 1, 4, 2, 3], 2, async (n) => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, n));
      running--;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 40, 20, 30]);
    expect(peak).toBe(2);
  });

  it("handles an empty list", async () => {
    expect(await mapLimit([], 3, () => Promise.resolve(1))).toEqual([]);
  });
});

describe("analyze", () => {
  it("sorts by severity, then line, then rule", async () => {
    const found = await analyze(lock, {
      registries: ["https://registry.npmjs.org/"],
      allowScripts: ["esbuild"],
      registry: new FakeRegistry(),
      ...opt,
    });
    const ranks = found.map((f) => severityRank[f.severity]);
    expect(ranks).toEqual([...ranks].sort((a, b) => b - a));
    expect(found[0]?.ruleId).toBe("LG002");
    expect(found.map((f) => f.ruleId)).toContain("LG007");
  });

  it("runs only offline rules without a registry", async () => {
    const found = await analyze(lock, {
      registries: ["https://registry.npmjs.org/"],
      allowScripts: [],
      registry: null,
      ...opt,
    });
    expect(found.map((f) => f.ruleId)).not.toContain("LG005");
    expect(found.map((f) => f.ruleId)).not.toContain("LG007");
  });
});
