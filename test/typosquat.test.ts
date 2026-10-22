import { describe, expect, it } from "vitest";
import { parseLockfile } from "../src/lockfile.js";
import { checkTyposquat, editDistance, imitates } from "../src/rules/typosquat.js";
import { readFixture } from "./helpers.js";

describe("editDistance", () => {
  it.each([
    ["", "", 0],
    ["abc", "", 3],
    ["", "abc", 3],
    ["lodash", "lodash", 0],
    ["lodash", "lodahs", 1], // adjacent swap counts once
    ["express", "expresss", 1],
    ["react", "raect", 1],
    ["kitten", "sitting", 3],
  ])("%s -> %s = %i", (a, b, want) => {
    expect(editDistance(a, b)).toBe(want);
  });
});

describe("imitates", () => {
  it("finds one-edit neighbours of popular names", () => {
    expect(imitates("expresss")).toBe("express");
    expect(imitates("lodahs")).toBe("lodash");
  });

  it("finds separator variants", () => {
    expect(imitates("cross_env")).toBe("cross-env");
    expect(imitates("crossenv")).toBe("cross-env");
  });

  it("does not flag the popular packages themselves or unrelated names", () => {
    expect(imitates("express")).toBeUndefined();
    expect(imitates("cross-env")).toBeUndefined();
    expect(imitates("my-company-utils")).toBeUndefined();
  });

  it("ignores one-letter neighbours of short names", () => {
    expect(imitates("reac")).toBeUndefined(); // 4 letters, one edit from react
  });
});

describe("checkTyposquat", () => {
  it("reports each suspicious name once", () => {
    const lock = parseLockfile("package-lock.json", readFixture("risky"));
    const found = checkTyposquat(lock);
    expect(found.map((f) => f.package).sort()).toEqual(["cross_env@7.0.3", "expresss@4.0.0"]);
    expect(found[0]).toMatchObject({ ruleId: "LG006", severity: "medium" });
  });
});
