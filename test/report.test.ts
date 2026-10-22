import { describe, expect, it } from "vitest";
import { render } from "../src/report.js";
import { rules } from "../src/rules/index.js";
import type { Finding } from "../src/types.js";

const findings: Finding[] = [
  {
    ruleId: "LG002",
    severity: "high",
    package: "from-git@1.2.3",
    file: "package-lock.json",
    line: 21,
    message: "from-git@1.2.3 comes from a|b",
    help: "Publish it",
  },
  {
    ruleId: "LG007",
    severity: "low",
    package: "old@1.0.0",
    file: "package-lock.json",
    line: 40,
    message: "old is deprecated",
  },
];
const opts = { files: 1, rules, version: "1.2.3" };

describe("render", () => {
  it("text lists findings and a summary", () => {
    const out = render(findings, "text", opts);
    expect(out).toContain("package-lock.json:21  HIGH   LG002  from-git@1.2.3 comes from a|b");
    expect(out).toContain("1 lockfile(s), 2 finding(s): 1 high, 0 medium, 1 low");
  });

  it("text says when nothing was found", () => {
    expect(render([], "text", opts)).toContain("No problems found.");
  });

  it("json carries findings and counts", () => {
    const out = JSON.parse(render(findings, "json", opts)) as { summary: unknown; findings: unknown[] };
    expect(out.summary).toEqual({ high: 1, medium: 0, low: 1 });
    expect(out.findings).toHaveLength(2);
  });

  it("markdown escapes pipes and picks the icon by severity", () => {
    const out = render(findings, "markdown", opts);
    expect(out).toContain("### 🛑 lockfile-guard");
    expect(out).toContain(
      "| high | LG002 | `from-git@1.2.3` | from-git@1.2.3 comes from a\\|b | Publish it |",
    );
    expect(out).toContain("| low | LG007 | `old@1.0.0` | old is deprecated |  |");
    expect(render(findings.slice(1), "markdown", opts)).toContain("### ⚠️ lockfile-guard");
    expect(render([], "markdown", opts)).toContain("### ✅ lockfile-guard");
  });

  it("sarif describes every rule and locates results", () => {
    const out = JSON.parse(render(findings, "sarif", opts)) as {
      version: string;
      runs: {
        tool: { driver: { version: string; rules: { id: string; properties: Record<string, unknown> }[] } };
        results: { ruleId: string; level: string; message: { text: string }; locations: unknown[] }[];
      }[];
    };
    const run = out.runs[0];
    expect(out.version).toBe("2.1.0");
    expect(run?.tool.driver.version).toBe("1.2.3");
    expect(run?.tool.driver.rules.map((r) => r.id)).toEqual(rules.map((r) => r.id));
    expect(run?.tool.driver.rules[1]?.properties["security-severity"]).toBe("8.0");
    expect(run?.results[0]).toMatchObject({
      ruleId: "LG002",
      level: "error",
      message: { text: "from-git@1.2.3 comes from a|b. Publish it" },
      locations: [
        { physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: 21 } } },
      ],
    });
    expect(run?.results[1]).toMatchObject({ level: "note", message: { text: "old is deprecated" } });
  });
});
