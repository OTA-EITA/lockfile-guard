// GitHub Action entry point. Inputs arrive as INPUT_* environment variables;
// outputs, annotations and the job summary use the files GitHub provides.
import { appendFileSync, writeFileSync } from "node:fs";
import { HttpRegistry } from "./registry-http.js";
import { render } from "./report.js";
import { rules } from "./rules/index.js";
import { scan } from "./scan.js";
import { severityRank } from "./types.js";
import type { Severity } from "./types.js";

declare const __VERSION__: string | undefined;
const version = typeof __VERSION__ === "string" ? __VERSION__ : "dev";

function input(name: string, fallback: string): string {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return v === undefined || v.trim() === "" ? fallback : v.trim();
}

// https://docs.github.com/actions/reference/workflow-commands-for-github-actions
const escapeData = (s: string) => s.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
const escapeProperty = (s: string) => escapeData(s).replaceAll(":", "%3A").replaceAll(",", "%2C");

async function run(): Promise<void> {
  const failOn = input("fail-on", "high");
  const sarifFile = input("sarif-file", "lockfile-guard.sarif");
  const registry = (process.env.npm_config_registry ?? "https://registry.npmjs.org").replace(/\/*$/, "/");
  const token = process.env.NPM_TOKEN;
  const result = await scan(input("path", ".").split(/\s+/), process.cwd(), {
    registries: [registry],
    allowScripts: input("allow-scripts", "")
      .split(/[\s,]+/)
      .filter(Boolean),
    registry:
      input("offline", "false") === "true"
        ? null
        : new HttpRegistry(token ? { url: registry, token } : { url: registry }),
    minAgeDays: Number(input("min-age", "7")),
    now: new Date(),
    concurrency: 8,
  });

  const opts = { files: result.files, rules, version };
  writeFileSync(sarifFile, render(result.findings, "sarif", opts));
  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) appendFileSync(summary, render(result.findings, "markdown", opts));
  const output = process.env.GITHUB_OUTPUT;
  if (output) appendFileSync(output, `sarif-file=${sarifFile}\nfindings=${String(result.findings.length)}\n`);
  for (const f of result.findings) {
    const level = f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "notice";
    process.stdout.write(
      `::${level} file=${escapeProperty(f.file)},line=${String(f.line)},title=${f.ruleId}::${escapeData(f.message)}\n`,
    );
  }
  if (
    failOn !== "none" &&
    result.findings.some((f) => severityRank[f.severity] >= severityRank[failOn as Severity])
  ) {
    process.exitCode = 1;
  }
}

run().catch((err: unknown) => {
  process.stdout.write(`::error::${escapeData(String(err))}\n`);
  process.exitCode = 1;
});
