import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { Registry } from "./registry.js";
import { HttpRegistry } from "./registry-http.js";
import { formats, render } from "./report.js";
import type { Format } from "./report.js";
import { rules } from "./rules/index.js";
import { scan } from "./scan.js";
import { severityRank } from "./types.js";
import type { Severity } from "./types.js";

declare const __VERSION__: string | undefined;
const version = typeof __VERSION__ === "string" ? __VERSION__ : "dev";

const usage = `usage: lockfile-guard [options] [path ...]

Checks package-lock.json files for supply-chain risks. Paths default to the
current directory; directories are searched for lockfiles.

options:
  --offline              skip checks that query the registry (LG005, LG007)
  --min-age <days>       report versions published fewer than this many days ago (default: 7)
  --registry <url>       allowed registry; repeatable (default: $npm_config_registry or https://registry.npmjs.org)
  --allow-scripts <pkg>  package allowed to run install scripts; repeatable or comma separated
  --format <format>      text, json, markdown or sarif (default: text)
  --fail-on <severity>   exit 1 on findings at least this severe: high, medium, low or none (default: medium)
  --list-rules           print the rules and exit
  --version              print the version and exit
  -h, --help             show this help
`;

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  cwd: string;
  env: Record<string, string | undefined>;
  now: () => Date;
  /** Builds the registry client; replaced in tests. */
  registry: (url: string, token: string | undefined) => Registry;
}

export async function main(argv: string[], io: Io): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        offline: { type: "boolean", default: false },
        "min-age": { type: "string", default: "7" },
        registry: { type: "string", multiple: true, default: [] },
        "allow-scripts": { type: "string", multiple: true, default: [] },
        format: { type: "string", default: "text" },
        "fail-on": { type: "string", default: "medium" },
        "list-rules": { type: "boolean", default: false },
        version: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (err) {
    io.stderr(`error: ${(err as Error).message}\n\n${usage}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    io.stdout(usage);
    return 0;
  }
  if (values.version) {
    io.stdout(`lockfile-guard ${version}\n`);
    return 0;
  }
  if (values["list-rules"]) {
    io.stdout(
      rules
        .map(
          (r) =>
            `${r.id}  ${r.severity.padEnd(6)}  ${r.title}${r.online ? " (registry)" : ""}: ${r.description}`,
        )
        .join("\n") + "\n",
    );
    return 0;
  }
  if (!(formats as string[]).includes(values.format)) {
    io.stderr(`error: unknown format "${values.format}" (want ${formats.join(", ")})\n`);
    return 2;
  }
  const failOn = values["fail-on"];
  if (failOn !== "none" && !(failOn in severityRank)) {
    io.stderr(`error: --fail-on must be high, medium, low or none, got "${failOn}"\n`);
    return 2;
  }
  const minAge = Number(values["min-age"]);
  if (!Number.isFinite(minAge) || minAge < 0) {
    io.stderr(`error: --min-age must be a non-negative number of days\n`);
    return 2;
  }

  const registries = (
    values.registry.length ? values.registry : [io.env.npm_config_registry ?? "https://registry.npmjs.org"]
  ).map((r) => r.replace(/\/*$/, "/"));
  const primary = registries[0] ?? "https://registry.npmjs.org/";
  let result;
  try {
    result = await scan(positionals.length ? positionals : ["."], io.cwd, {
      registries,
      allowScripts: values["allow-scripts"]
        .flatMap((s) => s.split(","))
        .map((s) => s.trim())
        .filter(Boolean),
      registry: values.offline ? null : io.registry(primary, io.env.NPM_TOKEN),
      minAgeDays: minAge,
      now: io.now(),
      concurrency: 8,
    });
  } catch (err) {
    io.stderr(`error: ${(err as Error).message}\n`);
    return 2;
  }
  if (result.files === 0) {
    io.stderr("error: no package-lock.json or npm-shrinkwrap.json found\n");
    return 2;
  }
  io.stdout(render(result.findings, values.format as Format, { files: result.files, rules, version }));

  if (failOn === "none") return 0;
  const threshold = severityRank[failOn as Severity];
  return result.findings.some((f) => severityRank[f.severity] >= threshold) ? 1 : 0;
}

/** True when this module is the program being run, also through npm's bin symlink. */
export function isEntryPoint(argv1: string | undefined, moduleUrl: string): boolean {
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

if (isEntryPoint(process.argv[1], import.meta.url)) {
  main(process.argv.slice(2), {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
    cwd: process.cwd(),
    env: process.env,
    now: () => new Date(),
    registry: (url, token) => new HttpRegistry(token === undefined ? { url } : { url, token }),
  }).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`error: ${String(err)}\n`);
      process.exitCode = 2;
    },
  );
}
