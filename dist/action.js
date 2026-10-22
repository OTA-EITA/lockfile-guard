// src/action.ts
import { appendFileSync, writeFileSync } from "node:fs";

// src/registry-http.ts
var HttpRegistry = class {
  constructor(opt) {
    this.opt = opt;
    this.base = opt.url.replace(/\/+$/, "");
  }
  opt;
  base;
  async packument(name) {
    const url = `${this.base}/${name.startsWith("@") ? "@" + encodeURIComponent(name.slice(1)) : encodeURIComponent(name)}`;
    const headers = { accept: "application/json" };
    if (this.opt.token) headers.authorization = `Bearer ${this.opt.token}`;
    const retries = this.opt.retries ?? 2;
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(url, { headers, signal: AbortSignal.timeout(this.opt.timeoutMs ?? 3e4) });
      if (res.status === 404) return null;
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
        continue;
      }
      if (!res.ok) throw new Error(`GET ${url}: HTTP ${String(res.status)}`);
      const body = await res.json();
      return { time: body.time ?? {}, versions: body.versions ?? {} };
    }
  }
};

// src/report.ts
function counts(findings) {
  const c = { high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}
function summary(findings, files) {
  const c = counts(findings);
  return `${String(files)} lockfile(s), ${String(findings.length)} finding(s): ${String(c.high)} high, ${String(c.medium)} medium, ${String(c.low)} low`;
}
function render(findings, format, opts) {
  switch (format) {
    case "json":
      return JSON.stringify({ findings, summary: counts(findings) }, null, 2) + "\n";
    case "markdown":
      return markdown(findings, opts.files);
    case "sarif":
      return JSON.stringify(sarif(findings, opts.rules, opts.version), null, 2) + "\n";
    case "text":
      return text(findings, opts.files);
  }
}
function text(findings, files) {
  const lines = findings.map((f) => {
    return `${f.file}:${String(f.line)}  ${f.severity.toUpperCase().padEnd(6)} ${f.ruleId}  ${f.message}`;
  });
  return [...lines, lines.length ? "" : "No problems found.", summary(findings, files), ""].join("\n");
}
function markdown(findings, files) {
  const icon = findings.some((f) => f.severity === "high") ? "\u{1F6D1}" : findings.length ? "\u26A0\uFE0F" : "\u2705";
  const out = [`### ${icon} lockfile-guard`, "", summary(findings, files), ""];
  if (findings.length) {
    out.push("| Severity | Rule | Package | Problem | What to do |", "|---|---|---|---|---|");
    for (const f of findings) {
      const esc = (s) => (s ?? "").replaceAll("|", "\\|");
      out.push(`| ${f.severity} | ${f.ruleId} | \`${f.package}\` | ${esc(f.message)} | ${esc(f.help)} |`);
    }
  }
  return out.join("\n") + "\n";
}
var sarifLevel = { high: "error", medium: "warning", low: "note" };
var securitySeverity = { high: "8.0", medium: "5.0", low: "2.0" };
function sarif(findings, rules2, version2) {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "lockfile-guard",
            version: version2,
            informationUri: "https://github.com/OTA-EITA/lockfile-guard",
            rules: rules2.map((r) => ({
              id: r.id,
              name: r.title,
              shortDescription: { text: r.title },
              fullDescription: { text: r.description },
              defaultConfiguration: { level: sarifLevel[r.severity] },
              properties: {
                tags: ["security", "npm", "supply-chain"],
                "security-severity": securitySeverity[r.severity]
              }
            }))
          }
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel[f.severity],
          message: { text: f.help ? `${f.message}. ${f.help}` : f.message },
          locations: [
            { physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }
          ]
        }))
      }
    ]
  };
}

// src/types.ts
var severityRank = { high: 3, medium: 2, low: 1 };

// src/rules/offline.ts
function id(p) {
  return `${p.name}@${p.version}`;
}
function finding(lock, p, f) {
  return { ...f, file: lock.file, line: p.line, package: id(p) };
}
function checkOffline(lock, opt) {
  const out = [];
  for (const p of lock.packages) {
    if (p.link) continue;
    if (p.hasInstallScript && !opt.allowScripts.includes(p.name)) {
      out.push(
        finding(lock, p, {
          ruleId: "LG001",
          severity: "medium",
          message: `${id(p)} runs an install script`,
          help: "Install with --ignore-scripts, or add it to --allow-scripts after reviewing what the script does."
        })
      );
    }
    if (p.resolved === void 0) continue;
    if (p.resolved.startsWith("http://")) {
      out.push(
        finding(lock, p, {
          ruleId: "LG003",
          severity: "high",
          message: `${id(p)} is downloaded over plain HTTP (${p.resolved})`,
          help: "Use an https:// registry so the tarball cannot be swapped in transit."
        })
      );
    } else if (!opt.registries.some((r) => p.resolved?.startsWith(r))) {
      out.push(
        finding(lock, p, {
          ruleId: "LG002",
          severity: "high",
          message: `${id(p)} comes from outside the allowed registries: ${p.resolved}`,
          help: "Git URLs and arbitrary tarballs bypass registry signatures and can change without notice. Publish it to your registry or add it to --registry."
        })
      );
    }
    if (p.integrity === void 0) {
      out.push(
        finding(lock, p, {
          ruleId: "LG004",
          severity: "medium",
          message: `${id(p)} has no integrity hash, so npm cannot detect a tampered tarball`,
          help: "Delete node_modules and the lockfile entry, then reinstall so npm records the sha512 integrity."
        })
      );
    }
  }
  return out;
}

// src/rules/online.ts
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
var day = 24 * 60 * 60 * 1e3;
async function checkOnline(lock, registry, opt) {
  const installable = lock.packages.filter((p) => !p.link && p.resolved !== void 0 && p.version !== "");
  const names = [...new Set(installable.map((p) => p.name))];
  const docs = /* @__PURE__ */ new Map();
  await mapLimit(names, opt.concurrency, async (name) => {
    docs.set(name, await registry.packument(name));
  });
  const out = [];
  for (const p of installable) {
    const doc = docs.get(p.name);
    const pkg = `${p.name}@${p.version}`;
    const base = { package: pkg, file: lock.file, line: p.line };
    if (!doc) continue;
    const published = doc.time[p.version];
    if (published !== void 0) {
      const ageDays = (opt.now.getTime() - Date.parse(published)) / day;
      if (ageDays < opt.minAgeDays) {
        const severity = p.hasInstallScript ? "high" : "medium";
        out.push({
          ...base,
          ruleId: "LG005",
          severity,
          message: `${pkg} was published ${ageDays < 1 ? "less than a day" : `${String(Math.floor(ageDays))} day(s)`} ago${p.hasInstallScript ? " and runs an install script" : ""}`,
          help: `Most hijacked releases are found and pulled within days. Pin the previous version until it is ${String(opt.minAgeDays)} days old.`
        });
      }
    }
    const deprecated = doc.versions[p.version]?.deprecated;
    if (deprecated) {
      out.push({
        ...base,
        ruleId: "LG007",
        severity: "low",
        message: `${pkg} is deprecated: ${deprecated}`,
        help: "Move to the replacement the maintainers recommend."
      });
    }
  }
  return out;
}

// src/rules/popular.ts
var popular = [
  // frameworks and UI
  "react",
  "react-dom",
  "preact",
  "vue",
  "svelte",
  "next",
  "nuxt",
  "angular",
  "@angular/core",
  "solid-js",
  "react-router",
  "react-router-dom",
  "redux",
  "react-redux",
  "zustand",
  "jotai",
  "mobx",
  "rxjs",
  "tailwindcss",
  "postcss",
  "autoprefixer",
  "sass",
  "less",
  "styled-components",
  "@emotion/react",
  // servers and http
  "express",
  "koa",
  "fastify",
  "hono",
  "hapi",
  "body-parser",
  "cors",
  "helmet",
  "morgan",
  "cookie-parser",
  "axios",
  "node-fetch",
  "got",
  "undici",
  "superagent",
  "request",
  "ws",
  "socket.io",
  "http-proxy",
  // utilities
  "lodash",
  "lodash-es",
  "underscore",
  "ramda",
  "moment",
  "dayjs",
  "date-fns",
  "luxon",
  "uuid",
  "nanoid",
  "classnames",
  "clsx",
  "debug",
  "ms",
  "chalk",
  "colors",
  "color",
  "kleur",
  "picocolors",
  "ora",
  "commander",
  "yargs",
  "minimist",
  "inquirer",
  "prompts",
  "dotenv",
  "cross-env",
  "rimraf",
  "mkdirp",
  "glob",
  "fast-glob",
  "globby",
  "minimatch",
  "micromatch",
  "chokidar",
  "fs-extra",
  "graceful-fs",
  "semver",
  "qs",
  "query-string",
  "mime",
  "mime-types",
  "async",
  "bluebird",
  "p-limit",
  "p-map",
  "execa",
  "cross-spawn",
  "which",
  "tslib",
  "core-js",
  "regenerator-runtime",
  "immer",
  "deepmerge",
  "object-assign",
  "inherits",
  "safe-buffer",
  "buffer",
  "events",
  "util",
  "path-browserify",
  "process",
  "readable-stream",
  "string_decoder",
  "escape-string-regexp",
  "strip-ansi",
  "ansi-regex",
  "ansi-styles",
  "supports-color",
  "has-flag",
  "yaml",
  "js-yaml",
  "json5",
  "ini",
  "toml",
  "xml2js",
  "fast-xml-parser",
  "csv-parse",
  "papaparse",
  "zod",
  "yup",
  "joi",
  "ajv",
  "class-validator",
  "validator",
  "jsonwebtoken",
  "jose",
  "bcrypt",
  "bcryptjs",
  "crypto-js",
  "argon2",
  "passport",
  "express-session",
  "cookie",
  "multer",
  "formidable",
  "busboy",
  // data and infra clients
  "mongoose",
  "mongodb",
  "pg",
  "mysql",
  "mysql2",
  "sqlite3",
  "better-sqlite3",
  "redis",
  "ioredis",
  "sequelize",
  "typeorm",
  "prisma",
  "@prisma/client",
  "knex",
  "drizzle-orm",
  "aws-sdk",
  "@aws-sdk/client-s3",
  "firebase",
  "firebase-admin",
  "@google-cloud/storage",
  "stripe",
  "twilio",
  "nodemailer",
  "@slack/web-api",
  "openai",
  "@anthropic-ai/sdk",
  "graphql",
  "@apollo/client",
  "apollo-server",
  // tooling
  "typescript",
  "ts-node",
  "tsx",
  "@types/node",
  "@types/react",
  "babel-core",
  "@babel/core",
  "@babel/preset-env",
  "webpack",
  "webpack-cli",
  "vite",
  "rollup",
  "esbuild",
  "parcel",
  "turbo",
  "nx",
  "eslint",
  "prettier",
  "jest",
  "vitest",
  "mocha",
  "chai",
  "sinon",
  "cypress",
  "playwright",
  "@playwright/test",
  "puppeteer",
  "nodemon",
  "pm2",
  "concurrently",
  "husky",
  "lint-staged",
  "lerna",
  "npm",
  "yarn",
  "pnpm",
  "node-gyp",
  "sharp",
  "canvas",
  "jsdom",
  "cheerio",
  "marked",
  "markdown-it",
  "highlight.js",
  "prismjs",
  "handlebars",
  "ejs",
  "pug",
  "mustache",
  "winston",
  "pino",
  "bunyan",
  "log4js",
  "electron",
  "react-native",
  "expo"
];

// src/rules/typosquat.ts
var popularSet = new Set(popular);
function editDistance(a, b) {
  const d = Array.from(
    { length: a.length + 1 },
    (_, i) => Array.from({ length: b.length + 1 }, (_2, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  const at = (i, j) => d[i]?.[j] ?? Number.POSITIVE_INFINITY;
  for (let i = 1; i <= a.length; i++) {
    const row = d[i] ?? [];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(at(i - 1, j) + 1, at(i, j - 1) + 1, at(i - 1, j - 1) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1])
        v = Math.min(v, at(i - 2, j - 2) + 1);
      row[j] = v;
    }
  }
  return at(a.length, b.length);
}
function normalise(name) {
  return name.toLowerCase().replace(/[-_.]/g, "");
}
function imitates(name) {
  if (popularSet.has(name)) return void 0;
  const n = normalise(name);
  for (const p of popular) {
    if (normalise(p) === n) return p;
    if (name.length >= 5 && editDistance(name, p) === 1) return p;
  }
  return void 0;
}
function checkTyposquat(lock) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const p of lock.packages) {
    if (p.link || seen.has(p.name)) continue;
    seen.add(p.name);
    const target = imitates(p.name);
    if (target === void 0) continue;
    out.push({
      ruleId: "LG006",
      severity: "medium",
      package: `${p.name}@${p.version}`,
      file: lock.file,
      line: p.line,
      message: `${p.name} looks like a typo of the popular package ${target}`,
      help: `Check that ${p.name} is really intended; typosquats imitate popular names to get installed by mistake.`
    });
  }
  return out;
}

// src/rules/index.ts
var rules = [
  {
    id: "LG001",
    severity: "medium",
    online: false,
    title: "Install script",
    description: "The package runs a preinstall, install or postinstall script."
  },
  {
    id: "LG002",
    severity: "high",
    online: false,
    title: "Untrusted source",
    description: "The tarball comes from a git URL or a host outside the allowed registries."
  },
  {
    id: "LG003",
    severity: "high",
    online: false,
    title: "Plain HTTP",
    description: "The tarball is downloaded without TLS."
  },
  {
    id: "LG004",
    severity: "medium",
    online: false,
    title: "Missing integrity",
    description: "No integrity hash, so a tampered tarball is not detected."
  },
  {
    id: "LG005",
    severity: "medium",
    online: true,
    title: "Freshly published",
    description: "The version is younger than the cooldown period; high when it also runs an install script."
  },
  {
    id: "LG006",
    severity: "medium",
    online: false,
    title: "Possible typosquat",
    description: "The name is one edit away from, or a separator variant of, a popular package."
  },
  {
    id: "LG007",
    severity: "low",
    online: true,
    title: "Deprecated",
    description: "The maintainers deprecated this version."
  }
];
async function analyze(lock, opt) {
  const findings = [...checkOffline(lock, opt), ...checkTyposquat(lock)];
  if (opt.registry) findings.push(...await checkOnline(lock, opt.registry, opt));
  return findings.sort(
    (a, b) => severityRank[b.severity] - severityRank[a.severity] || a.line - b.line || a.ruleId.localeCompare(b.ruleId)
  );
}

// src/scan.ts
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

// src/lockfile.ts
function folderName(path2) {
  const i = path2.lastIndexOf("node_modules/");
  return i < 0 ? path2 : path2.slice(i + "node_modules/".length);
}
function str(v) {
  return typeof v === "string" ? v : void 0;
}
function parseLockfile(file, source) {
  let raw;
  try {
    raw = JSON.parse(source);
  } catch (err) {
    throw new Error(`${file}: invalid JSON: ${err.message}`, { cause: err });
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw))
    throw new Error(`${file}: not a lockfile`);
  const doc = raw;
  const version2 = typeof doc.lockfileVersion === "number" ? doc.lockfileVersion : 0;
  if (version2 < 2 || typeof doc.packages !== "object" || doc.packages === null) {
    throw new Error(
      `${file}: lockfileVersion ${String(version2)} is not supported; regenerate it with npm 7 or later`
    );
  }
  const lineOf = /* @__PURE__ */ new Map();
  source.split("\n").forEach((line, i) => {
    const m = /^\s*"(node_modules\/[^"]+)":\s*\{/.exec(line);
    if (m?.[1] && !lineOf.has(m[1])) lineOf.set(m[1], i + 1);
  });
  const packages = [];
  for (const [path2, value] of Object.entries(doc.packages)) {
    if (path2 === "" || !path2.includes("node_modules/")) continue;
    if (typeof value !== "object" || value === null) continue;
    const p = value;
    const pkg = {
      path: path2,
      name: str(p.name) ?? folderName(path2),
      version: str(p.version) ?? "",
      dev: p.dev === true,
      optional: p.optional === true || p.devOptional === true,
      hasInstallScript: p.hasInstallScript === true,
      link: p.link === true,
      line: lineOf.get(path2) ?? 1
    };
    const resolved = str(p.resolved);
    const integrity = str(p.integrity);
    if (resolved !== void 0) pkg.resolved = resolved;
    if (integrity !== void 0) pkg.integrity = integrity;
    packages.push(pkg);
  }
  return { file, lockfileVersion: version2, packages };
}

// src/scan.ts
var lockfileNames = /* @__PURE__ */ new Set(["package-lock.json", "npm-shrinkwrap.json"]);
var skipDirs = /* @__PURE__ */ new Set(["node_modules", ".git", "dist", "testdata", "fixtures"]);
async function findLockfiles(root) {
  if ((await stat(root)).isFile()) return [root];
  const out = [];
  const walk = async (dir) => {
    const entries = (await readdir(dir, { withFileTypes: true })).sort(
      (a, b) => a.name.localeCompare(b.name)
    );
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!skipDirs.has(e.name)) await walk(path.join(dir, e.name));
      } else if (lockfileNames.has(e.name)) {
        out.push(path.join(dir, e.name));
      }
    }
  };
  await walk(root);
  return out;
}
async function scan(paths, cwd, opt) {
  const result = { findings: [], files: 0, packages: 0 };
  for (const p of paths) {
    for (const file of await findLockfiles(p)) {
      const rel = path.relative(cwd, file).split(path.sep).join("/") || file;
      const lock = parseLockfile(rel, await readFile(file, "utf8"));
      result.files++;
      result.packages += lock.packages.length;
      result.findings.push(...await analyze(lock, opt));
    }
  }
  return result;
}

// src/action.ts
var version = true ? "0.1.0" : "dev";
function input(name, fallback) {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return v === void 0 || v.trim() === "" ? fallback : v.trim();
}
var escapeData = (s) => s.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
var escapeProperty = (s) => escapeData(s).replaceAll(":", "%3A").replaceAll(",", "%2C");
async function run() {
  const failOn = input("fail-on", "high");
  if (failOn !== "none" && !(failOn in severityRank)) {
    throw new Error(`fail-on must be high, medium, low or none, got "${failOn}"`);
  }
  const minAgeDays = Number(input("min-age", "7"));
  if (!Number.isFinite(minAgeDays) || minAgeDays < 0)
    throw new Error("min-age must be a non-negative number of days");
  const sarifFile = input("sarif-file", "lockfile-guard.sarif");
  const registry = (process.env.npm_config_registry ?? "https://registry.npmjs.org").replace(/\/*$/, "/");
  const token = process.env.NPM_TOKEN;
  const result = await scan(input("path", ".").split(/\s+/), process.cwd(), {
    registries: [registry],
    allowScripts: input("allow-scripts", "").split(/[\s,]+/).filter(Boolean),
    registry: input("offline", "false") === "true" ? null : new HttpRegistry(token ? { url: registry, token } : { url: registry }),
    minAgeDays,
    now: /* @__PURE__ */ new Date(),
    concurrency: 8
  });
  const opts = { files: result.files, rules, version };
  writeFileSync(sarifFile, render(result.findings, "sarif", opts));
  const summary2 = process.env.GITHUB_STEP_SUMMARY;
  if (summary2) appendFileSync(summary2, render(result.findings, "markdown", opts));
  const output = process.env.GITHUB_OUTPUT;
  if (output) appendFileSync(output, `sarif-file=${sarifFile}
findings=${String(result.findings.length)}
`);
  for (const f of result.findings) {
    const level = f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "notice";
    process.stdout.write(
      `::${level} file=${escapeProperty(f.file)},line=${String(f.line)},title=${f.ruleId}::${escapeData(f.message)}
`
    );
  }
  if (failOn !== "none" && result.findings.some((f) => severityRank[f.severity] >= severityRank[failOn])) {
    process.exitCode = 1;
  }
}
run().catch((err) => {
  process.stdout.write(`::error::${escapeData(String(err))}
`);
  process.exitCode = 1;
});
