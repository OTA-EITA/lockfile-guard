// Bundles the CLI and the GitHub Action entry point into single files with
// no runtime dependencies. dist/action.js is committed, as JavaScript actions
// run straight from the repository.
import { readFileSync } from "node:fs";
import { build } from "esbuild";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));

const common = {
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  legalComments: "none",
  define: { __VERSION__: JSON.stringify(version) },
};

await build({
  ...common,
  entryPoints: ["src/cli.ts"],
  outfile: "dist/cli.js",
  banner: { js: "#!/usr/bin/env node" },
});
await build({ ...common, entryPoints: ["src/action.ts"], outfile: "dist/action.js" });
