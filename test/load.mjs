// Bundles a Deno edge-function module for Node: maps "npm:pkg@ver/path" imports to the local node_modules.
import { build } from "esbuild";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const npmSpecifiers = {
  name: "npm-specifiers",
  setup(b) {
    b.onResolve({ filter: /^npm:/ }, async (args) => {
      const spec = args.path.slice(4).replace(/^(@[^/]+\/[^@/]+|[^@/]+)@[^/]+/, "$1");
      return b.resolve(spec, { kind: args.kind, resolveDir: process.cwd() });
    });
  },
};

export async function load(entry) {
  const out = await build({ entryPoints: [entry], bundle: true, format: "esm", platform: "node", write: false, plugins: [npmSpecifiers] });
  const file = join(mkdtempSync(join(tmpdir(), "siwm-")), "mod.mjs");
  writeFileSync(file, out.outputFiles[0].text);
  return import(pathToFileURL(file).href);
}
