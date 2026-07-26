#!/usr/bin/env node
/**
 * Fail the build when a template references a static asset that will 404.
 *
 * This exists because the port shipped for weeks with every
 * static/node_modules/* asset missing (the Flask app npm-installs them into
 * static/, which is gitignored — see scripts/build-assets.mjs). Nothing
 * caught it: the server-rendered tests assert HTML, and a <script src> that
 * 404s still leaves the page rendering "fine". The visible damage was every
 * bootbox-confirm button doing nothing (delete domain / delete alias) and
 * flash toasts never appearing.
 *
 * Scans templates/ for url_for('static', filename='...') and literal
 * /static/... URLs, then asserts each resolves under public/static/.
 * Run by `npm run build:assets` via predeploy/pretest.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const templatesDir = path.join(root, "templates");
const publicStatic = path.join(root, "public", "static");

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = path.join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".html")) out.push(p);
  }
  return out;
}

// url_for('static', filename='X')  |  "/static/X"
const URL_FOR = /url_for\(\s*['"]static['"]\s*,\s*filename\s*=\s*['"]([^'"]+)['"]/g;
const LITERAL = /["'(]\/static\/([^"')?#]+)/g;

const refs = new Map(); // asset path -> first template that referenced it
for (const file of walk(templatesDir)) {
  const body = readFileSync(file, "utf8");
  for (const re of [URL_FOR, LITERAL]) {
    re.lastIndex = 0;
    let m = re.exec(body);
    while (m) {
      // Skip Jinja-interpolated names — they cannot be checked statically.
      if (!m[1].includes("{")) {
        if (!refs.has(m[1])) refs.set(m[1], path.relative(root, file));
      }
      m = re.exec(body);
    }
  }
}

const missing = [];
for (const [asset, from] of refs) {
  if (!existsSync(path.join(publicStatic, asset))) missing.push({ asset, from });
}

if (missing.length) {
  console.error(
    `check:assets — ${missing.length} referenced asset(s) missing from public/static (they would 404 at runtime):`,
  );
  for (const { asset, from } of missing) console.error(`  ${asset}   (${from})`);
  process.exit(1);
}
console.log(`check:assets — all ${refs.size} referenced static assets present`);
