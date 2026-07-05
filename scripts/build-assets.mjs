#!/usr/bin/env node
/**
 * Copy the Flask app's static assets (repo-root static/) into
 * cloudflare/public/static/ for Workers Assets to serve at /static/*.
 * Run before deploy: `npm run build:assets`.
 */

import { cpSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const src = path.join(path.dirname(root), "static");
const dest = path.join(root, "public", "static");

rmSync(dest, { recursive: true, force: true });
mkdirSync(path.dirname(dest), { recursive: true });
cpSync(src, dest, {
  recursive: true,
  filter: (p) => !/(\.DS_Store|Thumbs\.db)$/.test(p),
});
console.log(`copied static assets -> ${path.relative(root, dest)}`);
