#!/usr/bin/env node
/**
 * Copy static/ into public/static/ for Workers Assets to serve at /static/*.
 * Run before deploy: `npm run build:assets`.
 *
 * static/ is vendored from the upstream Flask app (see NOTICE). It is copied
 * rather than served directly because public/ is the Workers Assets
 * directory and also receives the front-end vendor libraries below.
 *
 * The Flask app ALSO serves front-end vendor libraries from
 * static/node_modules/, which it populates with its own `npm install` inside
 * static/ — and that directory is gitignored (repo .gitignore L9), so it is
 * simply absent here. Copying static/ alone therefore shipped a dashboard
 * whose every `url_for('static', filename='node_modules/...')` 404s: no
 * bootbox (every confirm-then-submit button silently dead — delete domain,
 * delete alias...), no toastr (flash messages invisible), no parsley (client
 * validation), no multiple-select, intro.js, htmx, qrious (2FA QR code).
 * jQuery/Bootstrap were unaffected: those come from the committed
 * static/assets/js/vendors/ theme bundle.
 *
 * So the packages are declared in this project's package.json instead and
 * the referenced FILES are mirrored into public/static/node_modules/ below,
 * preserving the paths the templates ask for. VENDOR_FILES must cover every
 * node_modules path referenced by templates/**; `npm run check:assets`
 * (scripts/check-assets.mjs) fails the build if one is missing.
 */

import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const src = path.join(root, "static");
const dest = path.join(root, "public", "static");

rmSync(dest, { recursive: true, force: true });
mkdirSync(path.dirname(dest), { recursive: true });
cpSync(src, dest, {
  recursive: true,
  filter: (p) => !/(\.DS_Store|Thumbs\.db)$/.test(p),
});
console.log(`copied static assets -> ${path.relative(root, dest)}`);

/**
 * Paths are relative to a node_modules root and are reproduced verbatim
 * under public/static/node_modules/, because that is the URL the Jinja/
 * nunjucks templates build. Directories are copied recursively (font-awesome
 * CSS pulls ../fonts/, intro.js and toastr ship maps).
 */
const VENDOR_FILES = [
  "@sentry/browser/build/bundle.min.js",
  "bootbox/dist/bootbox.min.js",
  "font-awesome/css/font-awesome.css",
  "font-awesome/fonts",
  "htmx.org/dist/htmx.min.js",
  "intro.js/minified/intro.min.js",
  "intro.js/minified/introjs.min.css",
  "multiple-select/dist/multiple-select.min.js",
  "multiple-select/dist/multiple-select.min.css",
  "parsleyjs/dist/parsley.min.js",
  "parsleyjs/dist/i18n/en.js",
  "qrious/dist/qrious.min.js",
  "toastr/build/toastr.min.js",
  "toastr/build/toastr.min.css",
  "vue/dist/vue.min.js",
];

const nm = path.join(root, "node_modules");
const vendorDest = path.join(dest, "node_modules");
const missing = [];
for (const rel of VENDOR_FILES) {
  const from = path.join(nm, rel);
  if (!existsSync(from)) {
    missing.push(rel);
    continue;
  }
  const to = path.join(vendorDest, rel);
  mkdirSync(path.dirname(to), { recursive: true });
  cpSync(from, to, { recursive: true });
}
if (missing.length) {
  console.error(
    `build:assets — MISSING vendor files (run npm install):\n  ${missing.join("\n  ")}`,
  );
  process.exit(1);
}
console.log(
  `copied ${VENDOR_FILES.length} vendor paths -> ${path.relative(root, vendorDest)}`,
);
