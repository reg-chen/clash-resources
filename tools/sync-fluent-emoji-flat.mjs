#!/usr/bin/env node
/**
 * Monthly sync of Microsoft's Fluent Emoji Flat assets through Iconify's
 * maintained, MIT-licensed JSON icon set. Only this directory is managed.
 *
 * Installation (CI):
 *   npm install --prefix tools --no-save --no-package-lock --ignore-scripts \
 *     --no-audit --no-fund @iconify/utils@3 @iconify-json/fluent-emoji-flat@1
 */
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getIconData, iconToSVG, iconToHTML } from "@iconify/utils";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT = join(ROOT, "icons", "fluent-emoji-flat");
const DATA = new URL("./node_modules/@iconify-json/fluent-emoji-flat/icons.json", import.meta.url);
const mode = process.argv[2] || "--check";
const MAX_CHANGES = 80;

if (!["--check", "--write"].includes(mode) || process.argv.length > 3) {
  throw new Error("Usage: node tools/sync-fluent-emoji-flat.mjs [--check|--write]");
}
if (!existsSync(OUTPUT)) {
  throw new Error("Expected managed icons directory is missing: " + OUTPUT);
}

const collection = JSON.parse(readFileSync(DATA, "utf8"));
const names = [...new Set([
  ...Object.keys(collection.icons || {}),
  ...Object.keys(collection.aliases || {}),
])].sort();
if (collection.prefix !== "fluent-emoji-flat" || names.length < 2500) {
  throw new Error("Unexpected or incomplete upstream Fluent Emoji Flat icon set");
}
const VALID_NAME = /^[a-z0-9][a-z0-9-]*$/;
const existing = new Set(readdirSync(OUTPUT).filter(name => name.endsWith(".svg")));
const upstream = new Set(names.map(name => name + ".svg"));

function canonicalSVG(svg) {
  const match = svg.trim().match(/^<svg\b([^>]*)>([\s\S]*?)<\/svg>$/);
  if (!match) throw new Error("Malformed SVG");
  const viewBox = match[1].match(/\bviewBox="([^"]+)"/);
  if (!viewBox) throw new Error("SVG has no viewBox");
  // Existing icons use the same path data, but often insert formatting
  // whitespace between XML tags. Never rewrite for whitespace alone.
  return viewBox[1] + "|" + match[2].trim().replace(/>\s+</g, "><");
}

const updates = [];
const additions = [];
for (const name of names) {
  if (!VALID_NAME.test(name)) throw new Error("Unsafe upstream name: " + name);
  const data = getIconData(collection, name);
  if (!data) throw new Error("Cannot resolve Iconify icon: " + name);
  const rendered = iconToSVG(data, { height: "auto" });
  const svg = iconToHTML(rendered.body, rendered.attributes);
  if (svg.length > 100000 ||
      /<\s*(?:script|foreignObject|iframe|image)\b|on\w+\s*=|(?:href|xlink:href)\s*=\s*["'](?:https?:|\/\/)/i.test(svg)) {
    throw new Error("Unexpected unsafe or oversized SVG: " + name);
  }
  const dest = join(OUTPUT, name + ".svg");
  if (existsSync(dest) && canonicalSVG(readFileSync(dest, "utf8")) === canonicalSVG(svg)) {
    continue;
  }
  const formatted = svg.replace(/^(<svg\b[^>]*>)/, "$1\n").replace(/<\/svg>$/, "\n</svg>\n");
  (existsSync(dest) ? updates : additions).push({ dest, content: formatted, name });
}
const missingUpstream = [...existing].filter(name => !upstream.has(name));
const pending = [...updates, ...additions];
const headline = "Fluent Emoji Flat: upstream " + names.length +
  ", existing " + existing.size + ", update " + updates.length +
  ", add " + additions.length + ", retained legacy " + missingUpstream.length;
console.log(headline);
for (const item of pending.slice(0, 15)) console.log("  " + item.name);
if (pending.length > 15) console.log("  ... and " + (pending.length - 15) + " more");
if (mode === "--check" && updates.length > 100) {
  // Temporary diagnostic for any unexpected mass change; never publish it.
  for (const item of updates.slice(0, 3)) {
    const before = canonicalSVG(readFileSync(item.dest, "utf8"));
    const after = canonicalSVG(item.content);
    let pos = 0;
    while (pos < before.length && pos < after.length && before[pos] === after[pos]) pos++;
    console.log("DIAGNOSTIC " + item.name + ": first diff " + pos +
      ", old " + JSON.stringify(before.slice(Math.max(0, pos - 40), pos + 160)) +
      ", upstream " + JSON.stringify(after.slice(Math.max(0, pos - 40), pos + 160)));
  }
}

if (process.env.GITHUB_STEP_SUMMARY) {
  const summary = [
    "### Fluent Emoji Flat monthly sync",
    "",
    "- Source: [Iconify / Fluent Emoji Flat](https://icon-sets.iconify.design/fluent-emoji-flat/)",
    "- Original artwork: [Microsoft Fluent UI Emoji](https://github.com/microsoft/fluentui-emoji) (MIT)",
    "- " + headline,
    "- Mode: " + mode,
    "",
  ].join("\n");
  const { appendFileSync } = await import("node:fs");
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
}

if (pending.length > MAX_CHANGES) {
  throw new Error("Refusing " + pending.length + " changed icons (limit " + MAX_CHANGES +
    "); inspect upstream/formatting first to avoid a mass rewrite and CDN purge throttling.");
}

if (mode === "--write") {
  for (const item of pending) writeFileSync(item.dest, item.content, "utf8");
  console.log("Wrote " + pending.length + " changed icons.");
} else {
  console.log("Read-only check; no files modified.");
}
// No deletions: legacy icons and hand-maintained brand icons remain untouched.
