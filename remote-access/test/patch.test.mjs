/**
 * @dsh-ext/remote-access — patch file validation.
 *
 * Run:  node test/patch.test.mjs
 *
 * Parses patches/cordis.patch.yml and asserts the structural contract the
 * profile user-layer consumes: two top-level entries — a `webserver` config
 * re-target (all-interfaces bind) and an `insert` that mounts the
 * `remote-access` plugin on the `connection` service.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/* js-yaml is not a declared dependency of this local plugin; the dsh
 * installation always carries it in its pnpm store, so resolve it from
 * there before falling back to a minimal structural parse (the patch file
 * is deliberately simple — a two-entry list of plain scalars). */
let load;
let yaml;
const CANDIDATES = [
  "js-yaml",
  // The dsh installation carries js-yaml in its pnpm store; the exact global
  // root differs per machine, so callers may point DSH_GLOBAL_ROOT at it.
  process.env.DSH_GLOBAL_ROOT
    ? `${process.env.DSH_GLOBAL_ROOT}/node_modules/.pnpm/js-yaml@4.3.2/node_modules/js-yaml/dist/js-yaml.mjs`
    : null,
].filter(Boolean);
for (const candidate of CANDIDATES) {
  try {
    yaml = await import(candidate);
    load = yaml.load;
    break;
  } catch {
    /* try next */
  }
}

const text = readFileSync(new URL("../patches/cordis.patch.yml", import.meta.url), "utf8");

if (load === undefined) {
  // Fallback: assert the exact literal lines the loader will read. This
  // keeps the test usable on a machine without the dsh store on hand.
  for (const expected of [
    "- id: webserver",
    "    host: 0.0.0.0",
    "    port: !!js ctx.webStartup.port ?? 3080",
    "    compression: gzip",
    "    compressionLevel: 1",
    "    compressionThresholdBytes: 1024",
    "- id: remote-access",
    "      name: '@dsh-ext/remote-access'",
    "      inject: [connection]",
    "      allowedHosts:",
    "          - your-domain.example",
    "        allowLoopback: true",
    "        allowLan: true",
  ]) {
    assert.ok(text.includes(expected), `patch file missing line: ${JSON.stringify(expected)}`);
  }
  console.log("remote-access: patch structure OK (literal-line fallback, js-yaml unavailable)");
  process.exit(0);
}

// The dsh entry-list dialect registers a `!!js` tag whose scalars round-trip
// as `{ __jsExpr }` nodes (see dsh-app-boot's YAML dialect); replicate it so
// a stock js-yaml can parse the document.
let doc;
try {
  doc = load(text);
} catch (error) {
  if (!String(error.message).includes("!<tag:yaml.org,2002:js>")) throw error;
  const { Schema, Type } = yaml;
  const jsExpr = new Type("tag:yaml.org,2002:js", {
    kind: "scalar",
    resolve: (data) => typeof data === "string",
    construct: (data) => ({ __jsExpr: data }),
  });
  const dialect = yaml.JSON_SCHEMA.extend(jsExpr);
  doc = load(text, { schema: dialect });
}
assert.ok(Array.isArray(doc), "patch document must be a top-level YAML list");
assert.equal(doc.length, 2, "two patch entries: webserver re-target + plugin mount");

// — entry 1: the webserver row re-target —
const [webserver, insertEntry] = doc;
assert.equal(webserver.id, "webserver");
assert.equal(webserver.disabled, undefined, "the row must stay enabled");
assert.equal(String(webserver.config.host), "0.0.0.0", "all-interfaces bind for remote domains");
// The port keeps the stock webStartup expression: a `!!js` node in the raw
// text (a `{ __jsExpr }` object after the dialect parse above).
assert.ok(text.includes("port: !!js ctx.webStartup.port ?? 3080"), "port must honor the --port flag");
if ("__jsExpr" in webserver.config.port) assert.equal(webserver.config.port.__jsExpr, "ctx.webStartup.port ?? 3080");
// The webserver schema requires these keys be restated (a patch replaces the
// row's whole config) — assert the stock row's values are preserved.
assert.equal(webserver.config.compression, "gzip");
assert.equal(webserver.config.compressionLevel, 1);
assert.equal(webserver.config.compressionThresholdBytes, 1024);

// — entry 2: the plugin mount —
assert.equal(insertEntry.id, undefined);
assert.ok(Array.isArray(insertEntry.insert), "the mount uses an `insert:` list");
assert.equal(insertEntry.insert.length, 1);
const mount = insertEntry.insert[0];
assert.equal(mount.id, "remote-access");
assert.equal(mount.name, "@dsh-ext/remote-access");
assert.deepEqual(mount.inject, ["connection"]);
assert.deepEqual(mount.config.allowedHosts, ["your-domain.example"]);
assert.equal(mount.config.allowLoopback, true);
assert.equal(mount.config.allowLan, true);

// — the mount row's authority entries must all be bare host[:port] or
//   `*.suffix` (the plugin rejects anything else at boot). —
const bad = mount.config.allowedHosts.filter((entry) => {
  const base = entry.startsWith("*.") ? entry.slice(2) : entry;
  let url;
  try {
    url = new URL(`http://${base}`);
  } catch {
    return true;
  }
  return url.pathname !== "/";
});
assert.equal(bad.length, 0, `non-authority entries: ${JSON.stringify(bad)}`);

console.log("remote-access: patch structure assertions passed");
