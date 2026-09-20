/**
 * @dsh-ext/remote-access — functional test for the full apply() mount.
 *
 * Run:  node test/apply.test.mjs
 *
 * Drives the real plugin module against a mock cordis context and a mock
 * connection service, asserting the exact request decisions the patched
 * requestRejection / authorizeIndex produce:
 *
 *   - trusted Host (configured domain, wildcard, loopback, LAN literal)
 *     with no launch token or cookie → accepted (no 401);
 *   - cross-site markers → 403 (the fence is retained);
 *   - untrusted Host → 403;
 *   - malformed configured entries → boot-time rejection.
 */

import assert from "node:assert/strict";
import { apply, name, inject, Config } from "../index.js";

/**
 * Run the plugin's Config exactly the way the cordis runtime does:
 * `Config["~standard"].validate(config)`. The real schemastery schema and
 * the package-local fallback both implement the Standard Schema v1
 * interface, so one code path covers both.
 */
function parseConfig(config = {}) {
  const result = Config["~standard"].validate(config);
  if ("issues" in result && result.issues?.length) {
    throw new Error(`remote-access config issues: ${JSON.stringify(result.issues)}`);
  }
  return result.value;
}

/* ── a minimal mock of the cordis plugin context the plugin reads ── */

function makeCtx({ connection, webRuntime, logs = [], indexInjections = [] }) {
  const listeners = {};
  const ctx = {
    get(service) {
      if (service === "connection") return connection;
      if (service === "webRuntime") return webRuntime;
      return undefined;
    },
    on(event, fn) {
      (listeners[event] ??= []).push(fn);
    },
    emit(event, ...args) {
      for (const fn of listeners[event] ?? []) fn(...args);
    },
    logger: {
      info: (msg) => logs.push(msg),
      warn: (msg) => logs.push(msg),
    },
  };
  ctx.indexInjections = indexInjections;
  return ctx;
}

/** A fake connection service shaped like the stock HostConnectionService. */
function makeConnection() {
  return {
    requestRejection: (request) => undefined,
    authorizeIndex: (request, response) => true,
  };
}

/** node:http-shaped request: string headers on a plain object. */
const req = (headers) => ({ headers, method: "GET" });

/** node:http-shaped request carrying a TCP source address (the proxy path). */
const reqFrom = (headers, remoteAddress) => ({
  headers,
  method: "GET",
  socket: { remoteAddress },
});

/* ── 1. boot with the shipped config shape ── */

const config = parseConfig({
  allowedHosts: ["gateway.example", "*.corp.example.com"],
  allowLoopback: true,
  allowLan: true,
  logDecisions: true,
});
assert.deepEqual(config.allowedHosts, ["gateway.example", "*.corp.example.com"]);
assert.equal(config.logDecisions, true);

const connection = makeConnection();
const logs = [];
const ctx = makeCtx({
  connection,
  webRuntime: { trustedHosts: ["192.168.1.20", "10.0.0.5"] },
  logs,
});
apply(ctx, config);

// The mount swapped the stock functions.
assert.equal(typeof connection.requestRejection, "function");
assert.equal(typeof connection.authorizeIndex, "function");

// — trusted Host, no token, no cookie —
assert.equal(connection.requestRejection(req({ host: "gateway.example" })), undefined);
assert.equal(connection.requestRejection(req({ host: "gateway.example:3080" })), undefined);
assert.equal(connection.requestRejection(req({ host: "sub.corp.example.com" })), undefined, "wildcard label");
assert.equal(connection.requestRejection(req({ host: "192.168.1.20" })), undefined, "LAN literal from webRuntime");
assert.equal(connection.requestRejection(req({ host: "127.0.0.1" })), undefined, "loopback");
assert.equal(connection.requestRejection(req({ host: "localhost" })), undefined, "loopback name");

// — untrusted Host —
assert.equal(connection.requestRejection(req({ host: "evil.example.com" })), 403);
assert.equal(connection.requestRejection(req({})), 403, "missing Host header");
assert.equal(connection.requestRejection(req({ host: "not a host" })), 403);

// — cross-site markers: `sec-fetch-site: cross-site` is retained —
assert.equal(connection.requestRejection(req({ host: "gateway.example", "sec-fetch-site": "cross-site" })), 403);
// — a foreign `Origin` no longer 403s on its own (the proxy-agnostic fix):
//   a trusted Host with any Origin passes; only the cross-site fetch
//   marker and untrusted hosts/sources still refuse.
assert.equal(
  connection.requestRejection(req({ host: "gateway.example", origin: "http://evil.org" })),
  undefined,
  "foreign Origin with trusted Host passes (Origin comparison dropped)"
);
assert.equal(
  connection.requestRejection(req({ host: "gateway.example:3080", origin: "http://gateway.example:3080" })),
  undefined,
  "same-host Origin passes"
);

// — index authorization —
const captured = { code: null, body: null };
const fakeRes = {
  writeHead(code, headers) {
    captured.code = code;
  },
  end(body) {
    captured.body = body;
  },
};
assert.equal(connection.authorizeIndex(req({ host: "gateway.example" }), fakeRes), true, "trusted host serves index without token");
assert.equal(captured.code, null, "no response written for the trusted host");
assert.equal(connection.authorizeIndex(req({ host: "evil.example.com" }), fakeRes), false, "untrusted host refused");
assert.equal(captured.code, 403);

// — the boot log summarized the trust set —
assert.ok(logs.some((line) => line.includes("gateway.example")), logs.join("\n"));

/* ── 2. boot with an empty allowedHosts still serves loopback ── */

const config2 = parseConfig({ allowedHosts: [] });
assert.deepEqual(config2.allowedHosts, []);
const connection2 = makeConnection();
apply(makeCtx({ connection: connection2 }), config2);
assert.equal(connection2.requestRejection(req({ host: "127.0.0.1" })), undefined);
assert.equal(connection2.requestRejection(req({ host: "gateway.example" })), 403, "no allowedHosts = no remote domains");

/* ── 3. loopback disabled ── */

const config3 = parseConfig({ allowLoopback: false });
const connection3 = makeConnection();
apply(makeCtx({ connection: connection3 }), config3);
assert.equal(connection3.requestRejection(req({ host: "127.0.0.1" })), 403);

/* ── 4. malformed configured entries are rejected at boot ── */

assert.throws(
  () => {
    const conn = makeConnection();
    apply(makeCtx({ connection: conn }), {
      allowedHosts: ["harness.example/path"],
      allowLoopback: true,
      allowLan: true,
      logDecisions: false,
    });
  },
  /not a valid host or wildcard authority/
);

assert.throws(
  () => {
    const conn = makeConnection();
    apply(makeCtx({ connection: conn }), {
      allowedHosts: ["host:0x7f"],
      allowLoopback: true,
      allowLan: true,
      logDecisions: false,
    });
  },
  /not a valid host or wildcard authority/
);

/* ── 5. proxy-trust: a request from a trusted source IP is accepted for ANY host ── */

// A reverse tunnel terminates TLS at the public domain and forwards to
// 127.0.0.1:3080 — its upstream Host is NOT the public domain. The plugin
// must trust the TCP source instead of the Host header.
const config5 = parseConfig({
  allowedHosts: ["gateway.example"],
  trustedClientNets: ["127.0.0.1/32", "192.168.0.0/16"],
});
const connection5 = makeConnection();
apply(makeCtx({ connection: connection5 }), config5);
// Loopback source with a foreign upstream Host → trusted (source wins).
assert.equal(connection5.requestRejection(reqFrom({ host: "upstream.internal" }, "127.0.0.1")), undefined, "loopback source, foreign host");
assert.equal(connection5.requestRejection(reqFrom({ host: "anything" }, "192.168.1.50")), undefined, "RFC1918 source, foreign host");
// A public source NOT in trustedClientNets with the allowed domain host →
// still trusted through the Host fence (direct-connection path).
assert.equal(connection5.requestRejection(reqFrom({ host: "gateway.example" }, "8.8.8.8")), undefined, "public source, allowed domain host");
// A public source NOT in trustedClientNets with a foreign host → 403.
assert.equal(connection5.requestRejection(reqFrom({ host: "evil.example.com" }, "8.8.8.8")), 403, "untrusted public source, foreign host");
// A trusted SOURCE (proxy) suppresses the cross-site marker: the proxy
// terminated TLS and the forwarded `sec-fetch-site` is proxy-distortion,
// so it must not 403 a same-origin browser request. An untrusted source
// with the marker still 403s (the host fence is the real defense there).
assert.equal(
  connection5.requestRejection(reqFrom({ host: "127.0.0.1", origin: "http://evil.org", "sec-fetch-site": "cross-site" }, "127.0.0.1")),
  undefined,
  "trusted source skips the cross-site marker"
);
assert.equal(
  connection5.requestRejection(
    reqFrom({ host: "gateway.example", "sec-fetch-site": "cross-site" }, "8.8.8.8")
  ),
  403,
  "cross-site marker from an UNtrusted source still 403s"
);
assert.equal(
  connection5.requestRejection(reqFrom({ host: "127.0.0.1", origin: "http://evil.org" }, "127.0.0.1")),
  undefined,
  "foreign Origin alone passes (Origin comparison dropped)"
);

/* ── 6. catch-all source trust (0.0.0.0/0) accepts any source ── */

const config6 = parseConfig({ allowedHosts: [], trustedClientNets: ["0.0.0.0/0"], allowLoopback: false, allowLan: false });
const connection6 = makeConnection();
apply(makeCtx({ connection: connection6 }), config6);
assert.equal(connection6.requestRejection(reqFrom({ host: "whatever" }, "8.8.8.8")), undefined, "catch-all trusts public sources");

/* ── 7. malformed trustedClientNets entries are rejected at boot ── */

assert.throws(
  () => {
    const conn = makeConnection();
    apply(makeCtx({ connection: conn }), {
      allowedHosts: [],
      trustedClientNets: ["10.0.0.0/33"],
    });
  },
  /trustedClientNets entry/
);

assert.throws(
  () => {
    const conn = makeConnection();
    apply(makeCtx({ connection: conn }), {
      allowedHosts: [],
      trustedClientNets: ["not a cidr"],
    });
  },
  /trustedClientNets entry/
);

/* ── 8. injectTransport: the owned-host transport row reaches index.html ── */

// With injectTransport on, apply() must register a `webserver/index-inject`
// listener that pushes a `global` row setting __DSH_TRANSPORT__ so the
// browser's isLoopback check passes for a public domain.
const ctx8 = makeCtx({ connection: makeConnection() });
apply(ctx8, { injectTransport: true, logDecisions: false });
ctx8.emit("webserver/index-inject", ctx8.indexInjections ?? []);
// The plugin registered its listener via ctx.on; emit through that same ctx.
// Re-emit through the real listener path:
const table8 = [];
// The on() listener was registered; trigger it by emitting on the ctx.
// (makeCtx.on stores listeners; emit fires them.)
ctx8.emit("webserver/index-inject", table8);
assert.ok(
  table8.some((row) => row?.kind === "global" && row?.name === "__DSH_TRANSPORT__" && row?.value?.ownsHost === true),
  `injectTransport should push a global row, got: ${JSON.stringify(table8)}`
);

// And with injectTransport off (the default), no such listener is registered.
const ctx8b = makeCtx({ connection: makeConnection() });
apply(ctx8b, { injectTransport: false, logDecisions: false });
const table8b = [];
ctx8b.emit("webserver/index-inject", table8b);
assert.equal(
  table8b.filter((row) => row?.name === "__DSH_TRANSPORT__").length,
  0,
  "injectTransport off should not push a transport row"
);

/* ── 9. plugin identity ── */

assert.equal(name, "remote-access");
assert.deepEqual(inject, ["connection"]);

console.log("remote-access: apply() functional assertions passed");
