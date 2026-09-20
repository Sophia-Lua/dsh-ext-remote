/**
 * @dsh-ext/remote-auth — functional tests for the deferred-mount credential gate.
 *
 * Run:  node test/apply.test.mjs
 *
 * The gate is mounted on a setImmediate tick (after all peer plugin
 * activations), so each block flushes before asserting.
 */

import assert from "node:assert/strict";
import { apply, name, inject, Config, makePasswordEntry, sha256Hex } from "../index.js";

function parseConfig(config = {}) {
  const result = Config["~standard"].validate(config);
  if ("issues" in result && result.issues?.length)
    throw new Error(`remote-auth config issues: ${JSON.stringify(result.issues)}`);
  return result.value;
}

/** Let the deferred mount finish. */
const flush = () => new Promise((resolve) => setImmediate(resolve));

function makeConnection() {
  return {
    requestRejection: (request) => {
      const host = request?.headers?.host;
      if (host === "gateway.example" || host === "127.0.0.1") return undefined;
      return 403;
    },
    authorizeIndex: (request, response) => {
      const host = request?.headers?.host;
      if (host === "gateway.example" || host === "127.0.0.1") return true;
      response.writeHead(403, { "content-type": "text/plain" });
      response.end("remote-access: untrusted host\n");
      return false;
    },
  };
}

const req = (headers, remoteAddress) => ({
  headers,
  method: "GET",
  ...(remoteAddress !== undefined ? { socket: { remoteAddress } } : {}),
});

function makeCtx({ connection, logs = [] }) {
  return {
    get(service) {
      if (service === "connection") return connection;
      return undefined;
    },
    logger: {
      info: (msg) => logs.push(msg),
      warn: (msg) => logs.push(msg),
    },
  };
}

/* ── 1. boot with a generated credential entry ── */

const entry = makePasswordEntry("testuser", "fixture-pass");
assert.ok(entry.salt.length >= 16, "salt is random bytes");
assert.equal(entry.hash, sha256Hex(entry.salt, "fixture-pass"), "hash is sha256(salt+pw)");

const config = parseConfig({
  authUsers: [entry],
  realm: "dsh-remote",
  allowLoopbackNoAuth: true,
  logDecisions: false,
});

const connection = makeConnection();
const logs = [];
apply(makeCtx({ connection, logs }), config);
await flush();

const basic = (user, pass) => "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");

/* ── 2. loopback callers are exempt: no credential needed ── */

assert.equal(
  connection.requestRejection(req({ host: "127.0.0.1" }, "127.0.0.1")),
  undefined,
  "loopback source without credentials passes the gate"
);
assert.equal(
  connection.requestRejection(req({ host: "evil.example.com" }, "127.0.0.1")),
  403,
  "loopback source still runs the inner Host fence (evil host → 403)"
);

/* ── 3. remote caller: credential gate ── */

assert.equal(
  connection.requestRejection(req({ host: "gateway.example" }, "10.0.0.5")),
  401,
  "remote source without credentials → 401"
);
assert.equal(
  connection.requestRejection(req({ host: "gateway.example", authorization: basic("testuser", "wrong") }, "10.0.0.5")),
  401,
  "remote source with wrong password → 401"
);
assert.equal(
  connection.requestRejection(req({ host: "gateway.example", authorization: basic("nobody", "fixture-pass") }, "10.0.0.5")),
  401,
  "remote source with unknown user → 401"
);
assert.equal(
  connection.requestRejection(req({ host: "gateway.example", authorization: basic("testuser", "fixture-pass") }, "10.0.0.5")),
  undefined,
  "remote source with valid credentials → inner fence passes"
);
assert.equal(
  connection.requestRejection(req({ host: "evil.example.com", authorization: basic("testuser", "fixture-pass") }, "10.0.0.5")),
  403,
  "valid credentials cannot bypass the inner Host fence"
);

/* ── 4. authorizeIndex: 401 + WWW-Authenticate on failure ── */

const captured = { code: null, headers: null, body: null };
const fakeRes = {
  writeHead(code, headers) {
    captured.code = code;
    captured.headers = headers;
  },
  end(body) {
    captured.body = body;
  },
};

assert.equal(
  connection.authorizeIndex(req({ host: "gateway.example" }, "10.0.0.5"), fakeRes),
  false,
  "remote source without credentials → index refused"
);
assert.equal(captured.code, 401, "401 written on credential failure");
assert.ok(
  captured.headers["www-authenticate"]?.includes('Basic realm="dsh-remote"'),
  `WWW-Authenticate present: ${JSON.stringify(captured.headers)}`
);
assert.match(captured.body, /remote-auth: unauthorized/);

const res2 = { writeHead() {}, end() {} };
assert.equal(
  connection.authorizeIndex(req({ host: "gateway.example", authorization: basic("testuser", "fixture-pass") }, "10.0.0.5"), res2),
  true,
  "remote source with valid credentials → inner index authorization"
);
const res3 = { writeHead() {}, end() {} };
assert.equal(
  connection.authorizeIndex(req({ host: "127.0.0.1" }, "127.0.0.1"), res3),
  true,
  "loopback source skips the gate and serves the index"
);

/* ── 5. allowLoopbackNoAuth: false gates loopback too ── */

const config5 = parseConfig({ authUsers: [entry], allowLoopbackNoAuth: false });
const connection5 = makeConnection();
apply(makeCtx({ connection: connection5 }), config5);
await flush();
assert.equal(
  connection5.requestRejection(req({ host: "127.0.0.1" }, "127.0.0.1")),
  401,
  "loopback is gated when allowLoopbackNoAuth is false"
);
assert.equal(
  connection5.requestRejection(req({ host: "127.0.0.1", authorization: basic("testuser", "fixture-pass") }, "127.0.0.1")),
  undefined,
  "loopback with credentials passes when gated"
);

/* ── 5b. tunnel topology: loopback + forwarded public host must auth ── */
const config5b = parseConfig({
  authUsers: [entry],
  allowLoopbackNoAuth: true,
  forwardedHostHeader: "x-forwarded-host",
  authHosts: ["gateway.example"],
});
const connection5b = makeConnection();
apply(makeCtx({ connection: connection5b }), config5b);
await flush();
assert.equal(
  connection5b.requestRejection(req({ host: "127.0.0.1" }, "127.0.0.1")),
  undefined,
  "bare loopback use stays exempt"
);
assert.equal(
  connection5b.requestRejection(
    req({ host: "gateway.example", "x-forwarded-host": "gateway.example" }, "127.0.0.1")
  ),
  401,
  "loopback carrying the public forwarded host must authenticate"
);
assert.equal(
  connection5b.requestRejection(
    req(
      { host: "gateway.example", "x-forwarded-host": "gateway.example", authorization: basic("testuser", "fixture-pass") },
      "127.0.0.1"
    )
  ),
  undefined,
  "loopback with forwarded public host + valid credentials passes"
);

/* ── 5c. late peer wrapping: a peer that wraps the service after the
 * gate mounted owns the entry point; the gate remains on the inner chain
 * (the late wrapper's captured `inner` is the gate-wrapped method). ── */
const config5c = parseConfig({
  authUsers: [entry],
  allowLoopbackNoAuth: true,
  forwardedHostHeader: "x-forwarded-host",
  authHosts: ["gateway.example"],
});
const connection5c = makeConnection();
apply(makeCtx({ connection: connection5c }), config5c);
await flush();
const gateBeforePeer = connection5c.requestRejection;
connection5c.requestRejection = (request) => {
  const host = request?.headers?.host;
  if (host === "gateway.example" || host === "127.0.0.1") return gateBeforePeer(request);
  return 403;
};
assert.equal(
  connection5c.requestRejection(req({ host: "gateway.example", "x-forwarded-host": "gateway.example" }, "10.0.0.5")),
  401,
  "late peer wrapper chains INTO the gate: remote without credentials → 401"
);
assert.equal(
  connection5c.requestRejection(
    req({ host: "gateway.example", "x-forwarded-host": "gateway.example", authorization: basic("testuser", "fixture-pass") }, "10.0.0.5")
  ),
  undefined,
  "late peer wrapper + valid credentials passes"
);

/* ── 5d. raw-instance callers (this.method via prototype) are gated too ── */
const config5d = parseConfig({
  authUsers: [entry],
  allowLoopbackNoAuth: true,
  forwardedHostHeader: "x-forwarded-host",
  authHosts: ["gateway.example"],
});
class RawConn {
  requestRejection(request) {
    const host = request?.headers?.host;
    if (host === "gateway.example" || host === "127.0.0.1") return undefined;
    return 403;
  }
  authorizeIndex(request, response) {
    const host = request?.headers?.host;
    if (host === "gateway.example" || host === "127.0.0.1") return true;
    response.writeHead(403, { "content-type": "text/plain" });
    response.end("untrusted\n");
    return false;
  }
}
const rawConn = new RawConn();
apply(makeCtx({ connection: rawConn }), config5d);
await flush();
assert.equal(
  rawConn.requestRejection(req({ host: "gateway.example", "x-forwarded-host": "gateway.example" }, "127.0.0.1")),
  401,
  "raw-instance caller (no own property) is gated via prototype surface"
);
assert.equal(
  rawConn.requestRejection(
    req({ host: "gateway.example", "x-forwarded-host": "gateway.example", authorization: basic("testuser", "fixture-pass") }, "127.0.0.1")
  ),
  undefined,
  "raw-instance caller with valid credentials passes the prototype gate"
);
// A peer that activates later wraps the instance via an OWN property: the
// gate must chain through that own property, not be bypassed by it.
const peerRej = rawConn.requestRejection;
rawConn.requestRejection = (request) => peerRej(request);
assert.equal(
  rawConn.requestRejection(req({ host: "gateway.example", "x-forwarded-host": "gateway.example" }, "127.0.0.1")),
  401,
  "own-property peer wrapper still chains through the gate"
);

/* ── 6. multiple users ── */
const entry2 = makePasswordEntry("alice", "pw-alice");
const config6 = parseConfig({ authUsers: [entry, entry2] });
const connection6 = makeConnection();
apply(makeCtx({ connection: connection6 }), config6);
await flush();
assert.equal(
  connection6.requestRejection(req({ host: "gateway.example", authorization: basic("alice", "pw-alice") }, "10.0.0.5")),
  undefined,
  "second user's credentials pass"
);
assert.equal(
  connection6.requestRejection(req({ host: "gateway.example", authorization: basic("alice", "alice-pw") }, "10.0.0.5")),
  401,
  "user A's password does not work for user B"
);

/* ── 7. Config validation rejects empty / malformed authUsers ── */
assert.throws(
  () => parseConfig({}),
  /authUsers must list at least one/,
  "empty authUsers is rejected at validation"
);
assert.throws(
  () => parseConfig({ authUsers: [] }),
  /authUsers must list at least one/
);
assert.throws(
  () => parseConfig({ authUsers: [{ name: "x" }] }),
  /salt|hash|name/,
  "an entry missing salt/hash is rejected"
);

/* ── 8. identity ── */
assert.equal(name, "remote-auth");
assert.deepEqual(inject, ["connection"]);

console.log("remote-auth: apply() functional assertions passed");
