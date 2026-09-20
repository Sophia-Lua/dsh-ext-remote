/**
 * @dsh-ext/remote-auth
 *
 * dsh web plugin: an account/password gate for remote-domain access.
 *
 * This is the security layer that sits ON TOP of @dsh-ext/remote-access.
 * remote-access removes the launch-token requirement so a remote browser can
 * reach the GUI; remote-auth adds back a credential gate so that reaching
 * the port is not the same as operating the harness.
 *
 * ── How it works ────────────────────────────────────────────────────────────
 *
 * Both plugins `inject: ["connection"]` and replace the connection service's
 * `requestRejection` / `authorizeIndex`. The profile patch layer lists
 * remote-access BEFORE remote-auth, so remote-auth activates later and wraps
 * the already-patched methods:
 *
 *   connection.requestRejection / authorizeIndex
 *     └─ remote-auth (this plugin, outermost)
 *          └─ remote-access (Host/Origin fence, no 401)
 *               └─ stock @deepseek-ai/dsh-client-connection
 *
 * This plugin wraps, it never unwraps: it captures the inner (remote-access)
 * implementations at activation time and composes its own check over them.
 *
 * ── The credential check ───────────────────────────────────────────────────
 *
 *   - Loopback callers (remoteAddress ∈ 127/8 or ::1) skip the gate: local
 *     use of the box stays token-free, matching remote-access' intent.
 *   - Every other caller must present valid credentials:
 *       HTTP requests  → `Authorization: Basic <user:password>` header
 *       WebSocket      → the upgrade request carries the same header; the
 *                        browser's native Basic-auth flow attaches it to
 *                        same-origin fetch and WebSocket upgrades after the
 *                        initial 401 + WWW-Authenticate login prompt.
 *   - A missing/invalid credential yields 401 + `WWW-Authenticate: Basic`,
 *     which is the standard "browser shows a username/password dialog"
 *     response. No launch token, no dsh cookie, no front-end changes.
 *
 * ── Password storage ───────────────────────────────────────────────────────
 *
 * `authUsers` holds `{ name, salt, hash }` where `hash =
 * sha256(salt + password)` in hex. Passwords are never written to the
 * patch file or logs; generate the pair with `make-password.mjs`
 * (`npm run make-password`) and paste only the salt + hash. Comparison is
 * constant-time.
 *
 * ── SECURITY ───────────────────────────────────────────────────────────────
 *
 * A valid credential grants full operation of this harness AND (when
 * remote-access' `injectTransport` is on) write access to the host's
 * settings/credential files. Only enable this for a domain you intend to
 * share. The loopback exemption means anyone who can reach the box's
 * loopback (the box itself, or a co-located process/container) still has
 * token-free access — that is by design for local use.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/* Minimal Standard-Schema v1 config, matching the shape the cordis runtime
 * validates via `Config["~standard"].validate(config)`. This plugin has no
 * external dependency: it only needs the node built-in crypto. */
const str = () => ({
  ["~standard"]: {
    validate(input) {
      if (typeof input !== "string" || input.length < 1)
        return { issues: [{ message: "expected non-empty string" }] };
      return { value: input };
    },
  },
});

/** One credential entry: username plus a salted SHA-256 password hash. */
const AuthUser = {
  ["~standard"]: {
    validate(input) {
      if (input === null || typeof input !== "object" || Array.isArray(input))
        return { issues: [{ message: "authUsers entry must be { name, salt, hash }" }] };
      const out = {};
      const issues = [];
      for (const key of ["name", "salt", "hash"]) {
        if (!(key in input)) {
          issues.push({ path: [key], message: `missing required key "${key}"` });
          continue;
        }
        const r = str()["~standard"].validate(input[key]);
        if ("issues" in r) issues.push(...r.issues.map((i) => ({ ...i, path: [key] })));
        else out[key] = r.value;
      }
      return issues.length ? { issues } : { value: out };
    },
  },
};

const name = "remote-auth";
const inject = ["connection"];

/**
 * Config.
 *  - authUsers: at least one `{ name, salt, hash }`; `hash` is
 *    `sha256(salt + password)` in lowercase hex.
 *  - allowLoopbackNoAuth: loopback callers skip the gate (default true).
 *  - forwardedHostHeader: name of a header carrying the PUBLIC host the
 *    visitor actually used (default "x-forwarded-host"). When enabled
 *    together with `authHosts`, a request whose loopback source is
 *    accompanied by that header naming one of `authHosts` is treated as a
 *    REMOTE caller and must authenticate. This is the key for the
 *    tunnel topology (cloudflared → nginx → dsh, all on one box): every
 *    browser request arrives at node:http with source 127.0.0.1, so a
 *    pure source-based exemption would let all remote traffic through.
 *    dsh's `X-Forwarded-For`-style trust (remote-access'
 *    `forwardedHostHeader`) has the same property on the Host fence.
 *  - authHosts: hosts (bare host / host:port / *.suffix) that are treated
 *    as remote when seen in `forwardedHostHeader`; only meaningful with
 *    `forwardedHostHeader` set.
 *  - realm: the `WWW-Authenticate` realm string shown in the browser dialog.
 *  - logDecisions: one activation summary line (never the credentials).
 */
const Config = {
  ["~standard"]: {
    validate(input) {
      const raw = input ?? {};
      const users = raw.authUsers ?? null;
      if (!Array.isArray(users) || users.length === 0)
        return { issues: [{ message: "remote-auth: authUsers must list at least one { name, salt, hash } entry" }] };
      const issues = [];
      const authUsers = [];
      users.forEach((u, i) => {
        const r = AuthUser["~standard"].validate(u);
        if ("issues" in r) issues.push(...(r.issues ?? []).map((x) => ({ ...x, path: ["authUsers", i, ...(x.path ?? [])] })));
        else authUsers.push(r.value);
      });
      if (issues.length) return { issues };
      const realm = raw.realm ?? "dsh";
      if (typeof realm !== "string" || realm.length === 0)
        issues.push({ path: ["realm"], message: "realm must be a non-empty string" });
      const allowLoopbackNoAuth = raw.allowLoopbackNoAuth ?? true;
      if (typeof allowLoopbackNoAuth !== "boolean")
        issues.push({ path: ["allowLoopbackNoAuth"], message: "expected boolean" });
      const logDecisions = raw.logDecisions ?? false;
      if (typeof logDecisions !== "boolean")
        issues.push({ path: ["logDecisions"], message: "expected boolean" });
      const forwardedHostHeader = raw.forwardedHostHeader ?? "x-forwarded-host";
      if (typeof forwardedHostHeader !== "string" || forwardedHostHeader.length === 0)
        issues.push({ path: ["forwardedHostHeader"], message: "expected string" });
      const authHosts = raw.authHosts ?? [];
      if (!Array.isArray(authHosts))
        issues.push({ path: ["authHosts"], message: "expected array of host strings" });
      if (issues.length) return { issues };
      return { value: { authUsers, realm, allowLoopbackNoAuth, logDecisions, forwardedHostHeader, authHosts } };
    },
  },
};

/**
 * True when the request's TCP source is a loopback address. Works on the
 * node:http IncomingMessage (`req.socket.remoteAddress`) and accepts an
 * explicit `remoteAddress` for tests.
 *
 * NOTE: with the tunnel topology (public domain → cloudflared/nginx on the
 * same box → dsh), EVERY browser request arrives at node:http as a
 * loopback source (127.0.0.1). A pure source-based exemption would let all
 * remote traffic through the gate, so `apply()` combines this with the
 * forwarded-host rule: a loopback request carrying `forwardedHostHeader`
 * naming one of `authHosts` is a remote caller and must authenticate.
 */
function isLoopbackSource(request) {
  const addr = request?.socket?.remoteAddress ?? request?.remoteAddress;
  if (typeof addr !== "string") return false;
  if (addr === "::1" || addr === "127.0.0.1") return true;
  if (/^127\./.test(addr)) return true;
  return false;
}

/** Parse one `Authorization` header value into { user, password } or null. */
function parseBasicAuth(headerValue) {
  if (typeof headerValue !== "string") return null;
  const match = /^Basic\s+(.+)$/i.exec(headerValue);
  if (!match) return null;
  let decoded;
  try {
    decoded = Buffer.from(match[1].trim(), "base64").toString("utf8");
  } catch {
    return null;
  }
  const sep = decoded.indexOf(":");
  if (sep === -1) return null;
  return { user: decoded.slice(0, sep), password: decoded.slice(sep + 1) };
}

/** Constant-time compare of `sha256(salt + password)` against the stored hash. */
function hashMatches(salt, hashHex, password) {
  const computed = createHash("sha256").update(salt + password, "utf8").digest("hex");
  const a = Buffer.from(computed, "utf8");
  const b = Buffer.from(String(hashHex).toLowerCase(), "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Read one request header from node:http or fetch-shaped headers. */
function readHeader(request, headerName) {
  const h = request?.headers;
  if (h instanceof Headers) return h.get(headerName) ?? h.get(headerName.toLowerCase());
  if (h === undefined || h === null || typeof h !== "object") return undefined;
  const lower = headerName.toLowerCase();
  for (const key of Object.keys(h)) {
    if (key.toLowerCase() === lower) {
      const value = h[key];
      return typeof value === "string" ? value : Array.isArray(value) ? value.join(", ") : undefined;
    }
  }
  return undefined;
}

function sha256Hex(salt, password) {
  return createHash("sha256").update(salt + password, "utf8").digest("hex");
}

/**
 * CLI helper: generate a `{ name, salt, hash }` entry for `authUsers`.
 * @param username - the account name.
 * @param password - the plaintext password (not stored anywhere).
 * @returns the entry to paste into the patch file's `authUsers` list.
 */
function makePasswordEntry(username, password) {
  const salt = randomBytes(16).toString("hex");
  return { name: username, salt, hash: sha256Hex(salt, password) };
}

/**
 * Mount the credential gate over the (remote-access-patched) connection
 * service.
 * @param ctx - plugin context carrying the `connection` service.
 * @param config - validated Config.
 */
function apply(ctx, config) {
  const { authUsers, realm, allowLoopbackNoAuth, logDecisions, forwardedHostHeader, authHosts } = config;

  /**
   * Does a loopback request carry the forwarded-host marker naming one of
   * `authHosts`? In the tunnel topology (public domain → cloudflared/nginx
   * on this box → dsh) every browser request arrives at node:http with
   * source 127.0.0.1; the proxy's forwarded-host header is what tells the
   * gate "this is really a remote visitor" and must be authenticated.
   */
  const isRemoteViaForwarded = (request) => {
    if (authHosts.length === 0) return false;
    const value = readHeader(request, forwardedHostHeader);
    if (typeof value !== "string") return false;
    let hostUrl;
    try {
      hostUrl = new URL(`http://${value.split(",")[0].trim()}`);
    } catch {
      return false;
    }
    const hostname = hostUrl.hostname;
    return authHosts.some((entry) => {
      if (entry.startsWith("*.")) {
        const suffix = entry.slice(2);
        return hostname === suffix || hostname.endsWith("." + suffix);
      }
      const [host, port] = entry.includes(":") ? entry.split(":") : [entry];
      if (hostname !== host) return false;
      return port !== undefined ? String(hostUrl.port) === port : true;
    });
  };

  /**
   * The gate itself: true when `request` may proceed. Loopback callers are
   * exempt UNLESS they carry the forwarded-host marker naming a configured
   * public host (the tunnel case); everyone else must present a valid Basic
   * credential matching one of `authUsers`.
   */
  const authorized = (request) => {
    if (allowLoopbackNoAuth && isLoopbackSource(request) && !isRemoteViaForwarded(request)) return true;
    const header = readHeader(request, "authorization");
    const parsed = parseBasicAuth(header);
    if (parsed === null) return false;
    for (const user of authUsers) {
      if (user.name === parsed.user && hashMatches(user.salt, user.hash, parsed.password)) return true;
    }
    return false;
  };

  const writeUnauthorized = (response) => {
    response.writeHead(401, {
      "www-authenticate": `Basic realm="${String(realm).replace(/"/g, "")}"`,
      "cache-control": "no-store",
      "content-type": "text/plain; charset=utf-8",
    });
    response.end("remote-auth: unauthorized\n");
  };

  /**
   * Mount the credential gate LATE, after every other plugin that wraps the
   * connection service has finished activating: we capture whatever
   * `requestRejection` / `authorizeIndex` the service currently exposes
   * (the inner fence chain) and wrap it. Mounting at apply-time is unsafe —
   * a peer plugin that activates later re-wraps the service and our gate
   * gets shadowed by its own-property assignment, so requests never reach
   * us (observed: no REQUEST-CHECK log lines, 200s for gated requests).
   */
  const mount = () => {
    const connection = ctx.get("connection");
    if (connection === undefined) {
      process.stderr.write(`[remote-auth] MOUNT-FAIL connection service not available yet\n`);
      setImmediate(mount);
      return;
    }
    const innerRejection = connection.requestRejection;
    const innerAuthorizeIndex = connection.authorizeIndex;
    const innerProtoRejection = connection.constructor?.prototype?.requestRejection;
    const innerProtoIndex = connection.constructor?.prototype?.authorizeIndex;
    process.stderr.write(
      `[remote-auth] MOUNT-TRACE hasOwnRej=${Object.prototype.hasOwnProperty.call(connection, "requestRejection")} innerRejName=${innerRejection?.name ?? "?"} innerIdxName=${innerAuthorizeIndex?.name ?? "?"} ctorName=${connection.constructor?.name ?? "?"} protoRejName=${innerProtoRejection?.name ?? "?"} protoIdxName=${innerProtoIndex?.name ?? "?"}\n`
    );

    const gateRejection = (request) => {
      if (!authorized(request)) {
        if (logDecisions) process.stderr.write(`[remote-auth] GATE-DENY(no-cred) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"}\n`);
        return 401;
      }
      const inner = innerRejection === undefined ? undefined : innerRejection(request);
      if (logDecisions && inner !== undefined) {
        process.stderr.write(`[remote-auth] GATE-PASSED-BUT-INNER-DENIED innerStatus=${inner} src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"}\n`);
      }
      return inner;
    };
    const gateIndex = (request, response) => {
      if (!authorized(request)) {
        if (logDecisions) process.stderr.write(`[remote-auth] INDEX-DENY(no-cred) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"}\n`);
        writeUnauthorized(response);
        return false;
      }
      if (innerAuthorizeIndex === undefined) return true;
      const result = innerAuthorizeIndex(request, response);
      if (!result && logDecisions) {
        process.stderr.write(`[remote-auth] INDEX-PASSED-BUT-INNER-DENIED src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} url=${request?.url ?? "?"}\n`);
      }
      return result;
    };

    // Surface 1: the service instance (covers internal closures that hold
    // the raw `HostConnectionService` reference — dsh-client-connection's
    // /api route — and any `ctx.get("connection")` view of the same fiber).
    connection.requestRejection = (request) => {
      if (logDecisions) process.stderr.write(`[remote-auth] GATE host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} src=${request?.socket?.remoteAddress ?? "?"} path=${request?.url ?? "?"} ok=${authorized(request)}\n`);
      return gateRejection(request);
    };
    connection.authorizeIndex = (request, response) => {
      if (logDecisions) process.stderr.write(`[remote-auth] INDEX-GATE host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} src=${request?.socket?.remoteAddress ?? "?"} url=${request?.url ?? "?"} ok=${authorized(request)}\n`);
      return gateIndex(request, response);
    };

    // Surface 2: the instance prototype (covers `this.requestRejection(...)`
    // style calls where an own property on the instance would otherwise
    // shadow the chain — and protects against a peer activating even later
    // that only wraps `this` methods).
    const ctorProto = connection.constructor?.prototype;
    if (ctorProto && !ctorProto.__remoteAuthWrapped) {
      ctorProto.__remoteAuthWrapped = true;
      ctorProto.requestRejection = function requestRejection(request) {
        if (logDecisions) process.stderr.write(`[remote-auth] GATE(via-proto) host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} src=${request?.socket?.remoteAddress ?? "?"} path=${request?.url ?? "?"} ok=${authorized(request)}\n`);
        if (!authorized(request)) {
          if (logDecisions) process.stderr.write(`[remote-auth] GATE-DENY(via-proto, no-cred) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"}\n`);
          return 401;
        }
        const inner = innerProtoRejection === undefined ? undefined : innerProtoRejection.call(this, request);
        if (logDecisions && inner !== undefined) {
          process.stderr.write(`[remote-auth] GATE-PASSED-BUT-INNER-DENIED(via-proto) innerStatus=${inner} src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"}\n`);
        }
        return inner;
      };
      ctorProto.authorizeIndex = function authorizeIndex(request, response) {
        if (logDecisions) process.stderr.write(`[remote-auth] INDEX-GATE(via-proto) host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} src=${request?.socket?.remoteAddress ?? "?"} url=${request?.url ?? "?"} ok=${authorized(request)}\n`);
        if (!authorized(request)) {
          if (logDecisions) process.stderr.write(`[remote-auth] INDEX-DENY(via-proto, no-cred) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"}\n`);
          writeUnauthorized(response);
          return false;
        }
        const result = innerProtoIndex === undefined ? true : innerProtoIndex.call(this, request, response);
        if (!result && logDecisions) {
          process.stderr.write(`[remote-auth] INDEX-PASSED-BUT-INNER-DENIED(via-proto) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} url=${request?.url ?? "?"}\n`);
        }
        return result;
      };
      // Own-instance shadowing: when THIS instance already carries its own
      // `requestRejection` / `authorizeIndex` (a peer wrapped it earlier),
      // `this.method(...)` resolves the own property and the prototype gate
      // would be bypassed — so mirror the gate on the instance too, chaining
      // to the instance's current (gate-inclusive) own methods.
      if (Object.prototype.hasOwnProperty.call(connection, "requestRejection")) {
        const ownRej = connection.requestRejection;
        connection.requestRejection = (request) => {
          if (logDecisions) process.stderr.write(`[remote-auth] GATE(via-own) host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} src=${request?.socket?.remoteAddress ?? "?"} path=${request?.url ?? "?"} ok=${authorized(request)}\n`);
          if (!authorized(request)) {
            if (logDecisions) process.stderr.write(`[remote-auth] GATE-DENY(via-own, no-cred) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"}\n`);
            return 401;
          }
          const inner = ownRej(request);
          if (logDecisions && inner !== undefined) {
            process.stderr.write(`[remote-auth] GATE-PASSED-BUT-INNER-DENIED(via-own) innerStatus=${inner} src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"}\n`);
          }
          return inner;
        };
      }
      if (Object.prototype.hasOwnProperty.call(connection, "authorizeIndex")) {
        const ownIdx = connection.authorizeIndex;
        connection.authorizeIndex = (request, response) => {
          if (logDecisions) process.stderr.write(`[remote-auth] INDEX-GATE(via-own) host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} src=${request?.socket?.remoteAddress ?? "?"} url=${request?.url ?? "?"} ok=${authorized(request)}\n`);
          if (!authorized(request)) {
            if (logDecisions) process.stderr.write(`[remote-auth] INDEX-DENY(via-own, no-cred) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"}\n`);
            writeUnauthorized(response);
            return false;
          }
          const result = ownIdx(request, response);
          if (!result && logDecisions) {
            process.stderr.write(`[remote-auth] INDEX-PASSED-BUT-INNER-DENIED(via-own) src=${request?.socket?.remoteAddress ?? "?"} host=${readHeader(request, "host") ?? "?"} fhost=${readHeader(request, forwardedHostHeader) ?? "-"} url=${request?.url ?? "?"}\n`);
          }
          return result;
        };
      }
    }

    process.stderr.write(
      `[remote-auth] MOUNT-OK hasOwnRej=${Object.prototype.hasOwnProperty.call(connection, "requestRejection")} innerRejName=${innerRejection?.name ?? "?"} innerIdxName=${innerAuthorizeIndex?.name ?? "?"} protoWrapped=${!!ctorProto?.__remoteAuthWrapped}\n`
    );
  };
  setImmediate(mount);

  if (logDecisions) {
    ctx.logger?.info?.(
      `remote-auth: credential gate deferred until post-activation; ${authUsers.length} user(s); loopback ${allowLoopbackNoAuth ? "exempt" : "gated"}${authHosts.length ? ` (forwarded host ${forwardedHostHeader} in [${authHosts.join(", ")}] counts as remote)` : ""}; realm="${realm}"`
    );
    process.stderr.write(`[remote-auth] APPLY-OK users=${authUsers.map((u) => u.name).join(",")} authHosts=[${authHosts.join(",")}] realm=${realm}\n`);
  }
}

export { Config, apply, inject, name, isLoopbackSource, parseBasicAuth, hashMatches, sha256Hex, makePasswordEntry, readHeader };
export default { name, inject, Config, apply };
