/**
 * @dsh-ext/remote-access
 *
 * dsh web plugin: serve the DeepSeek Harness Web GUI through a remote domain
 * without a launch token.
 *
 * ── What it does ─────────────────────────────────────────────────────────────
 *
 * The stock web profile binds to 127.0.0.1 and gates every browser request
 * through two layers in @deepseek-ai/dsh-client-connection:
 *
 *   1. Host/Origin fence  → 403 when Host is not loopback, a LAN IP literal
 *      derived from the bind, or a declared `trustedHosts` authority; a
 *      cross-site browser request (or an Origin that does not match the
 *      Host) is refused.
 *   2. Browser auth       → 401 without a launch token (?token=) that mints
 *      a persistent signed cookie. This layer guards index.html, the /api
 *      HTTP RPC, and the /api/remote.mux WebSocket upgrade.
 *
 * This plugin (together with the companion patch in `patches/`):
 *
 *   - re-targets the `webserver` row to `host: 0.0.0.0` so the port is
 *     reachable on the machine's network interfaces (the stock startup
 *     refuses the `--host 0.0.0.0` flag, and the webserver schema only
 *     accepts the two loopback/all-interfaces literals — a remote domain can
 *     never be a *literal*, so the bind must come from a patch layer);
 *   - when the bind is 0.0.0.0, the web-app's `resolveLanTrust` puts every
 *     non-internal IPv4 address of the box into `ctx.webRuntime.trustedHosts`,
 *     so LAN IP access works out of the box;
 *   - mounts this plugin on the `connection` service and replaces
 *     `requestRejection` / `authorizeIndex` with fence-only versions: the
 *     Host/Origin fence still runs (against `allowedHosts` + loopback + LAN
 *     IPs), but the browser-authentication 401 requirement is dropped.
 *
 * Result: a browser that navigates directly to `http://<domain>:<port>` (or
 * `http://<lan-ip>:<port>`) loads the GUI and talks to /api with no token
 * in the URL. The token-free flow does not mint cookies; the stock
 * `?token=` URLs still work.
 *
 * ── SECURITY ────────────────────────────────────────────────────────────────
 *
 * This deliberately removes the only credential gate on a remote deployment.
 * Anyone who can reach the port and send a matching `Host` header operates
 * this harness. Use it only behind a tunnel or on a trusted network. The
 * cross-site browser markers are retained, so a malicious page cannot
 * drive this API cross-origin.
 *
 * ── Layout ──────────────────────────────────────────────────────────────────
 *
 *   index.js                     the cordis plugin (host half only)
 *   patches/cordis.patch.yml     the patch entries to append to the profile's
 *                                user patch layer (webserver bind + mount)
 *
 * ── Installation ────────────────────────────────────────────────────────────
 *
 * 1. Make the package resolvable from the web profile (it is a local
 *    development plugin, so a `file:` dependency is the normal shape):
 *
 *       # in ~/.dsh/profiles/web/package.json
 *       "dependencies": { "@dsh-ext/remote-access": "file:/path/to/this/dir" }
 *
 *       dsh plugin --profile web add /path/to/this/dir   # runs pnpm add
 *
 * 2. Append the entries from `patches/cordis.patch.yml` to the profile's
 *    user patch layer (~/.dsh/profiles/web/cordis.patch.yml) — or pass the
 *    file as a `--patch` overlay at boot:
 *
 *       dsh --profile web --patch /path/to/this/dir/patches/cordis.patch.yml
 *
 * 3. Restart the web profile. Open the printed URL, or
 *    `http://<domain>:<port>` / `http://<lan-ip>:<port>` directly.
 *
 * Edit the `remote-access` row's `allowedHosts` to list every domain that
 * should reach the instance (bare `host` matches any port; `host:port` is
 * exact; `*.suffix` is a one-or-more-label wildcard).
 */

/* The stock plugin imports zod through @deepseek-ai/schemastery. In a local
 * development profile that package may not be installed, so fall back to a
 * minimal schema that reproduces exactly the Config shape below — and that
 * implements the Standard Schema (`~standard`) interface the cordis runtime
 * uses for validation (`Config["~standard"].validate(config)`), with the
 * same `.default()` / `.min()` builder surface. */
let z;
try {
  z = (await import("@deepseek-ai/schemastery")).default;
} catch {
  const validateIssues = (issues) =>
    issues.length ? { issues } : undefined;

  const string = () => {
    const base = {
      ["~standard"]: {
        validate(input) {
          if (typeof input !== "string" || input.length < 1)
            return { issues: [{ message: "expected non-empty string" }] };
          return { value: input };
        },
      },
    };
    base.min = (n) => ({
      ...base,
      ["~standard"]: {
        validate(input) {
          if (typeof input !== "string" || input.length < n)
            return { issues: [{ message: `expected string of length >= ${n}` }] };
          return { value: input };
        },
      },
    });
    return base;
  };

  const array = (item) => {
    const base = {
      ["~standard"]: {
        validate(input) {
          if (!Array.isArray(input)) return { issues: [{ message: "expected array" }] };
          const issues = [];
          const values = [];
          input.forEach((value, index) => {
            const result = item["~standard"].validate(value);
            if ("issues" in result && result.issues?.length)
              issues.push(...result.issues.map((i) => ({ ...i, path: [...(i.path ?? []), index] })));
            else if ("value" in result) values.push(result.value);
            else values.push(value);
          });
          return validateIssues(issues) ?? { value: values };
        },
      },
    };
    base.default = (dflt) => ({ ...base, default: dflt });
    return base;
  };

  const boolean = () => {
    const base = {
      ["~standard"]: {
        validate(input) {
          if (typeof input !== "boolean") return { issues: [{ message: "expected boolean" }] };
          return { value: input };
        },
      },
    };
    base.default = (dflt) => ({ ...base, default: dflt });
    return base;
  };

  const object = (spec) => {
    const schema = {
      ["~standard"]: {
        validate(input) {
          const out = {};
          const issues = [];
          for (const [key, field] of Object.entries(spec)) {
            const hasKey = input !== undefined && key in input;
            if (hasKey) {
              const result = field["~standard"].validate(input[key]);
              if ("issues" in result && result.issues?.length)
                issues.push(...result.issues.map((i) => ({ ...i, path: [...(i.path ?? []), key] })));
              else if ("value" in result) out[key] = result.value;
              else out[key] = input[key];
            } else if (field.default !== undefined) {
              out[key] = field.default;
            }
          }
          return validateIssues(issues) ?? { value: out };
        },
      },
    };
    return schema;
  };

  z = { object, array, string, boolean };
}

/** Stable Cordis plugin name. */
const name = "remote-access";

/** The `connection` service must exist (it is mounted by the web bundle). */
const inject = ["connection"];

const Authority = z.string().min(1);

const Config = z.object({
  /**
   * Non-loopback authorities browsers may present as `Host` (bare `host`
   * matches any port; `host:port` matches that exact authority;
   * `*.suffix` matches the suffix itself and one or more leading labels).
   * Empty = remote domains are refused (loopback still works).
   */
  allowedHosts: z.array(Authority).default([]),
  /** Keep loopback authorities (localhost, 127/8, ::1) trusted. */
  allowLoopback: z.boolean().default(true),
  /**
   * Also trust the LAN IP literals the web-app derives when the server
   * binds 0.0.0.0 (the stock `ctx.webRuntime.trustedHosts`), so browsers
   * can use `http://<lan-ip>:<port>` directly.
   */
  allowLan: z.boolean().default(true),
  /**
   * CIDR ranges of trusted TCP source addresses (the `req.socket
   * .remoteAddress` of node:http requests). A request whose source is in
   * one of these ranges is trusted for ANY `Host` header — this is the
   * proxy-trust path: a reverse tunnel / CDN that terminates TLS and
   * forwards to the loopback or a LAN IP may send its own upstream Host
   * (not the original public domain), and matching that Host against
   * `allowedHosts` would 403. Trusting the source IP instead is sound
   * because an attacker cannot forge the TCP source of a request the
   * proxy made.
   *
   * IPv4 CIDR only, plus the literals `::1` / `localhost`. Set
   * `["0.0.0.0/0"]` to trust every source (fully open — only do this
   * when the port is reachable solely through your own tunnel).
   * Defaults to loopback + RFC1918 private ranges.
   */
  trustedClientNets: z.array(z.string()).default([
    "127.0.0.1/32",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
  ]),
  /** Log a one-line summary of the active trust set at activation. */
  logDecisions: z.boolean().default(false),
  /**
   * Inject `globalThis.__DSH_TRANSPORT__ = { ownsHost: true }` into the
   * served index.html so the browser treats this page as the owning host.
   * `dsh-client-connection` computes
   * `isLoopback = transport?.ownsHost === true || isLoopbackHostname(hostname)`
   * — a public domain (e.g. your-domain.example behind a tunnel) is not
   * loopback, so the whole settings/credentials surface degrades to
   * in-memory persistence ("settings are unavailable in this browser").
   * With `ownsHost: true` injected, a trusted remote domain gets the same
   * host-persistence behaviour as a loopback page. Only enable this when
   * the Host/source fence above already restricts who reaches the port —
   * it hands remote pages write access to the host's settings and
   * credential stores.
   */
  injectTransport: z.boolean().default(false),
});

/* ------------------------------------------------------------------------ *
 * Authority matching — a superset of the stock fence's canonical matching,
 * plus one-label wildcards. Mirrors the semantics documented in
 * @deepseek-ai/dsh-client-connection.
 * ------------------------------------------------------------------------ */

/** Whether a normalized URL hostname names the local loopback authority. */
function isLoopbackHostname(hostname) {
  if (hostname === "localhost" || hostname === "[::1]") return true;
  const parts = hostname.split(".");
  return (
    parts.length === 4 &&
    parts[0] === "127" &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  );
}

/** Parse a `host` or `host:port` string into WHATWG parts; undefined on failure. */
function parseAuthority(authority) {
  try {
    const url = new URL(`http://${authority}`);
    // A bare authority must round-trip to a root path; anything else (a
    // `host/path` typo, an embedded userinfo, stripped whitespace) is
    // rejected as a misconfiguration, matching the stock fence's rule.
    if (url.pathname !== "/") return undefined;
    // The stock fence judges explicit ports through both special schemes;
    // a `:80` or `:443` written on the entry counts as an explicit port.
    const explicitPort =
      url.port !== ""
        ? url.port
        : new URL(`https://${authority}`).port !== ""
          ? new URL(`https://${authority}`).port
          : "";
    return { hostname: url.hostname, port: explicitPort, host: url.host };
  } catch {
    return undefined;
  }
}

/**
 * Does a parsed Host authority match one configured entry? Entries are
 * validated by the caller (apply() rejects malformed configured entries at
 * boot); the LAN snapshot is deployment-derived, so an unparsable literal is
 * skipped rather than failing the request.
 */
function matchesAllowed(hostUrl, allowedHosts) {
  return allowedHosts.some((entry) => {
    if (entry.startsWith("*.")) {
      const suffix = entry.slice(2).toLowerCase();
      const hostname = hostUrl.hostname.toLowerCase();
      // `*.example.com` trusts example.com and any *.example.com, any port.
      return hostname === suffix || hostname.endsWith(`.${suffix}`);
    }
    const entryUrl = parseAuthority(entry);
    if (entryUrl === undefined) return false;
    // An entry with an explicit port matches that exact authority; a
    // port-less entry matches the hostname on any port.
    return entryUrl.port !== ""
      ? hostUrl.host === `${entryUrl.hostname}:${entryUrl.port}`
      : hostUrl.hostname === entryUrl.hostname;
  });
}

/** Read the deployment's LAN trust snapshot (provided by dsh-web-app at bind). */
function lanTrustHosts(ctx) {
  let runtime;
  try {
    runtime = ctx.get?.("webRuntime");
  } catch {
    runtime = undefined;
  }
  return Array.isArray(runtime?.trustedHosts) ? runtime.trustedHosts : [];
}

/* ------------------------------------------------------------------------ *
 * CIDR source-trust — trust a request by its TCP source address (the proxy
 * path) rather than by its Host header.
 * ------------------------------------------------------------------------ */

/** Parse one IPv4 CIDR into { base, mask } (32-bit unsigned); null on bad input. */
function parseIpcidr(cidr) {
  const slash = cidr.indexOf("/");
  const net = slash === -1 ? cidr : cidr.slice(0, slash);
  const bits = slash === -1 ? 32 : Number(cidr.slice(slash + 1));
  const octets = net.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const baseNum = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return { base: (baseNum & mask) >>> 0, mask };
}

/** IPv4 dotted-quad to 32-bit unsigned; null when not a valid IPv4 literal. */
function ip4ToNum(ip) {
  const octets = ip.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

/**
 * Compile the `trustedClientNets` list into a source-matcher. Recognizes
 * IPv4 CIDR, the `0.0.0.0/0` catch-all, and the loopback literals `::1` /
 * `localhost`. Unrecognized entries are ignored (they would have failed the
 * boot-time validation below).
 */
function compileClientNets(nets) {
  const cidrs = [];
  let any = false;
  let loopback = false;
  for (const entry of nets) {
    if (entry === "0.0.0.0/0") {
      any = true;
      continue;
    }
    if (entry === "::1" || entry === "localhost" || entry === "127.0.0.1/8" || entry === "127.0.0.1/32") {
      loopback = true;
      continue;
    }
    const parsed = parseIpcidr(entry);
    if (parsed !== null) cidrs.push(parsed);
  }
  return (remoteAddress) => {
    if (any) return true;
    if (typeof remoteAddress !== "string") return false;
    const addr = remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
    if (loopback && (addr === "::1" || addr === "localhost" || addr === "127.0.0.1" || addr.startsWith("127.")))
      return true;
    const num = ip4ToNum(addr);
    if (num === null) return false;
    return cidrs.some((c) => ((num & c.mask) >>> 0) === c.base);
  };
}

/* ------------------------------------------------------------------------ */

/**
 * Mount remote access over the active connection service.
 * @param ctx - plugin context carrying the `connection` service.
 * @param config - validated Config.
 */
function apply(ctx, config) {
  const connection = ctx.get("connection");
  if (connection === undefined) throw new Error("remote-access: connection service missing");

  const allowedHosts = config.allowedHosts ?? [];
  for (const entry of allowedHosts) {
    const base = entry.startsWith("*.") ? entry.slice(2) : entry;
    if (parseAuthority(base) === undefined) {
      throw new Error(`remote-access: allowedHosts entry ${JSON.stringify(entry)} is not a valid host or wildcard authority`);
    }
  }

  const trustedClientNets = config.trustedClientNets ?? [];
  for (const entry of trustedClientNets) {
    if (
      entry === "0.0.0.0/0" ||
      entry === "::1" ||
      entry === "localhost" ||
      entry === "127.0.0.1/8" ||
      entry === "127.0.0.1/32" ||
      parseIpcidr(entry) !== null
    )
      continue;
    throw new Error(
      `remote-access: trustedClientNets entry ${JSON.stringify(entry)} is not an IPv4 CIDR, "0.0.0.0/0", "::1", or "localhost"`
    );
  }
  const clientTrusted = compileClientNets(trustedClientNets);

  /** Read one header value from node:http or fetch-shaped headers. */
  const header = (request, n) => {
    const h = request?.headers;
    if (h instanceof Headers) return h.get(n);
    const value = h?.[n];
    return typeof value === "string" ? value : undefined;
  };

  /**
   * Shared trust decision: a request is trusted when EITHER its source
   * address is in `trustedClientNets` (the proxy path — any Host is
   * accepted from a trusted source) OR its `Host` header names one of the
   * allowed authorities (the direct-connection path).
   */
  const isTrusted = (request) => {
    const remoteAddress = request?.socket?.remoteAddress ?? request?.remoteAddress;
    if (remoteAddress !== undefined && clientTrusted(remoteAddress)) return true;
    const host = header(request, "host");
    if (host === undefined) return false;
    let hostUrl;
    try {
      hostUrl = new URL(`http://${host}`);
    } catch {
      return false;
    }
    if (config.allowLoopback && isLoopbackHostname(hostUrl.hostname)) return true;
    if (matchesAllowed(hostUrl, allowedHosts)) return true;
    if (config.allowLan) {
      const lan = lanTrustHosts(ctx);
      if (lan.length > 0 && matchesAllowed(hostUrl, lan)) return true;
    }
    return false;
  };

  /**
   * True when the request's TCP source is itself trusted via `trustedClientNets`
   * (the reverse-proxy path) — as opposed to being trusted only because its Host
   * is allow-listed. A trusted SOURCE means a vetted proxy terminated TLS and
   * did the browser's same-origin work, so proxy-distorted markers
   * (`sec-fetch-site: cross-site`, a forwarded foreign `Origin`) carry no
   * additional signal and must not reject the request. A request that is
   * trusted ONLY by Host (an untrusted source) still has its cross-site
   * markers enforced, so a foreign cross-site read to an allow-listed host is
   * not opened up.
   */
  const isTrustedSource = (request) => {
    const remoteAddress = request?.socket?.remoteAddress ?? request?.remoteAddress;
    return remoteAddress !== undefined && clientTrusted(remoteAddress);
  };

  /**
   * The stock fence's cross-site browser markers, retained: over plain HTTP a
   * cross-site image/navigation read is unmarked, so the Host fence is the
   * real defense — but a `sec-fetch-site: cross-site` request or a foreign
   * Origin must still be refused.
   *
   * `skipOrigin` / `skipFetchSite` (a trusted proxy SOURCE) suppress the
   * browser-marker checks: a reverse tunnel that terminated TLS already did
   * the browser's same-origin work, and the forwarded `Origin`/`Sec-Fetch-Site`
   * name the public domain while the backend's `Host` is the upstream
   * (e.g. 127.0.0.1) — comparing them 403s every same-origin browser request.
   */
  const browserMarker = (request, skipOrigin = false, skipFetchSite = false) => {
    if (!skipFetchSite && header(request, "sec-fetch-site") === "cross-site") return "cross-site";
    if (skipOrigin) return undefined;
    const origin = header(request, "origin");
    if (origin === undefined) return undefined;
    const hostHeader = header(request, "host");
    if (hostHeader === undefined) return "origin";
    let originUrl;
    try {
      originUrl = new URL(origin);
    } catch {
      return "origin";
    }
    let hostUrl;
    try {
      hostUrl = new URL(`http://${hostHeader}`);
    } catch {
      return "origin";
    }
    return originUrl.host === hostUrl.host ? undefined : "origin";
  };

  /**
   * Fence-only request rejection: keeps the source/Host 403 class, drops the
   * 401 browser-authentication requirement. The same-origin `Origin`
   * comparison is dropped for requests that pass through a trusted proxy
   * source (nginx/tunnel): the browser's Origin names the public domain
   * (https://your-domain.example) while the backend Host is the upstream
   * (your-domain.example without the port, or 127.0.0.1:3080 when the proxy
   * does not forward the Host header) — a scheme/port mismatch that is
   * specific to the proxy topology, not a cross-site attack. The retained
   * `sec-fetch-site: cross-site` marker still blocks a genuinely foreign
   * top-level context.
   */
  connection.requestRejection = (request) => {
    const trustedSource = isTrustedSource(request);
    const trustedHost = isTrusted(request);
    if (!trustedHost) {
      if (config.logDecisions)
        process.stderr.write(
          `[remote-access] REJ-DENY src=${request?.socket?.remoteAddress ?? "?"} host=${header(request, "host") ?? "?"} secfetchsite=${header(request, "sec-fetch-site") ?? "-"} path=${request?.url ?? "?"}\n`
        );
      return 403;
    }
    if (browserMarker(request, trustedHost, trustedSource) !== undefined) {
      if (config.logDecisions)
        process.stderr.write(
          `[remote-access] REJ-DENY(marker) src=${request?.socket?.remoteAddress ?? "?"} host=${header(request, "host") ?? "?"} marker=${browserMarker(request, trustedHost, trustedSource)}\n`
        );
      return 403;
    }
    return undefined;
  };

  /**
   * Index authentication that passes for trusted sources/hosts: no launch
   * token, no cookie, no 303 redirect — serve index.html directly.
   */
  connection.authorizeIndex = (request, response) => {
    const trustedSource = isTrustedSource(request);
    const trustedHost = isTrusted(request);
    if (trustedHost && browserMarker(request, trustedHost, trustedSource) === undefined) return true;
    if (config.logDecisions)
      process.stderr.write(
        `[remote-access] IDX-DENY src=${request?.socket?.remoteAddress ?? "?"} host=${header(request, "host") ?? "?"} origin=${header(request, "origin") ?? "-"} secfetchsite=${header(request, "sec-fetch-site") ?? "-"} url=${request?.url ?? "?"}\n`
      );
    response.writeHead(403, { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" });
    response.end("remote-access: untrusted source or host\n");
    return false;
  };

  /**
   * Host persistence for the browser: tell the served index.html that this
   * page owns its host, so `dsh-client-connection` computes
   * `isLoopback = true` and the settings/credentials surface stays on host
   * persistence even when the browser's `location.hostname` is a public
   * domain (behind a tunnel) rather than 127.0.0.1. The injection table is
   * gathered per index render via the `webserver/index-inject` emission; the
   * client entry awaits `__DSH_BOOT_READY__` before reading this global, so
   * a head-placed row is visible to the `dsh-client-connection` plugin.
   */
  if (config.injectTransport) {
    ctx.on?.("webserver/index-inject", (table) => {
      table.push({
        kind: "global",
        name: "__DSH_TRANSPORT__",
        value: { ownsHost: true },
      });
    });
    ctx.logger?.info?.(
      `remote-access: injecting __DSH_TRANSPORT__ { ownsHost: true } into index.html — remote pages keep host persistence`
    );
  }

  if (config.logDecisions) {
    const trust = [
      ...(config.allowLoopback ? ["loopback"] : []),
      ...allowedHosts,
      ...(config.allowLan ? [...lanTrustHosts(ctx), "(lan at bind time)"] : []),
      `(sources: ${trustedClientNets.join(", ")})`,
    ];
    ctx.logger?.info?.(`remote-access: browser authentication skipped; trusted hosts = ${trust.join(", ") || "(none)"}`);
  }
}

export { Config, apply, inject, name };
export default { name, inject, Config, apply };
