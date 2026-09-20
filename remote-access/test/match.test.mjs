/**
 * @dsh-ext/remote-access — unit smoke test for the authority-matching core.
 *
 * Run:  node test/match.test.mjs
 *
 * Verifies the same semantics the patched `connection.requestRejection` and
 * `connection.authorizeIndex` use (extracted here, identical to index.js) so
 * the trust rules can be exercised without the full dsh runtime:
 *
 *   - loopback classification (localhost / ::1 / 127.x, no 126.x / 128.x);
 *   - exact host, host:port, and `*.suffix` wildcard matching;
 *   - the cross-site browser-marker rules the fence retains.
 */

import assert from "node:assert/strict";

/* ── copies of the plugin's core predicates (kept in lockstep with index.js) ── */

function isLoopbackHostname(hostname) {
  if (hostname === "localhost" || hostname === "[::1]") return true;
  const parts = hostname.split(".");
  return (
    parts.length === 4 &&
    parts[0] === "127" &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  );
}

function parseAuthority(authority) {
  try {
    const url = new URL(`http://${authority}`);
    if (url.pathname !== "/") return undefined;
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

function matchesAllowedStrict(hostUrl, allowedHosts) {
  for (const entry of allowedHosts) {
    const base = entry.startsWith("*.") ? entry.slice(2) : entry;
    if (parseAuthority(base) === undefined) {
      throw new Error(`strict: ${JSON.stringify(entry)} is not a valid host or wildcard authority`);
    }
  }
  return matchesAllowed(hostUrl, allowedHosts);
}

function matchesAllowed(hostUrl, allowedHosts) {
  return allowedHosts.some((entry) => {
    if (entry.startsWith("*.")) {
      const suffix = entry.slice(2).toLowerCase();
      const hostname = hostUrl.hostname.toLowerCase();
      return hostname === suffix || hostname.endsWith(`.${suffix}`);
    }
    const entryUrl = parseAuthority(entry);
    if (entryUrl === undefined) return false;
    return entryUrl.port !== ""
      ? hostUrl.host === `${entryUrl.hostname}:${entryUrl.port}`
      : hostUrl.hostname === entryUrl.hostname;
  });
}

/** The plugin's shared Host-fence decision given a trust-set shape. */
function hostTrusted(config, hostHeader, lanHosts = []) {
  let hostUrl;
  try {
    hostUrl = new URL(`http://${hostHeader}`);
  } catch {
    return false;
  }
  if (config.allowLoopback && isLoopbackHostname(hostUrl.hostname)) return true;
  if (matchesAllowed(hostUrl, config.allowedHosts)) return true;
  if (config.allowLan && lanHosts.length > 0 && matchesAllowed(hostUrl, lanHosts)) return true;
  return false;
}

/* ── cases ── */

const config = {
  allowedHosts: ["gateway.example", "harness.internal:8443", "*.corp.example.com"],
  allowLoopback: true,
  allowLan: true,
};
const lan = ["192.168.1.20", "10.0.0.5"];

// loopback classification
assert.equal(isLoopbackHostname("localhost"), true);
assert.equal(isLoopbackHostname("[::1]"), true);
assert.equal(isLoopbackHostname("127.0.0.1"), true);
assert.equal(isLoopbackHostname("127.8.9.10"), true);
assert.equal(isLoopbackHostname("126.0.0.1"), false);
assert.equal(isLoopbackHostname("128.0.0.1"), false);
assert.equal(isLoopbackHostname("0.0.0.0"), false);
assert.equal(isLoopbackHostname("192.168.1.20"), false);

// exact host matches any port
assert.equal(hostTrusted(config, "gateway.example"), true);
assert.equal(hostTrusted(config, "Gateway.example:3080"), true); // case-insensitive
assert.equal(hostTrusted(config, "evil.gateway.example"), false); // sibling label must not match
assert.equal(hostTrusted(config, "example.com"), false); // a bare host not in the list is not implied

// host:port entries match that exact authority only
assert.equal(hostTrusted(config, "harness.internal:8443"), true);
assert.equal(hostTrusted(config, "harness.internal:80"), false);
assert.equal(hostTrusted(config, "harness.internal"), false);

// wildcard: suffix itself plus one or more leading labels
assert.equal(hostTrusted(config, "corp.example.com"), true);
assert.equal(hostTrusted(config, "a.corp.example.com"), true);
assert.equal(hostTrusted(config, "a.b.corp.example.com"), true);
assert.equal(hostTrusted(config, "evilcorp.example.com"), false);
assert.equal(hostTrusted(config, "corp.example.com.evil.org"), false);

// LAN literals from the bind snapshot
assert.equal(hostTrusted(config, "192.168.1.20:3080", lan), true);
assert.equal(hostTrusted(config, "10.0.0.5", lan), true);
assert.equal(hostTrusted(config, "192.168.1.20", []), false);

// loopback stays trusted; disabling it removes that class
assert.equal(hostTrusted(config, "127.0.0.1:3080"), true);
assert.equal(hostTrusted({ ...config, allowLoopback: false }, "127.0.0.1:3080"), false);

// untrusted / unparsable Host
assert.equal(hostTrusted(config, "not a host at all !!"), false);
assert.equal(hostTrusted(config, ""), false);

// entry validation: user-configured entries must be strict bare
// host[:port] authorities (the plugin's apply() rejects them at boot —
// mirrored here), while the deployment-derived LAN snapshot stays lenient
// (skipped, never thrown on). The stock fence's exact-host spelling check
// is not reproduced: WHATWG hostnames are compared, so `0x7f.0.0.1`
// canonically means 127.0.0.1 here — an acceptable trade for a local
// deployment tool, documented in index.js.
assert.throws(() => matchesAllowedStrict(new URL("http://x"), ["harness.example/path"]));
assert.throws(() => matchesAllowedStrict(new URL("http://x"), ["*.not a domain !"]));
assert.throws(() => matchesAllowedStrict(new URL("http://x"), ["host:0x7f"]));
assert.doesNotThrow(() => matchesAllowed(new URL("http://1.2.3.4"), ["192.168.1.20", "weird..literal"]));

// parseAuthority port semantics (explicit :80/:443 count as explicit ports)
assert.equal(parseAuthority("h:80")?.port, "80");
assert.equal(parseAuthority("h:443")?.port, "443");
assert.equal(parseAuthority("h")?.port, "");

// ── browser-marker rules (retained by the patched fence) ──

function browserMarker(hostHeader, secFetchSite, origin) {
  if (secFetchSite === "cross-site") return "cross-site";
  if (origin === undefined) return undefined;
  if (hostHeader === undefined) return "origin";
  let o, h;
  try {
    o = new URL(origin);
    h = new URL(`http://${hostHeader}`);
  } catch {
    return "origin";
  }
  return o.host === h.host ? undefined : "origin";
}

assert.equal(browserMarker("gateway.example", undefined, undefined), undefined); // direct navigation
assert.equal(browserMarker("gateway.example:3080", "same-site", "http://gateway.example:3080"), undefined);
assert.equal(browserMarker("gateway.example", "cross-site", undefined), "cross-site");
assert.equal(browserMarker("gateway.example", undefined, "http://evil.org"), "origin");
assert.equal(browserMarker("gateway.example:3080", undefined, "http://gateway.example:3080/"), undefined);
// an explicit non-default port on Host is not the same authority as the
// bare hostname (WHATWG does not strip :3080 the way it strips :80)
assert.equal(browserMarker("gateway.example", undefined, "http://gateway.example:3080/"), "origin");

console.log("remote-access: all match/marker assertions passed");
