# @dsh-ext/remote-access

A local [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh) web plugin: serve the
browser GUI through a **remote domain** without a **launch token**.

## What problem it solves

The stock web profile (`dsh --profile web`):

1. binds the web server to `127.0.0.1` — the `--host 0.0.0.0` flag is
   *refused at startup*, and the `webserver` row's config schema only
   accepts the two literals `127.0.0.1` / `0.0.0.0`, so a remote domain can
   never be a *literal* bind and needs a patch layer to reach it;
2. gates every browser request through two layers in
   `@deepseek-ai/dsh-client-connection`:
   - **Host/Origin fence** → 403 when the `Host` header is not loopback, a
     LAN IP literal derived from the bind, or a declared `trustedHosts`
     authority; cross-site browser requests are refused;
   - **browser authentication** → 401 without the `?token=` launch token
     that mints a persistent signed cookie. This layer guards `index.html`,
     the `/api` HTTP RPC, and the `/api/remote.mux` WebSocket upgrade.

Result: today, a remote domain (`https://dsh.example.com` → this box) can
reach the port only after you hand the browser the token URL that `dsh web`
prints.

This plugin changes both facts:

- `patches/cordis.patch.yml` re-targets the `webserver` row to
  `host: 0.0.0.0` (the schema allows the literal; the *runtime* is what
  binds it), and mounts this plugin on the `connection` service;
- when the bind is `0.0.0.0`, the web-app's `resolveLanTrust` puts every
  non-internal IPv4 of the box into `ctx.webRuntime.trustedHosts`, so LAN
  IP access works with zero extra config;
- the plugin's `apply()` swaps `connection.requestRejection` and
  `connection.authorizeIndex` for **fence-only** versions: the Host/Origin
  fence still runs (against `allowedHosts` + loopback + LAN IPs, plus the
  retained cross-site markers), but the 401 browser-authentication
  requirement is dropped. When `logDecisions: true`, a one-line boot
  summary of the active trust set is logged (default `false` — quiet).

A browser that navigates directly to `http://<domain>:3080` (or
`http://<lan-ip>:3080`) loads the GUI and talks to `/api` **with no token
in the URL**. The stock `?token=` URLs keep working.

## SECURITY

This deliberately removes the only credential gate on a remote deployment.
Anyone who can reach the port and send a matching `Host` header operates
this harness. Use it only behind a tunnel or on a trusted network. The
cross-site browser markers are retained, so a malicious *page* cannot drive
this API cross-origin — but an attacker who *owns* a trusted domain (or a
LAN IP) has full access.

## Layout

```
index.js                  cordis plugin (host half): the fence-only mount
patches/cordis.patch.yml  the two patch entries (webserver bind + plugin mount)
test/                     node --test-free assertion suites (node test/*.mjs)
```

## Development

Plain Node ESM, no build step. Dependencies: none (the optional
`@deepseek-ai/schemastery` import falls back to a bundled Standard-Schema
mini-validator, so the module loads even without the dsh store).

```sh
node test/match.test.mjs   # authority matching + browser-marker semantics
node test/apply.test.mjs   # full apply() mount against a mock connection
node test/patch.test.mjs   # patch file structure (js-yaml when available)
```

## Installing into a dsh profile (deferred)

Not performed by this repository. When ready:

1. Make the package resolvable from the web profile — a `file:` dependency
   is the normal shape for a local plugin:

   ```sh
   dsh plugin --profile web add /path/to/this/dir
   ```

2. Apply the patch entries — either append them to the profile's user layer
   (`~/.dsh/profiles/web/cordis.patch.yml`) or boot with the overlay:

   ```sh
   dsh --profile web --patch /path/to/this/dir/patches/cordis.patch.yml
   ```

3. Edit the `remote-access` row's `allowedHosts` to every domain that should
   reach this instance (bare `host` = any port; `host:port` = exact;
   `*.suffix` = one-or-more-label wildcard), then restart `dsh web`.

## Behavior matrix (patched fence)

| request shape                                        | decision |
| ---------------------------------------------------- | -------- |
| direct navigation, `Host: your.domain.example` (allowed) | accepted, no token |
| `Host: <lan-ip>` from the bind-time snapshot         | accepted, no token |
| `Host: 127.0.0.1` / `localhost` (loopback allowed)   | accepted, no token |
| `Host: anything-else`                                 | 403 |
| `Sec-Fetch-Site: cross-site` on any host              | 403 |
| `Origin` not matching `Host`                           | 403 |
| stock `?token=` URL (cookie still valid)               | accepted (regression-safe) |
