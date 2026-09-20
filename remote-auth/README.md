# @dsh-ext/remote-auth

A dsh web plugin that adds **account/password verification** to remote-domain
access, layered on top of `@dsh-ext/remote-access`.

## What problem it solves

`remote-access` removes the launch-token requirement so a browser can reach
the GUI through a domain (e.g. `gateway.example`). That is a **reachability**
feature: anyone who can reach the port with a trusted `Host` header operates
the harness. `remote-auth` adds back a **credential** gate:

- **loopback callers** (`127.x`, `::1`) stay token-free — local use is
  unchanged;
- **every other caller** (including the reverse-proxy/tunnel source) must
  present valid Basic-auth credentials, else `401 + WWW-Authenticate:
  Basic` — the browser's native username/password dialog;
- the credential check runs **before** the inner `remote-access` fence, so a
  valid credential cannot bypass the Host/Origin fence either.

## Security model

- Passwords are **never stored in the patch file or logs** — only
  `sha256(salt + password)` hex digests, compared in constant time.
- Generate an entry with the bundled tool:

  ```sh
  node make-password.mjs --user <username>
  # prompts twice for the password and prints:
  #   - name: "<username>"
  #     salt: <hex>
  #     hash: <hex>
  ```

- A valid credential grants **full operation** of this harness, and (when
  `remote-access`' `injectTransport` is enabled) write access to the host's
  settings/credential files. Enable it only for a domain you intend to share.
- The loopback exemption is deliberate: the box itself (and co-located
  processes) keep token-free access. If you also want to gate local traffic,
  set `allowLoopbackNoAuth: false`.

## Install

1. Add the dependency to the web profile (`link:` form, like
   `remote-access`):

   ```sh
   cd ~/.dsh/profiles/web
   node /home/<you>/.local/share/pnpm/bin/dsh plugin add ../plugin-auth  # or pnpm add ../plugin-auth
   ```

   (a `file:`/`link:` dependency in `package.json` is what the dsh plugin
   installer writes for local plugins.)

2. Append the mount row to `~/.dsh/profiles/web/cordis.patch.yml` **after**
   the `remote-access` row (order matters: `remote-auth` must activate later
   so it wraps the already-patched `connection` methods):

   ```yaml
   - insert:
       - id: remote-auth
         name: '@dsh-ext/remote-auth'
         inject: [connection]
         config:
           realm: dsh
           allowLoopbackNoAuth: true
           logDecisions: false
           authUsers:
             - name: '<username>'
               salt: <from make-password.mjs>
               hash: <from make-password.mjs>
   ```

3. Restart the web profile. First visit to the domain prompts for the
   account; correct credentials load the GUI, wrong ones stay at 401.

## Config

| key | default | meaning |
| --- | --- | --- |
| `authUsers` | required | array of `{ name, salt, hash }`; `hash = sha256(salt + password)` hex |
| `allowLoopbackNoAuth` | `true` | skip the gate for `127/8` / `::1` sources |
| `realm` | `"dsh"` | `WWW-Authenticate` realm shown in the browser dialog |
| `logDecisions` | `false` | one activation summary line (never the credentials) |

## Tests

```sh
node test/apply.test.mjs
```
