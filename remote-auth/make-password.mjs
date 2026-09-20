#!/usr/bin/env node
/**
 * @dsh-ext/remote-auth — password hash generator.
 *
 * Generates a `{ name, salt, hash }` entry for the plugin's `authUsers`
 * config. The plaintext password is read from the terminal (hidden input on
 * TTY) or a `--password` flag, and is never written to disk or the patch
 * file — only the salt and SHA-256 hash are emitted.
 *
 * Usage:
 *   node make-password.mjs --user <name>            # prompts for password
 *   node make-password.mjs --user <name> --password <pw>
 *
 * Output (YAML, paste under `authUsers:` in cordis.patch.yml):
 *   - name: <name>
 *     salt: <hex>
 *     hash: <hex>
 */

import { makePasswordEntry } from "./index.js";
import readline from "node:readline";

function parseArgs(argv) {
  const out = { user: null, password: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--user" || a === "-u") out.user = argv[++i];
    else if (a === "--password" || a === "-p") out.password = argv[++i];
    else if (a === "--help" || a === "-h") out.help = true;
  }
  return out;
}

async function promptPassword() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  const ask = (q) => new Promise((resolve) => rl.question(q, (a) => resolve(a)));
  const pw = await ask("Password (hidden): ");
  const pw2 = await ask("Confirm password: ");
  rl.close();
  if (pw.length === 0) {
    process.stderr.write("password must be non-empty\n");
    process.exit(1);
  }
  if (pw !== pw2) {
    process.stderr.write("passwords do not match\n");
    process.exit(1);
  }
  return pw;
}

const args = parseArgs(process.argv.slice(2));

if (args.help || args.user === null) {
  process.stdout.write(
    "Usage: node make-password.mjs --user <name> [--password <pw>]\n" +
      "  -u, --user <name>       account name (required)\n" +
      "  -p, --password <pw>     plaintext password (prompts when omitted)\n"
  );
  process.exit(args.help ? 0 : 1);
}

const password = args.password ?? (await promptPassword());
const entry = makePasswordEntry(args.user, password);

process.stdout.write(
  `# paste this entry under "authUsers:" in cordis.patch.yml\n` +
    `# (the plaintext password was for user "${args.user}"; it is not stored here)\n` +
    `- name: ${JSON.stringify(entry.name)}\n` +
    `  salt: ${entry.salt}\n` +
    `  hash: ${entry.hash}\n`
);
