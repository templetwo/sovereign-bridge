#!/usr/bin/env node
'use strict';

// Watchman preview redactor — a thin stdin->stdout shim over t2helix's
// lib/secrets.js scrub(). The pattern table is LOADED from the t2helix tree
// (T2HELIX_ROOT, default ~/t2helix), never copied here, so the watchman's eyes
// can never drift from the helix write-path redaction.
//
// Contract with sanitizer.py (fail-closed on every edge):
//   exit 0  + redacted text on stdout   -> usable
//   exit != 0 (any reason)              -> caller records 'sanitizer-failed'
//                                          and ships metadata only
// This script NEVER writes the raw input to stdout on a failure path.

const path = require('path');
const os = require('os');

const root = process.env.T2HELIX_ROOT || path.join(os.homedir(), 't2helix');

let secrets;
try {
  secrets = require(path.join(root, 'lib', 'secrets.js'));
} catch (err) {
  process.stderr.write(`sanitize_preview: cannot load t2helix secrets from ${root}: ${err.message}\n`);
  process.exit(3);
}

const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('error', () => process.exit(5));
process.stdin.on('end', () => {
  let out;
  try {
    // scrub() = pattern redaction + fixed-point backstop: if a second pass
    // would still change the string, the WHOLE field is coarse-masked rather
    // than a residual secret persisted. Same invariant the helix chronicle
    // write path relies on.
    out = secrets.scrub(Buffer.concat(chunks).toString('utf8'));
  } catch (err) {
    process.stderr.write(`sanitize_preview: scrub threw: ${err.message}\n`);
    process.exit(4); // fail closed — emit nothing
  }
  process.stdout.write(out == null ? '' : String(out));
  process.exit(0);
});
