#!/usr/bin/env node
'use strict';

// Watchman preview redactor — a thin stdin->stdout shim over t2helix's
// lib/secrets.js scrub(). The pattern table is LOADED from the t2helix tree
// (T2HELIX_ROOT, default ~/t2helix), never copied here, so the watchman's eyes
// can never drift from the helix write-path redaction.
//
// TWO MODES:
//   (default)  stdin is raw text            -> stdout is scrub(text)
//   --json     stdin is a JSON array of     -> stdout is a JSON array of the
//              strings                         same length, each scrub()ed
//              INDEPENDENTLY
//
// The --json mode exists for metadata sanitization (leak-hunt finding 1): every
// string metadata field runs through the SAME redactor as previews, and each
// field must be scrubbed on its own. scrub()'s fixed-point backstop coarse-masks
// a WHOLE field when a residual would survive, so batching fields into one
// string would let one poisoned field erase all the others. One process, N
// independent scrubs — same redactor, no cross-field contamination, and no
// per-field process-spawn cost.
//
// Contract with sanitizer.py (fail-closed on every edge):
//   exit 0  + redacted text / JSON array on stdout   -> usable
//   exit != 0 (any reason)                           -> caller records
//                                                       'sanitizer-failed' and
//                                                       ships metadata only
// This script NEVER writes the raw input to stdout on a failure path.

const path = require('path');
const os = require('os');

const jsonMode = process.argv.includes('--json');
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
  const input = Buffer.concat(chunks).toString('utf8');
  let out;
  try {
    // scrub() = pattern redaction + fixed-point backstop: if a second pass
    // would still change the string, the WHOLE field is coarse-masked rather
    // than a residual secret persisted. Same invariant the helix chronicle
    // write path relies on.
    if (jsonMode) {
      const values = JSON.parse(input);
      if (!Array.isArray(values)) {
        process.stderr.write('sanitize_preview: --json input is not an array\n');
        process.exit(6); // fail closed — emit nothing
      }
      const scrubbed = values.map((v) => {
        const s = secrets.scrub(String(v));
        return s == null ? '' : String(s);
      });
      out = JSON.stringify(scrubbed);
    } else {
      out = secrets.scrub(input);
    }
  } catch (err) {
    process.stderr.write(`sanitize_preview: scrub threw: ${err.message}\n`);
    process.exit(4); // fail closed — emit nothing
  }
  process.stdout.write(out == null ? '' : String(out));
  process.exit(0);
});
