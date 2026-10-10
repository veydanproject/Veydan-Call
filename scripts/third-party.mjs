#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Veydan Project
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.1

// THIRD-PARTY-LICENSES.md of VCall: every crate of Cargo.lock the node is
// built from, with its version and licence, read from cargo.
// The binaries of a release and the image carry it next to LICENSE.
//
//   node scripts/third-party.mjs          (make third-party)
//
// Run it after Cargo.lock changes; the export checks that the file lists
// every package of the lock at its version.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(DIR, 'THIRD-PARTY-LICENSES.md');

const meta = JSON.parse(execFileSync('cargo', ['metadata', '--format-version', '1', '--locked', '--manifest-path', path.join(DIR, 'Cargo.toml')], {
  encoding: 'utf8', maxBuffer: 256 << 20,
}));
const crates = meta.packages
  .filter((p) => p.source !== null)
  .map((p) => ({ name: p.name, version: p.version, license: (p.license ?? p.license_file ?? 'see the crate').replace(/\s*\/\s*/g, ' OR ') }))
  .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version, undefined, { numeric: true }));

const counts = new Map();
for (const c of crates) counts.set(c.license, (counts.get(c.license) ?? 0) + 1);
const summary = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

const text = `# Third-Party Licenses

VCall is built from the open-source crates below. This file goes with every
copy of the node: next to the binary of each release and as
\`/THIRD-PARTY-LICENSES.md\` in the image. It lists every crate of
\`Cargo.lock\`, for every system the node is built for, with its licence.

- **Rust crates:** ${crates.length}

## License summary

| License | Count |
|---|---:|
${summary.map(([license, n]) => `| ${license} | ${n} |`).join('\n')}

## Crates

| Crate | Version | License |
|---|---|---|
${crates.map((c) => `| ${c.name} | ${c.version} | ${c.license} |`).join('\n')}

## License texts

- MIT — https://opensource.org/license/mit
- Apache-2.0 — https://www.apache.org/licenses/LICENSE-2.0
- BSD-2-Clause — https://opensource.org/license/bsd-2-clause
- BSD-3-Clause — https://opensource.org/license/bsd-3-clause
- ISC — https://opensource.org/license/isc-license-txt
- MPL-2.0 — https://www.mozilla.org/en-US/MPL/2.0/
- Zlib — https://opensource.org/license/zlib
- Unicode-3.0 — https://www.unicode.org/license.txt
- CC0-1.0 — https://creativecommons.org/publicdomain/zero/1.0/legalcode
- BSL-1.0 — https://www.boost.org/LICENSE_1_0.txt
- CDLA-Permissive-2.0 — https://cdla.dev/permissive-2-0/
- Unlicense — https://unlicense.org/

The text of each crate's licence, with its copyright notice, is in the
crate's own source (\`cargo vendor\`, or the crate on crates.io).
`;
fs.writeFileSync(OUT, text);
console.log(`${path.relative(process.cwd(), OUT) || OUT}: ${crates.length} crates`);
