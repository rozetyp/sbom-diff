// Unit tests for core.ts: the test-pack scenarios plus focused regression cases.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { loadCore, readSbom, FIXTURES, EXPECTED } from './load-core.mjs';

const core = loadCore();
const load = (file) => core.normalize(core.parseSBOMText(readSbom(file)));
const ids = (list) => list.map((c) => `${c.name}@${c.version}`).sort();
const changedIds = (list) => list.map((c) => `${c.from.name} ${c.from.version} → ${c.to.version} (${c.fields.join(', ')})`).sort();
const cdx = (components) => JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components });
const fromText = (text) => core.normalize(core.parseSBOMText(text));

const { scenarios } = JSON.parse(fs.readFileSync(EXPECTED, 'utf8'));

for (const s of scenarios) {
  test(`test pack: ${s.id}`, () => {
    if (s.error) {
      assert.throws(() => load(s.file), (err) => err instanceof core.SBOMFormatError && err.message.includes(s.error));
      return;
    }
    if (s.file) {
      const comps = load(s.file);
      assert.equal(comps.length, s.count, 'component count');
      if (s.unknownLicenses !== undefined) assert.equal(core.generateSummary(comps).unknownLicenses, s.unknownLicenses);
      for (const [preset, violators] of Object.entries(s.policies || {})) {
        const r = core.policyCheck(comps, core.POLICY_PRESETS[preset]);
        assert.deepEqual(ids(r.violations), [...violators].sort(), `policy ${preset}`);
        assert.equal(r.pass, violators.length === 0, `policy ${preset} pass flag`);
      }
      return;
    }
    const A = load(s.a);
    const B = load(s.b);
    assert.deepEqual([A.length, B.length], s.counts, 'component counts');
    const d = core.diff(A, B);
    assert.deepEqual(ids(d.added), [...s.added].sort(), 'added');
    assert.deepEqual(ids(d.removed), [...s.removed].sort(), 'removed');
    assert.deepEqual(changedIds(d.changed), [...s.changed].sort(), 'changed');
  });
}

test('every fixture file is covered by a scenario', () => {
  const used = new Set(scenarios.flatMap((s) => [s.file, s.a, s.b]).filter(Boolean));
  const files = fs.readdirSync(FIXTURES);
  assert.deepEqual(files.filter((f) => !used.has(f)), []);
});

test('license expressions: parse, precedence and ids', () => {
  assert.deepEqual(core.expandLicenses('MIT OR (Apache-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0)'), ['MIT', 'Apache-2.0', 'GPL-2.0-only']);
  assert.deepEqual(core.expandLicenses('NOASSERTION'), []);
  // AND binds tighter than OR: "MIT OR GPL AND LGPL" = MIT OR (GPL AND LGPL)
  const r = core.policyCheck(fromText(cdx([{ name: 'x', version: '1', licenses: [{ expression: 'MIT OR GPL-3.0-only AND LGPL-2.1-only' }] }])), { forbiddenLicenses: ['GPL-*'] });
  assert.equal(r.pass, true);
  assert.equal(core.parseLicenseExpression('MIT OR'), null);
  assert.equal(core.parseLicenseExpression('(MIT'), null);
});

test('malformed expressions are checked conservatively', () => {
  const r = core.policyCheck(fromText(cdx([{ name: 'x', version: '1', licenses: [{ expression: 'MIT OR GPL-3.0-only)' }] }])), { forbiddenLicenses: ['GPL-*'] });
  assert.equal(r.pass, false);
});

test('several license entries on one component all apply', () => {
  const comps = fromText(cdx([{ name: 'x', version: '1', licenses: [{ license: { id: 'MIT' } }, { license: { id: 'GPL-3.0-only' } }] }]));
  assert.equal(comps[0].licenseExpression, 'MIT AND GPL-3.0-only');
  assert.equal(core.policyCheck(comps, core.POLICY_PRESETS['No GPL']).pass, false);
});

test('wildcard patterns', () => {
  assert.ok(core.licenseMatches('GPL-3.0-only', 'GPL-*'));
  assert.ok(core.licenseMatches('gpl-2.0+', 'GPL-*'));
  assert.ok(core.licenseMatches('GPL', 'GPL-*'));
  assert.ok(!core.licenseMatches('LGPL-2.1-only', 'GPL-*'));
  assert.ok(core.licenseMatches('SSPL-1.0', 'sspl-1.0'));
  assert.deepEqual(core.parseLicenseList(' GPL-*, SSPL-1.0  BUSL-1.1,'), ['GPL-*', 'SSPL-1.0', 'BUSL-1.1']);
});

test('custom policy with no patterns passes', () => {
  assert.equal(core.policyCheck(load('cdx-fail.json'), { forbiddenLicenses: [] }).pass, true);
});

test('purl identity strips version, qualifiers, subpath and normalizes %40 scopes', () => {
  assert.equal(core.generateIdentity('pkg:npm/%40scope/name@1.2.3?x=1#a', 'name'), 'pkg:npm/@scope/name');
  assert.equal(core.generateIdentity('pkg:npm/@scope/name@1.2.3', 'name'), 'pkg:npm/@scope/name');
  assert.equal(core.generateIdentity('pkg:maven/org.a/b@1.0', 'b'), 'pkg:maven/org.a/b');
  assert.equal(core.generateIdentity(undefined, 'Left-Pad '), 'name:left-pad');
});

test('license-only and supplier changes are reported without a version change', () => {
  const A = fromText(cdx([{ name: 'x', version: '1', purl: 'pkg:npm/x@1', licenses: [{ license: { id: 'MIT' } }] }]));
  const B = fromText(cdx([{ name: 'x', version: '1', purl: 'pkg:npm/x@1', licenses: [{ license: { id: 'GPL-3.0-only' } }] }]));
  assert.deepEqual(changedIds(core.diff(A, B).changed), ['x 1 → 1 (licenses)']);
  assert.deepEqual(core.diff(A, A), { added: [], removed: [], changed: [] });
});

test('SPDX supplier prefix does not cause a false supplier change', () => {
  const A = fromText(cdx([{ name: 'x', version: '1', supplier: { name: 'Acme' } }]));
  const B = fromText(JSON.stringify({ spdxVersion: 'SPDX-2.3', packages: [{ name: 'x', versionInfo: '1', supplier: 'Organization: Acme' }] }));
  assert.deepEqual(core.diff(A, B).changed, []);
});

test('diff does not mutate its inputs', () => {
  const A = fromText(cdx([{ name: 'z', version: '1', licenses: [{ license: { id: 'MIT' } }, { license: { id: 'Apache-2.0' } }] }]));
  const before = JSON.stringify(A);
  core.diff(A, A);
  assert.equal(JSON.stringify(A), before);
});

test('markdown report uses real newlines and lists everything up to the limit', () => {
  const A = load('cdx-a.json');
  const B = load('cdx-fail.json');
  const d = core.diff(A, B);
  const md = core.buildMarkdownReport({ fileA: 'a.json', fileB: 'b.json', componentsA: A.length, componentsB: B.length, diff: d, generatedAt: 'T' });
  assert.ok(!md.includes('\\n'), 'no literal backslash-n');
  for (const c of d.added) assert.ok(md.includes(`\n- ${c.name}@${c.version}\n`), `${c.name} listed on its own line`);
  const many = core.buildMarkdownReport({ fileA: 'a', fileB: 'b', componentsA: 0, componentsB: 82, diff: core.diff([], load('cdx-large-b.json')), generatedAt: 'T' }, 50);
  assert.ok(many.includes('- ... and 32 more'));
});

test('json report has clean components and the full lists', () => {
  const d = core.diff(load('cdx-large-a.json'), load('cdx-large-b.json'));
  const j = core.buildJsonReport({ fileA: 'a', fileB: 'b', componentsA: 81, componentsB: 82, diff: core.diff([], load('cdx-large-b.json')), generatedAt: 'T' });
  assert.equal(j.diff.added.length, 82);
  assert.deepEqual(Object.keys(j.diff.added[0]).sort(), ['licenses', 'name', 'purl', 'supplier', 'version']);
  assert.equal(d.added.length, 1);
});
