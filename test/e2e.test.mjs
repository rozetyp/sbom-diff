// Browser tests: drive the real page in headless Chromium.
// Needs a browser: `npx playwright install chromium` (CI), or a local Google Chrome as a fallback.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';
import { startServer } from './serve.mjs';
import { FIXTURES } from './load-core.mjs';

const SB = (f) => path.join(FIXTURES, f);
let server, browser, context, page, base;
let consoleErrors = [];
let externalRequests = [];

async function launch() {
  try {
    return await chromium.launch();
  } catch {
    return await chromium.launch({ channel: 'chrome' });
  }
}

before(async () => {
  server = await startServer(0);
  base = `http://127.0.0.1:${server.address().port}/`;
  browser = await launch();
});

after(async () => {
  await browser?.close();
  server?.close();
});

beforeEach(async () => {
  await context?.close();
  context = await browser.newContext({ acceptDownloads: true });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: base.slice(0, -1) });
  page = await context.newPage();
  consoleErrors = [];
  externalRequests = [];
  page.on('console', (m) => m.type() === 'error' && consoleErrors.push(m.text()));
  page.on('pageerror', (e) => consoleErrors.push(e.message));
  page.on('request', (r) => !r.url().startsWith(base) && !r.url().startsWith('data:') && externalRequests.push(r.url()));
  await page.goto(base);
});

const text = (sel) => page.locator(sel).innerText();
const counts = async () => [await text('#addedCount'), await text('#removedCount'), await text('#changedCount')];
async function upload(side, file) {
  await page.setInputFiles(`#file${side}`, SB(file));
  await page.waitForFunction((s) => document.querySelector(`#drop${s} .loading`) === null, side);
}

test('diff of two CycloneDX files', async () => {
  await upload('A', 'cdx-a.json');
  assert.ok(await page.locator('#inlineHint').isVisible(), 'hint after one file');
  await upload('B', 'cdx-b.json');
  assert.deepEqual(await counts(), ['1', '1', '1']);
  await page.click('[data-tab="changed"]');
  const changed = await text('#listChanged');
  assert.match(changed, /alpha\s+1\.0\.0 → 2\.0\.0/);
  assert.doesNotMatch(changed, /Licenses/, 'no license line when licenses did not change');
  assert.deepEqual(consoleErrors, []);
  assert.deepEqual(externalRequests, []);
});

test('cross-format and multi-version diffs', async () => {
  await upload('A', 'cdx-a.json');
  await upload('B', 'spdx-b.json');
  assert.deepEqual(await counts(), ['1', '1', '1']);
  await upload('A', 'cdx-multiversion-a.json');
  await upload('B', 'cdx-multiversion-b.json');
  assert.deepEqual(await counts(), ['1', '1', '1']);
  await page.click('[data-tab="removed"]');
  assert.match(await text('#listRemoved'), /lodash\s+4\.17\.20/);
});

test('a non-SBOM file is rejected and clears that side', async () => {
  await upload('A', 'cdx-a.json');
  await upload('B', 'cdx-b.json');
  await upload('B', 'not-sbom.json');
  assert.match(await text('#error'), /Could not load not-sbom\.json as SBOM B\. Not a CycloneDX or SPDX SBOM/);
  assert.equal(await text('#summaryB'), '', 'old summary is cleared');
  assert.equal(await page.locator('#diffSection').isVisible(), false, 'no diff against a rejected file');
  await upload('B', 'invalid.json');
  assert.match(await text('#error'), /Not valid JSON/);
  await upload('B', 'spdx3.json');
  assert.match(await text('#error'), /SPDX 3\.0/);
  await upload('B', 'cdx-b.json');
  assert.equal(await page.locator('#error').isVisible(), false, 'error clears on a good file');
  assert.deepEqual(await counts(), ['1', '1', '1']);
});

test('policy presets and custom list', async () => {
  await upload('A', 'cdx-fail.json');
  await page.check('#policyToggle');
  assert.match(await text('#policyRules'), /Forbids GPL-\*, AGPL-\*\. Checking cdx-fail\.json\./);
  assert.match(await text('#policyResult'), /FAIL[\s\S]*Violations \(2\)/);
  await page.selectOption('#policyPreset', 'Permissive Only');
  assert.match(await text('#policyResult'), /Violations \(4\)/);
  await page.selectOption('#policyPreset', 'Custom');
  assert.ok(await page.locator('#policyCustom').isVisible());
  assert.match(await text('#policyResult'), /PASS/, 'empty custom list passes');
  await page.fill('#policyCustom', 'SSPL-*, LGPL-2.1-only');
  assert.match(await text('#policyResult'), /Violations \(2\)/);
  await upload('B', 'cdx-dual-license.json');
  await page.selectOption('#policyPreset', 'No GPL');
  assert.match(await text('#policyRules'), /Checking cdx-dual-license\.json/, 'policy runs on SBOM B');
  const result = await text('#policyResult');
  assert.match(result, /Violations \(2\)/);
  assert.doesNotMatch(result, /dual-mit-gpl/, 'MIT OR GPL is allowed');
});

test('copy as markdown and export JSON', async () => {
  await upload('A', 'cdx-a.json');
  await upload('B', 'cdx-fail.json');
  await page.check('#policyToggle');
  await page.click('#copyBtn');
  await page.waitForFunction(() => document.querySelector('#copyBtn').textContent === 'Copied!');
  const md = await page.evaluate(() => navigator.clipboard.readText());
  assert.ok(md.includes('\n- agpl-lib@1.2.0\n- gpl-lib@3.0.0\n'), 'one item per line');
  assert.ok(!md.includes('\\n'));
  assert.match(md, /License Policy: FAIL/);

  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#exportBtn')]);
  const report = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
  assert.match(download.suggestedFilename(), /^sbom-diff-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.json$/);
  assert.deepEqual(report.summary, { totalA: 3, totalB: 5, added: 5, removed: 3, changed: 0 });
  assert.equal(report.policy.checkedFile, 'cdx-fail.json');
  assert.equal(report.policy.violations.length, 2);
});

test('sample buttons load the bundled examples', async () => {
  await page.click('details.sample-menu >> nth=0 >> summary');
  await page.click('[data-sample="A:cyclonedx"]');
  await page.click('details.sample-menu >> nth=1 >> summary');
  await page.click('[data-sample="B:cyclonedx"]');
  await page.waitForSelector('#diffSection', { state: 'visible' });
  assert.match(await text('#summaryA'), /cyclonedx-a\.json/);
  assert.notDeepEqual(await counts(), ['0', '0', '0']);
  assert.deepEqual(consoleErrors, []);
});

test('pasting SBOM JSON loads it', async () => {
  const json = fs.readFileSync(SB('cdx-a.json'), 'utf8');
  await page.evaluate((t) => {
    const dt = new DataTransfer();
    dt.setData('text', t);
    window.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt }));
  }, json);
  assert.match(await text('#summaryA'), /pasted\.json/);
});

test('hostile names are escaped', async () => {
  const evil = JSON.stringify({
    bomFormat: 'CycloneDX',
    components: [{ name: '<img src=x onerror=window.__xss=1>', version: '"><b>1', licenses: [{ license: { id: '<script>window.__xss=2</script>' } }] }],
  });
  await page.setInputFiles('#fileA', { name: '<img src=y onerror=window.__xss=3>.json', mimeType: 'application/json', buffer: Buffer.from(evil) });
  await upload('B', 'cdx-a.json');
  await page.check('#policyToggle');
  await page.selectOption('#policyPreset', 'Custom');
  await page.fill('#policyCustom', '<script>*');
  await page.click('[data-tab="removed"]');
  assert.equal(await page.evaluate(() => window.__xss), undefined);
});

test('phone-width layout has no horizontal scroll', async () => {
  await page.setViewportSize({ width: 375, height: 800 });
  await upload('A', 'cdx-a.json');
  await upload('B', 'cdx-b.json');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  assert.ok(overflow <= 0, `overflow ${overflow}px`);
});

test('content pages load without errors', async () => {
  for (const p of ['how-to-generate-sbom.html', 'cyclonedx-vs-spdx.html', 'sbom-compliance-policies.html']) {
    const res = await page.goto(base + p);
    assert.equal(res.status(), 200, p);
  }
  assert.deepEqual(consoleErrors, []);
  assert.deepEqual(externalRequests, []);
});
