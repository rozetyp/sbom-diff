// Loads the compiled core.js (a plain browser script) into a VM context and returns its globals.
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(here, '..');
export const FIXTURES = path.join(here, 'fixtures');
export const EXPECTED = path.join(here, 'expected.json');

export function loadCore() {
  // Run in this realm (not a new context) so arrays/objects compare with assert.deepStrictEqual.
  vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'core.js'), 'utf8'), { filename: 'core.js' });
  // const/class declarations are not globalThis properties; expose the ones tests need.
  return vm.runInThisContext(
    `({ parseSBOMText, normalize, diff, policyCheck, generateSummary, expandLicenses, parseLicenseExpression,
        licenseMatches, generateIdentity, parseLicenseList, buildMarkdownReport, buildJsonReport,
        POLICY_PRESETS, SBOMFormatError })`
  );
}

export function readSbom(file) {
  return fs.readFileSync(path.join(FIXTURES, file), 'utf8');
}
