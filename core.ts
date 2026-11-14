// SBOM Diff core: format detection, normalization, license expressions, diff and policy.
// Pure functions, no DOM. Loaded as a plain script before app.js, and by the tests in a VM.

// ============================================================================
// TYPES
// ============================================================================

interface CycloneDXLicenseChoice {
  license?: { id?: string; name?: string };
  expression?: string;
}

interface CycloneDXComponent {
  name: string;
  version?: string;
  purl?: string;
  licenses?: CycloneDXLicenseChoice[];
  supplier?: { name?: string };
  components?: CycloneDXComponent[];
  [key: string]: unknown;
}

interface CycloneDXSBOM {
  bomFormat: string;
  components?: CycloneDXComponent[];
  [key: string]: unknown;
}

interface SPDXPackage {
  name: string;
  versionInfo?: string;
  externalRefs?: Array<{ referenceType?: string; referenceCategory?: string; referenceLocator?: string }>;
  licenseDeclared?: string;
  licenseConcluded?: string;
  supplier?: string;
  [key: string]: unknown;
}

interface SPDXSBOM {
  spdxVersion: string;
  packages?: SPDXPackage[];
  [key: string]: unknown;
}

type SBOMFormat = 'CycloneDX' | 'SPDX';

interface NormalizedComponent {
  key: string; // identity + version: unique within one SBOM
  identity: string; // version-less identity used to match components across SBOMs
  name: string;
  version: string;
  purl?: string;
  licenses: string[]; // license ids found in the expression, or ['UNKNOWN']
  licenseExpression: string; // full expression, '' when unknown
  supplier?: string;
  format: SBOMFormat;
}

interface Summary {
  totalComponents: number;
  licenseCounts: Record<string, number>;
  topLicenses: Array<{ license: string; count: number }>;
  unknownLicenses: number;
}

interface DiffChange {
  key: string;
  from: NormalizedComponent;
  to: NormalizedComponent;
  fields: Array<'version' | 'licenses' | 'supplier'>;
}

interface DiffResult {
  added: NormalizedComponent[];
  removed: NormalizedComponent[];
  changed: DiffChange[];
}

interface PolicyViolation {
  key: string;
  name: string;
  version: string;
  license: string; // the forbidden license id(s) that make the expression unsatisfiable
  expression: string;
}

interface PolicyResult {
  pass: boolean;
  violations: PolicyViolation[];
}

interface Policy {
  forbiddenLicenses: string[];
}

class SBOMFormatError extends Error {}

// ============================================================================
// CONSTANTS
// ============================================================================

const MAX_BYTES = 20 * 1024 * 1024;
const MAX_LIST_ITEMS = 50;

const POLICY_PRESETS: Record<string, Policy> = {
  'No GPL': { forbiddenLicenses: ['GPL-*', 'AGPL-*'] },
  'No AGPL': { forbiddenLicenses: ['AGPL-*'] },
  'No Copyleft': { forbiddenLicenses: ['GPL-*', 'AGPL-*', 'LGPL-*'] },
  'No SSPL': { forbiddenLicenses: ['SSPL-*'] },
  'Permissive Only': {
    forbiddenLicenses: ['GPL-*', 'AGPL-*', 'LGPL-*', 'SSPL-*', 'CC-BY-SA-*', 'CC-BY-NC-*'],
  },
  Custom: { forbiddenLicenses: [] },
};

const NO_LICENSE_VALUES = new Set(['NONE', 'NOASSERTION', 'UNKNOWN', '']);

// ============================================================================
// FORMAT DETECTION
// ============================================================================

function isCycloneDX(sbom: unknown): sbom is CycloneDXSBOM {
  return !!sbom && typeof sbom === 'object' && (sbom as CycloneDXSBOM).bomFormat === 'CycloneDX';
}

function isSPDX(sbom: unknown): sbom is SPDXSBOM {
  const v = sbom && typeof sbom === 'object' ? (sbom as SPDXSBOM).spdxVersion : undefined;
  return typeof v === 'string' && v.startsWith('SPDX-');
}

function isSPDX3(sbom: unknown): boolean {
  if (!sbom || typeof sbom !== 'object') return false;
  const ctx = (sbom as Record<string, unknown>)['@context'];
  return JSON.stringify(ctx ?? '').toLowerCase().includes('spdx');
}

/** Parse file text into an SBOM object, or throw SBOMFormatError with a message a user can act on. */
function parseSBOMText(text: string): CycloneDXSBOM | SPDXSBOM {
  const trimmed = text.trimStart();
  if (trimmed.startsWith('<')) {
    throw new SBOMFormatError('This looks like XML. Only JSON SBOMs are supported: export CycloneDX JSON or SPDX JSON.');
  }
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new SBOMFormatError(`Not valid JSON (${(err as Error).message}).`);
  }
  if (isCycloneDX(data) || isSPDX(data)) return data;
  if (isSPDX3(data)) {
    throw new SBOMFormatError('SPDX 3.0 (JSON-LD) is not supported yet. Export SPDX 2.3 JSON or CycloneDX JSON.');
  }
  throw new SBOMFormatError(
    'Not a CycloneDX or SPDX SBOM: expected "bomFormat": "CycloneDX" or an "spdxVersion" field.'
  );
}

// ============================================================================
// LICENSE EXPRESSIONS (SPDX syntax: AND, OR, WITH, parentheses)
// ============================================================================

type LicenseNode =
  | { type: 'id'; id: string }
  | { type: 'with'; base: LicenseNode; exception: string }
  | { type: 'and' | 'or'; children: LicenseNode[] };

function tokenizeLicense(expr: string): string[] {
  return expr.replace(/\(/g, ' ( ').replace(/\)/g, ' ) ').split(/\s+/).filter(Boolean);
}

/** Parse an SPDX license expression. Returns null if it is malformed. */
function parseLicenseExpression(expr: string): LicenseNode | null {
  const tokens = tokenizeLicense(expr);
  let pos = 0;
  const peek = () => tokens[pos]?.toUpperCase();

  function parseOr(): LicenseNode | null {
    const first = parseAnd();
    if (!first) return null;
    const children = [first];
    while (peek() === 'OR') {
      pos++;
      const next = parseAnd();
      if (!next) return null;
      children.push(next);
    }
    return children.length === 1 ? first : { type: 'or', children };
  }

  function parseAnd(): LicenseNode | null {
    const first = parseWith();
    if (!first) return null;
    const children = [first];
    while (peek() === 'AND') {
      pos++;
      const next = parseWith();
      if (!next) return null;
      children.push(next);
    }
    return children.length === 1 ? first : { type: 'and', children };
  }

  function parseWith(): LicenseNode | null {
    const base = parseAtom();
    if (!base) return null;
    if (peek() === 'WITH') {
      pos++;
      const exception = tokens[pos++];
      if (!exception || ['(', ')', 'AND', 'OR', 'WITH'].includes(exception.toUpperCase())) return null;
      return { type: 'with', base, exception };
    }
    return base;
  }

  function parseAtom(): LicenseNode | null {
    const tok = tokens[pos];
    if (tok === undefined) return null;
    if (tok === '(') {
      pos++;
      const inner = parseOr();
      if (!inner || tokens[pos] !== ')') return null;
      pos++;
      return inner;
    }
    if (tok === ')' || ['AND', 'OR', 'WITH'].includes(tok.toUpperCase())) return null;
    pos++;
    return { type: 'id', id: tok };
  }

  const tree = parseOr();
  return tree && pos === tokens.length ? tree : null;
}

function licenseIds(node: LicenseNode): string[] {
  if (node.type === 'id') return [node.id];
  if (node.type === 'with') return licenseIds(node.base);
  return node.children.flatMap(licenseIds);
}

/** License ids in an expression (deduplicated, NONE/NOASSERTION dropped). */
function expandLicenses(expression: string): string[] {
  if (!expression || NO_LICENSE_VALUES.has(expression.trim().toUpperCase())) return [];
  const tree = parseLicenseExpression(expression);
  const ids = tree
    ? licenseIds(tree)
    : tokenizeLicense(expression).filter((t) => !['(', ')', 'AND', 'OR', 'WITH'].includes(t.toUpperCase()));
  return [...new Set(ids.filter((id) => !NO_LICENSE_VALUES.has(id.toUpperCase())))];
}

/** Does a license id match a policy pattern? "GPL-*" matches GPL, GPL-3.0-only, GPL-2.0+; plain patterns match exactly. */
function licenseMatches(id: string, pattern: string): boolean {
  const lic = id.toUpperCase();
  const pat = pattern.trim().toUpperCase();
  if (!pat) return false;
  if (pat.endsWith('*')) {
    const prefix = pat.slice(0, -1);
    const stem = prefix.replace(/[-.]$/, '');
    return lic.startsWith(prefix) || lic === stem || lic === `${stem}+`;
  }
  return lic === pat;
}

/** Can the expression be satisfied without using a forbidden license? OR needs one allowed branch, AND needs all. */
function expressionAllowed(node: LicenseNode, isForbidden: (id: string) => boolean): boolean {
  if (node.type === 'id') return !isForbidden(node.id);
  if (node.type === 'with') return expressionAllowed(node.base, isForbidden);
  if (node.type === 'and') return node.children.every((c) => expressionAllowed(c, isForbidden));
  return node.children.some((c) => expressionAllowed(c, isForbidden));
}

// ============================================================================
// NORMALIZATION
// ============================================================================

/** Version-less identity: a purl without version, qualifiers and subpath, or "name:<lowercased name>". */
function generateIdentity(purl: string | undefined, name: string): string {
  if (purl && purl.startsWith('pkg:')) {
    let clean = purl.split('#')[0].split('?')[0];
    const slash = clean.indexOf('/');
    const at = clean.lastIndexOf('@');
    if (slash >= 0 && at > slash) clean = clean.slice(0, at);
    // npm scopes may be written %40scope or @scope
    return clean.replace(/%40/gi, '@').toLowerCase();
  }
  return `name:${name.trim().toLowerCase()}`;
}

function cdxLicenseExpression(comp: CycloneDXComponent): string {
  const parts: string[] = [];
  for (const choice of comp.licenses || []) {
    const value = choice.expression || choice.license?.id || choice.license?.name;
    if (value && !NO_LICENSE_VALUES.has(value.trim().toUpperCase())) parts.push(value.trim());
  }
  // Several license entries on one component: all of them apply.
  if (parts.length <= 1) return parts[0] || '';
  return parts.map((p) => (/\s(OR|AND)\s/i.test(p) ? `(${p})` : p)).join(' AND ');
}

function spdxLicenseExpression(pkg: SPDXPackage): string {
  // The concluded license is the reviewer's determination; fall back to the declared one.
  for (const value of [pkg.licenseConcluded, pkg.licenseDeclared]) {
    if (value && !NO_LICENSE_VALUES.has(value.trim().toUpperCase())) return value.trim();
  }
  return '';
}

function makeComponent(
  name: string,
  rawVersion: string | undefined,
  purl: string | undefined,
  licenseExpression: string,
  supplier: string | undefined,
  format: SBOMFormat
): NormalizedComponent {
  const version = rawVersion && rawVersion.trim() ? rawVersion.trim() : 'unknown';
  const identity = generateIdentity(purl, name);
  const ids = expandLicenses(licenseExpression);
  return {
    key: `${identity}@${version}`,
    identity,
    name,
    version,
    purl,
    licenses: ids.length ? ids : ['UNKNOWN'],
    licenseExpression,
    supplier: supplier || undefined,
    format,
  };
}

function dedupeByKey(components: NormalizedComponent[]): NormalizedComponent[] {
  const map = new Map<string, NormalizedComponent>();
  for (const c of components) if (!map.has(c.key)) map.set(c.key, c);
  return [...map.values()];
}

function normalizeCycloneDX(sbom: CycloneDXSBOM): NormalizedComponent[] {
  const out: NormalizedComponent[] = [];
  const walk = (list: CycloneDXComponent[] | undefined) => {
    for (const comp of list || []) {
      if (comp && typeof comp.name === 'string' && comp.name) {
        out.push(makeComponent(comp.name, comp.version, comp.purl, cdxLicenseExpression(comp), comp.supplier?.name, 'CycloneDX'));
      }
      walk(comp?.components);
    }
  };
  walk(sbom.components);
  return dedupeByKey(out);
}

/** SPDX suppliers look like "Organization: Acme" or "NOASSERTION"; keep just the name. */
function spdxSupplier(value: string | undefined): string | undefined {
  if (!value || NO_LICENSE_VALUES.has(value.trim().toUpperCase())) return undefined;
  return value.replace(/^\s*(Organization|Person|Tool)\s*:\s*/i, '').trim() || undefined;
}

function normalizeSPDX(sbom: SPDXSBOM): NormalizedComponent[] {
  const out: NormalizedComponent[] = [];
  for (const pkg of sbom.packages || []) {
    if (!pkg || typeof pkg.name !== 'string' || !pkg.name) continue;
    const purl = (pkg.externalRefs || []).find((r) => r.referenceType === 'purl')?.referenceLocator;
    out.push(makeComponent(pkg.name, pkg.versionInfo, purl, spdxLicenseExpression(pkg), spdxSupplier(pkg.supplier), 'SPDX'));
  }
  return dedupeByKey(out);
}

function normalize(sbom: CycloneDXSBOM | SPDXSBOM): NormalizedComponent[] {
  if (isCycloneDX(sbom)) return normalizeCycloneDX(sbom);
  if (isSPDX(sbom)) return normalizeSPDX(sbom);
  throw new SBOMFormatError('Not a CycloneDX or SPDX SBOM.');
}

// ============================================================================
// SUMMARY
// ============================================================================

function generateSummary(components: NormalizedComponent[]): Summary {
  const licenseCounts: Record<string, number> = {};
  let unknownLicenses = 0;
  for (const comp of components) {
    if (!comp.licenseExpression) unknownLicenses++;
    for (const lic of comp.licenses) {
      if (lic !== 'UNKNOWN') licenseCounts[lic] = (licenseCounts[lic] || 0) + 1;
    }
  }
  const topLicenses = Object.entries(licenseCounts)
    .map(([license, count]) => ({ license, count }))
    .sort((a, b) => b.count - a.count || a.license.localeCompare(b.license))
    .slice(0, 10);
  return { totalComponents: components.length, licenseCounts, topLicenses, unknownLicenses };
}

// ============================================================================
// DIFF
// ============================================================================

function sameLicenses(a: NormalizedComponent, b: NormalizedComponent): boolean {
  return JSON.stringify([...a.licenses].sort()) === JSON.stringify([...b.licenses].sort());
}

function fieldChanges(from: NormalizedComponent, to: NormalizedComponent): DiffChange['fields'] {
  const fields: DiffChange['fields'] = [];
  if (from.version !== to.version) fields.push('version');
  if (!sameLicenses(from, to)) fields.push('licenses');
  if ((from.supplier || '') !== (to.supplier || '') && from.supplier && to.supplier) fields.push('supplier');
  return fields;
}

function groupBy(components: NormalizedComponent[], keyOf: (c: NormalizedComponent) => string) {
  const map = new Map<string, NormalizedComponent[]>();
  for (const c of components) {
    const k = keyOf(c);
    const list = map.get(k);
    if (list) list.push(c);
    else map.set(k, [c]);
  }
  return map;
}

/**
 * Compare two component lists.
 * Components are matched by identity (purl without version, else name). Within one identity,
 * equal versions pair up; if exactly one version is left on each side it is a version change,
 * otherwise the leftovers are reported as removed / added (e.g. lodash 4.17.20 + 4.17.21 -> 4.17.21).
 */
function diff(componentsA: NormalizedComponent[], componentsB: NormalizedComponent[]): DiffResult {
  const added: NormalizedComponent[] = [];
  const removed: NormalizedComponent[] = [];
  const changed: DiffChange[] = [];

  const pairUp = (as: NormalizedComponent[], bs: NormalizedComponent[]) => {
    const restA: NormalizedComponent[] = [];
    const restB = [...bs];
    for (const a of as) {
      const i = restB.findIndex((b) => b.version === a.version);
      if (i >= 0) {
        const b = restB.splice(i, 1)[0];
        const fields = fieldChanges(a, b);
        if (fields.length) changed.push({ key: b.key, from: a, to: b, fields });
      } else {
        restA.push(a);
      }
    }
    if (restA.length === 1 && restB.length === 1) {
      changed.push({ key: restB[0].key, from: restA[0], to: restB[0], fields: fieldChanges(restA[0], restB[0]) });
      return { restA: [], restB: [] };
    }
    return { restA, restB };
  };

  const groupsA = groupBy(componentsA, (c) => c.identity);
  const groupsB = groupBy(componentsB, (c) => c.identity);
  let leftoverA: NormalizedComponent[] = [];
  let leftoverB: NormalizedComponent[] = [];
  for (const identity of new Set([...groupsA.keys(), ...groupsB.keys()])) {
    const { restA, restB } = pairUp(groupsA.get(identity) || [], groupsB.get(identity) || []);
    leftoverA.push(...restA);
    leftoverB.push(...restB);
  }

  // Second pass: when only one side has a purl (common across tools/formats), match leftovers by name.
  const byNameA = groupBy(leftoverA, (c) => c.name.toLowerCase());
  const byNameB = groupBy(leftoverB, (c) => c.name.toLowerCase());
  for (const [name, as] of byNameA) {
    const bs = byNameB.get(name);
    if (!bs) {
      removed.push(...as);
      continue;
    }
    const purlMismatch = as.some((a) => !a.purl) || bs.some((b) => !b.purl);
    if (purlMismatch) {
      const { restA, restB } = pairUp(as, bs);
      removed.push(...restA);
      added.push(...restB);
    } else {
      removed.push(...as);
      added.push(...bs);
    }
    byNameB.delete(name);
  }
  for (const bs of byNameB.values()) added.push(...bs);

  return { added, removed, changed };
}

// ============================================================================
// POLICY
// ============================================================================

function policyCheck(components: NormalizedComponent[], policy: Policy): PolicyResult {
  const patterns = policy.forbiddenLicenses.map((p) => p.trim()).filter(Boolean);
  const isForbidden = (id: string) => patterns.some((p) => licenseMatches(id, p));
  const violations: PolicyViolation[] = [];
  if (!patterns.length) return { pass: true, violations };

  for (const comp of components) {
    if (!comp.licenseExpression) continue;
    const tree = parseLicenseExpression(comp.licenseExpression);
    // A malformed expression is checked conservatively: every id in it must be allowed.
    const allowed = tree ? expressionAllowed(tree, isForbidden) : !comp.licenses.some(isForbidden);
    if (!allowed) {
      violations.push({
        key: comp.key,
        name: comp.name,
        version: comp.version,
        license: comp.licenses.filter(isForbidden).join(', '),
        expression: comp.licenseExpression,
      });
    }
  }
  return { pass: violations.length === 0, violations };
}

/** Parse a user-entered list like "GPL-*, SSPL-1.0" into patterns. */
function parseLicenseList(text: string): string[] {
  return text.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
}

// ============================================================================
// REPORTS
// ============================================================================

function byNameVersion(a: { name?: string; version?: string }, b: { name?: string; version?: string }): number {
  return (a.name || '').localeCompare(b.name || '') || (a.version || '').localeCompare(b.version || '');
}

function publicComponent(c: NormalizedComponent) {
  return {
    name: c.name,
    version: c.version,
    purl: c.purl,
    licenses: c.licenseExpression || 'UNKNOWN',
    supplier: c.supplier,
  };
}

interface ReportInput {
  fileA: string;
  fileB: string;
  componentsA: number;
  componentsB: number;
  diff: DiffResult;
  policy?: { name: string; forbidden: string[]; checkedFile: string; result: PolicyResult };
  generatedAt: string;
}

function buildJsonReport(r: ReportInput) {
  return {
    metadata: { generatedAt: r.generatedAt, sbomA: r.fileA, sbomB: r.fileB, tool: 'SBOM Diff' },
    summary: {
      totalA: r.componentsA,
      totalB: r.componentsB,
      added: r.diff.added.length,
      removed: r.diff.removed.length,
      changed: r.diff.changed.length,
    },
    policy: r.policy
      ? {
          name: r.policy.name,
          forbidden: r.policy.forbidden,
          checkedFile: r.policy.checkedFile,
          pass: r.policy.result.pass,
          violations: r.policy.result.violations,
        }
      : undefined,
    diff: {
      added: [...r.diff.added].sort(byNameVersion).map(publicComponent),
      removed: [...r.diff.removed].sort(byNameVersion).map(publicComponent),
      changed: [...r.diff.changed]
        .sort((a, b) => byNameVersion(a.to, b.to))
        .map((c) => ({ fields: c.fields, from: publicComponent(c.from), to: publicComponent(c.to) })),
    },
  };
}

function buildMarkdownReport(r: ReportInput, limit = 50): string {
  const lines: string[] = [];
  const list = <T>(items: T[], fmt: (x: T) => string) => {
    for (const item of items.slice(0, limit)) lines.push(`- ${fmt(item)}`);
    if (items.length > limit) lines.push(`- ... and ${items.length - limit} more`);
    if (!items.length) lines.push('- none');
  };
  lines.push('# SBOM Diff Summary', '');
  lines.push(`**Comparing:** ${r.fileA} → ${r.fileB}`, `**Date:** ${r.generatedAt}`, '');
  lines.push('## Summary');
  lines.push(`- **Added:** ${r.diff.added.length}`, `- **Removed:** ${r.diff.removed.length}`, `- **Changed:** ${r.diff.changed.length}`, '');
  if (r.policy) {
    const p = r.policy;
    lines.push(`## License Policy: ${p.result.pass ? 'PASS' : 'FAIL'}`);
    lines.push(`**Policy:** ${p.name} (forbids ${p.forbidden.join(', ') || 'nothing'}), checked against ${p.checkedFile}`, '');
    if (!p.result.pass) {
      list([...p.result.violations].sort(byNameVersion), (v) => `${v.name}@${v.version}: ${v.expression}`);
      lines.push('');
    }
  }
  lines.push(`## Added (${r.diff.added.length})`);
  list([...r.diff.added].sort(byNameVersion), (c) => `${c.name}@${c.version}`);
  lines.push('', `## Removed (${r.diff.removed.length})`);
  list([...r.diff.removed].sort(byNameVersion), (c) => `${c.name}@${c.version}`);
  lines.push('', `## Changed (${r.diff.changed.length})`);
  list([...r.diff.changed].sort((a, b) => byNameVersion(a.to, b.to)), (c) => {
    const parts = [c.from.version === c.to.version ? c.to.version : `${c.from.version} → ${c.to.version}`];
    if (c.fields.includes('licenses')) parts.push(`licenses ${c.from.licenseExpression || 'UNKNOWN'} → ${c.to.licenseExpression || 'UNKNOWN'}`);
    if (c.fields.includes('supplier')) parts.push(`supplier ${c.from.supplier} → ${c.to.supplier}`);
    return `${c.to.name}: ${parts.join('; ')}`;
  });
  return lines.join('\n') + '\n';
}
