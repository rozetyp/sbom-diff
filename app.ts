// SBOM Diff UI: file loading, rendering and export. Logic lives in core.ts (loaded first).

type Side = 'A' | 'B';

interface LoadedSBOM {
  fileName: string;
  components: NormalizedComponent[];
  summary: Summary;
}

// ============================================================================
// STATE
// ============================================================================

const loaded: Record<Side, LoadedSBOM | null> = { A: null, B: null };
let diffResult: DiffResult | null = null;
let policyEnabled = false;
let policyPreset = 'No GPL';
let customLicenses: string[] = [];
let policyResult: PolicyResult | null = null;

// ============================================================================
// HELPERS
// ============================================================================

function $(selector: string): HTMLElement {
  return document.querySelector(selector)!;
}

function escapeHtml(text: string | number): string {
  const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return String(text).replace(/[&<>"']/g, (c) => map[c]);
}

function showError(message: string): void {
  const el = $('#error');
  el.textContent = message;
  el.style.display = 'block';
  el.scrollIntoView({ block: 'nearest' });
}

function clearError(): void {
  const el = $('#error');
  el.style.display = 'none';
  el.textContent = '';
}

function forbiddenList(): string[] {
  return policyPreset === 'Custom' ? customLicenses : POLICY_PRESETS[policyPreset].forbiddenLicenses;
}

/** The policy runs against SBOM B (the newer one) when loaded, else A. */
function policyTarget(): LoadedSBOM | null {
  return loaded.B || loaded.A;
}

// ============================================================================
// STATE UPDATES
// ============================================================================

function recompute(): void {
  diffResult = loaded.A && loaded.B ? diff(loaded.A.components, loaded.B.components) : null;
  const target = policyTarget();
  policyResult = policyEnabled && target ? policyCheck(target.components, { forbiddenLicenses: forbiddenList() }) : null;
  renderSummary('A');
  renderSummary('B');
  renderDiff();
  renderPolicy();
}

function zoneText(side: Side): string {
  return loaded[side] ? 'Drop or click to replace this file' : `Drop SBOM ${side} (JSON) or click to select`;
}

function setLoaded(side: Side, sbom: LoadedSBOM | null): void {
  loaded[side] = sbom;
  const zone = document.getElementById(`drop${side}`)!;
  zone.classList.toggle('has-file', !!sbom);
  zone.querySelector('.drop-zone-text')!.textContent = zoneText(side);
  recompute();
}

// ============================================================================
// RENDERING
// ============================================================================

function renderSummary(side: Side): void {
  const el = document.getElementById(`summary${side}`)!;
  const sbom = loaded[side];
  if (!sbom) {
    el.innerHTML = '';
    return;
  }
  const { summary } = sbom;
  const parts = [`${summary.totalComponents} ${summary.totalComponents === 1 ? 'component' : 'components'}`];
  if (summary.unknownLicenses) parts.push(`${summary.unknownLicenses} without a license`);
  const top = summary.topLicenses[0];
  if (top) parts.push(`most common license ${escapeHtml(top.license)}`);
  el.innerHTML = `<b>${escapeHtml(sbom.fileName)}</b> · ${parts.join(' · ')}`;
}

function table(head: string[], rows: string[], total: number, emptyText: string): string {
  const cols = head.length;
  const body = rows.length
    ? rows.join('') +
      (total > MAX_LIST_ITEMS
        ? `<tr class="more"><td colspan="${cols}">${total - MAX_LIST_ITEMS} more not shown. Export JSON has the full list.</td></tr>`
        : '')
    : `<tr class="empty"><td colspan="${cols}">${emptyText}</td></tr>`;
  return `<table class="data"><thead><tr>${head.map((h) => `<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table>`;
}

function renderList(containerId: string, items: NormalizedComponent[], kind: 'added' | 'removed'): void {
  const sign = kind === 'added' ? '+' : '−';
  const sorted = [...items].sort(byNameVersion);
  const rows = sorted.slice(0, MAX_LIST_ITEMS).map(
    (c) => `<tr class="${kind}">
      <td class="sign" aria-hidden="true">${sign}</td>
      <td class="mono">${escapeHtml(c.name)}</td>
      <td class="mono">${escapeHtml(c.version)}</td>
      <td class="mono">${escapeHtml(c.licenseExpression || 'unknown')}</td>
    </tr>`
  );
  document.getElementById(containerId)!.innerHTML = table(
    ['<span class="visually-hidden">Change</span>', 'Component', 'Version', 'License'],
    rows,
    sorted.length,
    `Nothing ${kind}.`
  );
}

function renderChangedList(containerId: string, changes: DiffChange[]): void {
  const sorted = [...changes].sort((a, b) => byNameVersion(a.to, b.to));
  const arrow = '<span class="arrow">→</span>';
  const anyNotes = sorted.some((ch) => ch.fields.includes('licenses') || ch.fields.includes('supplier'));
  const rows = sorted.slice(0, MAX_LIST_ITEMS).map((ch) => {
    const version = ch.fields.includes('version')
      ? `${escapeHtml(ch.from.version)} ${arrow} ${escapeHtml(ch.to.version)}`
      : escapeHtml(ch.to.version);
    const notes: string[] = [];
    if (ch.fields.includes('licenses')) {
      notes.push(`license ${escapeHtml(ch.from.licenseExpression || 'unknown')} ${arrow} ${escapeHtml(ch.to.licenseExpression || 'unknown')}`);
    }
    if (ch.fields.includes('supplier')) {
      notes.push(`supplier ${escapeHtml(ch.from.supplier || '')} ${arrow} ${escapeHtml(ch.to.supplier || '')}`);
    }
    return `<tr class="changed">
      <td class="sign" aria-hidden="true">~</td>
      <td class="mono">${escapeHtml(ch.to.name)}</td>
      <td class="mono">${version}</td>
      ${anyNotes ? `<td class="mono note">${notes.join('<br>')}</td>` : ''}
    </tr>`;
  });
  const head = ['<span class="visually-hidden">Change</span>', 'Component', 'Version'];
  if (anyNotes) head.push('Also changed');
  document.getElementById(containerId)!.innerHTML = table(
    head,
    rows,
    sorted.length,
    'Nothing changed.'
  );
}

function renderDiff(): void {
  const hasDiff = !!diffResult;
  const anyLoaded = !!(loaded.A || loaded.B);
  $('#diffSection').hidden = !hasDiff;
  $('#exportSection').hidden = !hasDiff;
  $('#policySection').hidden = !anyLoaded;
  $('#inlineHint').hidden = hasDiff || !anyLoaded;
  if (!diffResult) return;

  $('#addedCount').textContent = String(diffResult.added.length);
  $('#removedCount').textContent = String(diffResult.removed.length);
  $('#changedCount').textContent = String(diffResult.changed.length);
  renderList('listAdded', diffResult.added, 'added');
  renderList('listRemoved', diffResult.removed, 'removed');
  renderChangedList('listChanged', diffResult.changed);
}

function renderPolicy(): void {
  $('#policyControls').hidden = !policyEnabled;
  $('#policyCustomWrap').hidden = policyPreset !== 'Custom';
  const target = policyTarget();
  const forbidden = forbiddenList();
  $('#policyRules').textContent = policyEnabled
    ? `Forbids ${forbidden.join(', ') || 'nothing yet'}.${target ? ` Checking ${target.fileName}.` : ' Load an SBOM to check it.'}`
    : '';

  const container = $('#policyResult');
  if (!policyEnabled || !policyResult) {
    container.innerHTML = '';
    return;
  }
  const { pass, violations } = policyResult;
  if (pass) {
    container.innerHTML = `<div class="verdict pass"><strong>PASS</strong><span>No component needs a forbidden license.</span></div>`;
    return;
  }
  const sorted = [...violations].sort(byNameVersion);
  const rows = sorted.slice(0, MAX_LIST_ITEMS).map(
    (v) => `<tr>
      <td class="mono">${escapeHtml(v.name)}</td>
      <td class="mono">${escapeHtml(v.version)}</td>
      <td class="mono">${escapeHtml(v.expression)}</td>
    </tr>`
  );
  container.innerHTML = `
    <div class="verdict fail"><strong>FAIL</strong><span>Violations (${violations.length}): ${violations.length === 1 ? 'this component needs' : 'these components need'} a forbidden license.</span></div>
    <div class="table-wrap">${table(['Component', 'Version', 'License'], rows, sorted.length, '')}</div>`;
}

// ============================================================================
// FILE LOADING
// ============================================================================

function setLoading(side: Side, loading: boolean): void {
  const text = document.getElementById(`drop${side}`)!.querySelector('.drop-zone-text')!;
  if (loading) text.innerHTML = '<span class="loading"></span> Loading...';
  else text.textContent = zoneText(side);
}

function loadText(text: string, fileName: string, side: Side): void {
  try {
    const components = normalize(parseSBOMText(text));
    setLoaded(side, { fileName, components, summary: generateSummary(components) });
  } catch (err) {
    const reason = err instanceof SBOMFormatError ? err.message : `Unexpected error: ${String(err)}`;
    showError(`Could not load ${fileName} as SBOM ${side}. ${reason}`);
    setLoaded(side, null);
  }
}

function readFile(file: File, side: Side): void {
  clearError();
  if (file.size > MAX_BYTES) {
    showError(`${file.name} is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max ${MAX_BYTES / 1024 / 1024} MB.`);
    return;
  }
  setLoading(side, true);
  const reader = new FileReader();
  reader.onload = () => {
    setLoading(side, false);
    loadText(String(reader.result || ''), file.name, side);
  };
  reader.onerror = () => {
    setLoading(side, false);
    showError(`Could not read ${file.name}.`);
  };
  reader.readAsText(file);
}

const SAMPLES: Record<string, string> = {
  'A:cyclonedx': 'samples/cyclonedx-a.json',
  'B:cyclonedx': 'samples/cyclonedx-b.json',
  'A:spdx': 'samples/spdx-a.json',
  'B:spdx': 'samples/spdx-b.json',
};

async function loadSample(sample: string): Promise<void> {
  const side = sample.split(':')[0] as Side;
  const path = SAMPLES[sample];
  clearError();
  try {
    const response = await fetch(path);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    loadText(await response.text(), path, side);
  } catch (err) {
    showError(`Could not load sample ${path}: ${String(err)}`);
  }
}

// ============================================================================
// WIRING
// ============================================================================

function wireDrop(side: Side): void {
  const zone = document.getElementById(`drop${side}`)!;
  const input = document.getElementById(`file${side}`) as HTMLInputElement;
  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      input.click();
    }
  });
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('dragging');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragging'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragging');
    const file = e.dataTransfer?.files[0];
    if (file) readFile(file, side);
  });
  input.addEventListener('change', () => {
    const file = input.files?.[0];
    if (file) readFile(file, side);
    input.value = '';
  });
}

function initTabs(): void {
  document.querySelectorAll('.diff-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.diff-tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.getAttribute('data-tab');
      $('#listAdded').hidden = tab !== 'added';
      $('#listRemoved').hidden = tab !== 'removed';
      $('#listChanged').hidden = tab !== 'changed';
      document.querySelectorAll('.diff-tab').forEach((b) => b.setAttribute('aria-selected', String(b === btn)));
    });
  });
}

function initPolicy(): void {
  const select = $('#policyPreset') as HTMLSelectElement;
  select.innerHTML = Object.keys(POLICY_PRESETS)
    .map((k) => `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`)
    .join('');
  select.value = policyPreset;

  ($('#policyToggle') as HTMLInputElement).addEventListener('change', (e) => {
    policyEnabled = (e.target as HTMLInputElement).checked;
    recompute();
  });
  select.addEventListener('change', () => {
    policyPreset = select.value;
    recompute();
  });
  ($('#policyCustom') as HTMLInputElement).addEventListener('input', (e) => {
    customLicenses = parseLicenseList((e.target as HTMLInputElement).value);
    recompute();
  });
}

function currentReport(): ReportInput | null {
  if (!diffResult || !loaded.A || !loaded.B) return null;
  const target = policyTarget();
  return {
    fileA: loaded.A.fileName,
    fileB: loaded.B.fileName,
    componentsA: loaded.A.components.length,
    componentsB: loaded.B.components.length,
    diff: diffResult,
    policy:
      policyEnabled && policyResult && target
        ? { name: policyPreset, forbidden: [...forbiddenList()], checkedFile: target.fileName, result: policyResult }
        : undefined,
    generatedAt: new Date().toISOString(),
  };
}

function initExport(): void {
  const copyBtn = $('#copyBtn');
  copyBtn.addEventListener('click', async () => {
    const report = currentReport();
    if (!report) return;
    try {
      await navigator.clipboard.writeText(buildMarkdownReport(report));
      copyBtn.textContent = 'Copied!';
      setTimeout(() => (copyBtn.textContent = 'Copy as Markdown'), 2000);
    } catch (err) {
      showError(`Could not copy to the clipboard: ${String(err)}`);
    }
  });

  $('#exportBtn').addEventListener('click', () => {
    const report = currentReport();
    if (!report) return;
    const blob = new Blob([JSON.stringify(buildJsonReport(report), null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sbom-diff-${report.generatedAt.slice(0, 19).replace(/[:T]/g, '-')}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}

function initSamples(): void {
  document.querySelectorAll('[data-sample]').forEach((btn) => {
    btn.addEventListener('click', () => loadSample(btn.getAttribute('data-sample')!));
  });
}

function initPaste(): void {
  window.addEventListener('paste', (e) => {
    const target = e.target as HTMLElement | null;
    if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) return;
    const text = e.clipboardData?.getData('text');
    if (!text || !text.trim().startsWith('{')) return;
    clearError();
    loadText(text, 'pasted.json', loaded.A ? 'B' : 'A');
  });
}

function init(): void {
  wireDrop('A');
  wireDrop('B');
  initTabs();
  initPolicy();
  initExport();
  initSamples();
  initPaste();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
