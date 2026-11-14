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

function setLoaded(side: Side, sbom: LoadedSBOM | null): void {
  loaded[side] = sbom;
  document.getElementById(`drop${side}`)!.classList.toggle('has-file', !!sbom);
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
  const top = summary.topLicenses[0]?.license || '—';
  el.innerHTML = `
    <div class="summary-card">
      <h2 style="margin:0 0 var(--space-sm);font-size:1.125rem;font-weight:600;overflow-wrap:anywhere">${escapeHtml(sbom.fileName)}</h2>
      <div class="summary-stats">
        <div class="stat">
          <span class="stat-value">${summary.totalComponents}</span>
          <span class="stat-label">Components</span>
        </div>
        <div class="stat">
          <span class="stat-value">${summary.unknownLicenses}</span>
          <span class="stat-label">Unknown Licenses</span>
        </div>
        <div class="stat">
          <span class="stat-value" style="overflow-wrap:anywhere">${escapeHtml(top)}</span>
          <span class="stat-label">Top License</span>
        </div>
      </div>
    </div>
  `;
}

const EMPTY_LIST = '<div style="text-align:center;padding:var(--space-3xl);color:var(--color-gray-400)">None</div>';

function moreRow(total: number): string {
  return total > MAX_LIST_ITEMS ? `<div class="component-item">... and ${total - MAX_LIST_ITEMS} more (all included in Export JSON)</div>` : '';
}

function renderList(containerId: string, items: NormalizedComponent[], itemType: 'added' | 'removed'): void {
  const el = document.getElementById(containerId)!;
  if (!items.length) {
    el.innerHTML = EMPTY_LIST;
    return;
  }
  const sorted = [...items].sort(byNameVersion);
  el.innerHTML =
    sorted
      .slice(0, MAX_LIST_ITEMS)
      .map(
        (c) => `
    <div class="component-item ${itemType}">
      <div class="component-name">${escapeHtml(c.name)}</div>
      <div class="component-version">${escapeHtml(c.version)}</div>
      <div style="font-size:.8125rem;color:var(--color-text-secondary)">${escapeHtml(c.licenseExpression || 'Unknown license')}</div>
    </div>`
      )
      .join('') + moreRow(sorted.length);
}

function renderChangedList(containerId: string, changes: DiffChange[]): void {
  const el = document.getElementById(containerId)!;
  if (!changes.length) {
    el.innerHTML = EMPTY_LIST;
    return;
  }
  const sorted = [...changes].sort((a, b) => byNameVersion(a.to, b.to));
  const detail = (label: string, from: string, to: string) =>
    `<div style="font-size:.8125rem;color:var(--color-text-secondary)">${label}: ${escapeHtml(from)} → ${escapeHtml(to)}</div>`;
  el.innerHTML =
    sorted
      .slice(0, MAX_LIST_ITEMS)
      .map((ch) => {
        const version = ch.fields.includes('version')
          ? `${escapeHtml(ch.from.version)} → ${escapeHtml(ch.to.version)}`
          : escapeHtml(ch.to.version);
        return `
    <div class="component-item changed">
      <div class="component-name">${escapeHtml(ch.to.name)}</div>
      <div class="component-version">${version}</div>
      ${ch.fields.includes('licenses') ? detail('Licenses', ch.from.licenseExpression || 'Unknown', ch.to.licenseExpression || 'Unknown') : ''}
      ${ch.fields.includes('supplier') ? detail('Supplier', ch.from.supplier || '', ch.to.supplier || '') : ''}
    </div>`;
      })
      .join('') + moreRow(sorted.length);
}

function renderDiff(): void {
  const hasDiff = !!diffResult;
  const anyLoaded = !!(loaded.A || loaded.B);
  $('#diffSection').style.display = hasDiff ? '' : 'none';
  $('#exportSection').style.display = hasDiff ? '' : 'none';
  $('#policySection').style.display = anyLoaded ? '' : 'none';
  $('#inlineHint').style.display = !hasDiff && anyLoaded ? '' : 'none';
  if (!diffResult) return;

  const counts = { Added: diffResult.added.length, Removed: diffResult.removed.length, Changed: diffResult.changed.length };
  for (const [label, n] of Object.entries(counts)) {
    $(`#${label.toLowerCase()}Count`).textContent = String(n);
    $(`#badge${label}`).textContent = String(n);
  }
  renderList('listAdded', diffResult.added, 'added');
  renderList('listRemoved', diffResult.removed, 'removed');
  renderChangedList('listChanged', diffResult.changed);
}

function renderPolicy(): void {
  $('#policyControls').style.display = policyEnabled ? '' : 'none';
  $('#policyCustomWrap').style.display = policyPreset === 'Custom' ? 'block' : 'none';
  const target = policyTarget();
  const forbidden = forbiddenList();
  $('#policyRules').textContent = policyEnabled
    ? `Forbids: ${forbidden.join(', ') || 'nothing yet'}${target ? `. Checking ${target.fileName}.` : '. Load an SBOM to check it.'}`
    : '';

  const container = $('#policyResult');
  if (!policyEnabled || !policyResult) {
    container.innerHTML = '';
    return;
  }
  const { pass, violations } = policyResult;
  const sorted = [...violations].sort(byNameVersion);
  const cell = 'padding:var(--space-md);border-bottom:1px solid var(--color-gray-200)';
  const head = `text-align:left;${cell};background:var(--color-gray-50);font-weight:600`;
  container.innerHTML = `
    <div class="policy-result ${pass ? 'pass' : 'fail'}">
      <div class="policy-badge">${pass ? '✓ PASS' : '✗ FAIL'}</div>
      ${
        pass
          ? ''
          : `<div style="overflow-x:auto">
          <h3 style="font-size:1rem;font-weight:600;color:#991b1b;margin-bottom:var(--space-lg)">Violations (${violations.length})</h3>
          <table style="width:100%;border-collapse:collapse;font-size:.875rem">
            <thead><tr><th style="${head}">Component</th><th style="${head}">Version</th><th style="${head}">License</th></tr></thead>
            <tbody>
              ${sorted
                .slice(0, MAX_LIST_ITEMS)
                .map(
                  (v) => `<tr>
                <td style="${cell}">${escapeHtml(v.name)}</td>
                <td style="${cell}">${escapeHtml(v.version)}</td>
                <td style="${cell};font-family:ui-monospace,'Cascadia Code','Courier New',monospace;font-weight:600;color:var(--color-danger)">${escapeHtml(v.expression)}</td>
              </tr>`
                )
                .join('')}
            </tbody>
          </table>
          ${violations.length > MAX_LIST_ITEMS ? `<p style="text-align:center;margin-top:var(--space-md);color:var(--color-text-secondary)">... and ${violations.length - MAX_LIST_ITEMS} more</p>` : ''}
        </div>`
      }
    </div>`;
}

// ============================================================================
// FILE LOADING
// ============================================================================

function setLoading(side: Side, loading: boolean): void {
  const text = document.getElementById(`drop${side}`)!.querySelector('.drop-zone-text')!;
  if (loading) text.innerHTML = '<span class="loading"></span> Loading...';
  else text.textContent = `Drop SBOM ${side} (JSON) or click to select`;
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
      $('#listAdded').style.display = tab === 'added' ? '' : 'none';
      $('#listRemoved').style.display = tab === 'removed' ? '' : 'none';
      $('#listChanged').style.display = tab === 'changed' ? '' : 'none';
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
