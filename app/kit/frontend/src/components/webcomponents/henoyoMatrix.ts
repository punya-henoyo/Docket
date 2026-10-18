// <henoyo-matrix>: coverage grid (met / missing / unknown) or numeric heatmap.

import { kitLocale } from './colourScheme';
import {
  HenoyoElement,
  chip,
  defineElement,
  downloadCsv,
  emit,
  esc,
  legend,
  truncatedSpan,
  type KitStat,
  glyph,
  isMaterial,
  ON_DARK,
  type ColourScheme,
  type Material,
} from './henoyoKit';
import { EXCESS_COLOR, isExcessive, paintCell, type HeatBand } from './heatmapScale';
import { SEVERITY, severityKey } from '../../data/editorial';

export type MatrixValue = 'met' | 'missing' | 'unknown' | 'na' | 'partial' | number;

export interface HenoyoMatrixRow {
  id: string;
  label: string;
  sublabel?: string;
  material?: Material;
  glyphName?: string;
  severity?: string;
}

export interface HenoyoMatrixColumn {
  id: string;
  label: string;
  group?: string;
}

export interface HenoyoMatrixCell {
  row: string;
  col: string;
  value: MatrixValue;
  severity?: string;
  note?: string;
}

const HATCH = 'repeating-linear-gradient(135deg, transparent 0 5px, rgb(0 0 0 / .07) 5px 7px)';

const COVERAGE: Record<string, { mark: string; text: string; word: string }> = {
  met: { mark: '✓', text: 'Met', word: 'met' },
  partial: { mark: '◐', text: 'Partial', word: 'partial' },
  missing: { mark: '✕', text: 'Missing', word: 'missing' },
  unknown: { mark: '?', text: 'Unknown', word: 'unknown' },
  na: { mark: '—', text: '', word: 'not applicable' },
};

function kindOf(v: MatrixValue | undefined): string {
  if (typeof v === 'number') return 'num';
  return v !== undefined && v in COVERAGE ? v : 'na';
}

/** The finding of a coverage matrix. */
export function coverageFinding(missing: number, required: number): string {
  if (required === 0) return 'Nothing to assess yet';
  return missing === 0
    ? `All ${required} cells covered`
    : `${missing} of ${required} cells missing`;
}

/** The finding of a heatmap: its largest cell. */
export function heatFinding(top: { row: string; col: string; value: number } | null): string {
  return top === null || top.value <= 0
    ? 'Nothing counted yet'
    : `Highest: ${top.row} × ${top.col} (${top.value.toLocaleString(kitLocale())})`;
}

function severityPill(value: string, s: ColourScheme): string {
  const key = severityKey(value);
  if (key === null) return `<span class="sev">${esc(value)}</span>`;
  const paint = s.severity[key];
  const style =
    key === 'critical'
      ? `background:${paint.stroke};color:${ON_DARK};border-color:${paint.stroke}`
      : `color:${paint.stroke}`;
  return `<span class="sev" style="${style}">${esc(SEVERITY[key].word)}</span>`;
}

export class HenoyoMatrix extends HenoyoElement {
  private _heading: string | undefined;
  private _truncated = false;
  private _mode: 'coverage' | 'heatmap' = 'coverage';
  private _rows: HenoyoMatrixRow[] = [];
  private _columns: HenoyoMatrixColumn[] = [];
  private _cells: HenoyoMatrixCell[] = [];
  private _bands: HeatBand[] = [];
  private _showCounts = true;
  private _excessAt: number | null = null;
  private _exportEnabled: boolean | undefined;
  private focusAt = { r: 0, c: 0 };
  private hadFocus = false;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-act]');
      if (!target) return;
      if (target.dataset.act === 'cell') {
        const row = target.dataset.row ?? '';
        const col = target.dataset.col ?? '';
        const cell = this._cells.find((c) => c.row === row && c.col === col);
        emit(this, 'henoyo:cell-selected', { row, col, value: cell?.value ?? 'na' });
      } else if (target.dataset.act === 'export') this.exportCsv();
    });
    this.root.addEventListener('keydown', (e) => {
      const key = (e as KeyboardEvent).key;
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-r]');
      if (!target || !key.startsWith('Arrow')) return;
      let r = Number(target.dataset.r);
      let c = Number(target.dataset.c);
      if (key === 'ArrowUp') r -= 1;
      else if (key === 'ArrowDown') r += 1;
      else if (key === 'ArrowLeft') c -= 1;
      else if (key === 'ArrowRight') c += 1;
      const dest = this.root.querySelector<HTMLElement>(`[data-r="${r}"][data-c="${c}"]`);
      if (!dest) return;
      e.preventDefault();
      target.tabIndex = -1;
      dest.tabIndex = 0;
      this.focusAt = { r, c };
      dest.focus();
    });
    this.root.addEventListener('focusin', (e) => {
      const t = (e.target as HTMLElement).closest<HTMLElement>('[data-r]');
      if (!t) return;
      this.focusAt = { r: Number(t.dataset.r), c: Number(t.dataset.c) };
    });
  }

  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(v: boolean | undefined) {
    this._truncated = v === true;
    this.invalidate();
  }
  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v;
    this.invalidate();
  }
  get mode(): 'coverage' | 'heatmap' {
    return this._mode;
  }
  set mode(v: 'coverage' | 'heatmap') {
    this._mode = v === 'heatmap' ? 'heatmap' : 'coverage';
    this.invalidate();
  }
  get rows(): HenoyoMatrixRow[] {
    return this._rows;
  }
  set rows(v: HenoyoMatrixRow[]) {
    this._rows = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get columns(): HenoyoMatrixColumn[] {
    return this._columns;
  }
  set columns(v: HenoyoMatrixColumn[]) {
    this._columns = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get cells(): HenoyoMatrixCell[] {
    return this._cells;
  }
  set cells(v: HenoyoMatrixCell[]) {
    this._cells = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get bands(): HeatBand[] {
    return this._bands;
  }
  set bands(v: HeatBand[] | undefined) {
    this._bands = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get showCounts(): boolean {
    return this._showCounts;
  }
  set showCounts(v: boolean | undefined) {
    this._showCounts = v !== false;
    this.invalidate();
  }
  get excessAt(): number | null {
    return this._excessAt;
  }
  set excessAt(v: number | null | undefined) {
    this._excessAt = typeof v === 'number' && Number.isFinite(v) ? v : null;
    this.invalidate();
  }
  get exportEnabled(): boolean | undefined {
    return this._exportEnabled;
  }
  set exportEnabled(v: boolean | undefined) {
    this._exportEnabled = v;
    this.invalidate();
  }

  protected override invalidate(): void {
    const a = this.root.activeElement;
    this.hadFocus = !!a && a.hasAttribute('data-r');
    super.invalidate();
  }

  protected override afterRender(): void {
    if (!this.hadFocus) return;
    this.hadFocus = false;
    this.root
      .querySelector<HTMLElement>(`[data-r="${this.focusAt.r}"][data-c="${this.focusAt.c}"]`)
      ?.focus();
  }

  private lookup(): Map<string, HenoyoMatrixCell> {
    const map = new Map<string, HenoyoMatrixCell>();
    for (const c of this._cells) {
      const key = `${c.row}\u0000${c.col}`;
      if (map.has(key)) continue;
      map.set(
        key,
        typeof c.value === 'number' && !Number.isFinite(c.value) ? { ...c, value: 'na' } : c,
      );
    }
    return map;
  }

  private exportCsv(): void {
    const map = this.lookup();
    const rows: (string | number | undefined)[][] = [];
    for (const r of this._rows)
      for (const c of this._columns) {
        const cell = map.get(`${r.id}\u0000${c.id}`);
        rows.push([r.label, c.label, cell?.value ?? 'na', cell?.note]);
      }
    downloadCsv(this, 'matrix', ['row', 'column', 'value', 'note'], rows);
  }

  protected styles(): string {
    return `
.scroll { overflow-x:auto; padding:0 0 4px; }
table { border-collapse:separate; border-spacing:0; width:100%; font-size:13px; }
th, td { padding:4px; text-align:center; border-bottom:1px solid var(--k-hairline); }
thead th { font-size:11.5px; font-weight:600; color:var(--k-text-2); vertical-align:bottom; min-width:84px; padding:8px 4px; }
thead th.grp { text-transform:uppercase; letter-spacing:.08em; font-size:10.5px; color:var(--k-text-3); border-bottom:1px solid var(--k-hairline-2); }
th.rowh { position:sticky; left:0; z-index:1; background:var(--k-surface); text-align:left; font-weight:600; min-width:150px; max-width:220px; padding:6px 12px 6px var(--h-kit-pad, 22px); border-right:1px solid var(--k-hairline); }
thead th.rowh { z-index:2; }
@media (max-width:560px) { th.rowh { min-width:104px; max-width:140px; padding-left:10px; } thead th { min-width:64px; } .cell { min-width:60px; } }
.rl { display:flex; align-items:center; gap:8px; }
.rl > div { min-width:0; overflow-wrap:anywhere; }
.rl small { display:block; font-weight:400; color:var(--k-text-3); font-size:11.5px; }
.tot { font-size:12px; color:var(--k-text-2); font-weight:600; white-space:nowrap; font-variant-numeric:tabular-nums; min-width:64px; }
.cell { width:100%; min-width:76px; min-height:var(--h-kit-row, 36px); border:1px solid transparent; border-radius:8px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:5px; font-size:12px; font-weight:600; background:var(--k-surface-2); color:var(--k-text); }
.cell:hover { border-color:var(--k-hairline-2); }
.cell.met { background:var(--k-surface-2); color:var(--k-text-2); font-weight:500; }
.cell.partial { background:var(--k-warn-soft); color:var(--k-warn); }
.cell.missing { background:var(--k-bad-soft); color:var(--k-bad); }
.cell.unknown { background:var(--k-neutral-soft); color:var(--k-neutral); border:1px dashed var(--k-neutral); }
.cell.na { background-color:transparent; color:var(--k-text-3); font-weight:400; background-image:${HATCH}; }
.cell.num { font-variant-numeric:tabular-nums; }
.bang { margin-left:2px; font-weight:700; }
.sev { font-size:10.5px; font-weight:700; padding:1px 7px; border-radius:999px; border:1px solid currentColor; text-transform:capitalize; white-space:nowrap; }
.scale { display:flex; align-items:center; gap:6px; padding:var(--h-kit-row-py, 10px) var(--h-kit-pad, 22px) calc(var(--h-kit-pad-y, 18px) - 4px); font-size:12px; color:var(--k-text-3); font-variant-numeric:tabular-nums; }
.scale .sw { width:22px; height:14px; border:1px solid var(--k-hairline); }
.keyed { padding:0 var(--h-kit-pad, 22px) calc(var(--h-kit-pad-y, 18px) - 4px); }
`;
  }

  protected view(): string {
    const rows = this._rows;
    const cols = this._columns;
    const map = this.lookup();
    const heat = this._mode === 'heatmap';
    const sch = this.scheme();
    const fr = Math.min(this.focusAt.r, rows.length - 1);
    const fc = Math.min(this.focusAt.c, cols.length - 1);
    const eyebrow = this._heading ?? (heat ? 'Heatmap' : 'Coverage');

    const nums = [...map.values()]
      .map((c) => c.value)
      .filter((v): v is number => typeof v === 'number');
    const min = nums.length ? Math.min(...nums) : 0;
    const max = nums.length ? Math.max(...nums) : 0;
    const intensity = (v: number): number =>
      max === min ? (max > 0 ? 1 : 0) : (v - min) / (max - min);

    let top: { row: string; col: string; value: number } | null = null;
    if (heat)
      for (const r of rows)
        for (const c of cols) {
          const v = map.get(`${r.id}\u0000${c.id}`)?.value;
          if (typeof v === 'number' && (top === null || v > top.value))
            top = { row: r.label, col: c.label, value: v };
        }
    const kinds: Record<string, number> = {};
    let met = 0;
    let required = 0;
    let missing = 0;
    let unknown = 0;
    const rowTot = rows.map(() => ({ met: 0, req: 0 }));
    const colTot = cols.map(() => ({ met: 0, req: 0 }));
    if (!heat)
      rows.forEach((r, ri) =>
        cols.forEach((c, ci) => {
          const v = map.get(`${r.id}\u0000${c.id}`)?.value;
          const k = kindOf(v);
          kinds[k] = (kinds[k] ?? 0) + 1;
          if (k === 'na' || k === 'num') return;
          required++;
          rowTot[ri]!.req++;
          colTot[ci]!.req++;
          if (k === 'met') {
            met++;
            rowTot[ri]!.met++;
            colTot[ci]!.met++;
          } else if (k === 'missing') missing++;
          else if (k === 'unknown') unknown++;
        }),
      );
    const pct = required ? Math.round((met / required) * 100) : 0;

    const stats: KitStat[] = heat
      ? nums.length
        ? [{ text: `Range ${min} to ${max}` }]
        : []
      : [
          { tone: pct >= 80 ? 'ok' : 'warn', text: `${pct}% met` },
          ...(missing > 0 ? [{ tone: 'bad' as const, text: `${missing} missing` }] : []),
          ...(unknown > 0 ? [{ text: `${unknown} unknown` }] : []),
        ];
    const exp =
      this._exportEnabled !== false && rows.length && cols.length
        ? `<button class="btn" type="button" data-act="export">${glyph('download', 14)}Export CSV</button>`
        : '';
    const title = heat ? heatFinding(top) : coverageFinding(missing, required);
    const header = this.head(eyebrow, rows.length === 0 || cols.length === 0 ? eyebrow : title, {
      stats,
      actions: exp,
    });
    const foot = this.foot(truncatedSpan(this._truncated));
    if (rows.length === 0 || cols.length === 0)
      return `<div class="card">${header}<div class="empty">Nothing to show yet.</div>${foot}</div>`;

    let groupRow = '';
    if (cols.some((c) => c.group)) {
      const spans: { g: string; n: number }[] = [];
      for (const c of cols) {
        const g = c.group ?? '';
        const last = spans[spans.length - 1];
        if (last && last.g === g) last.n++;
        else spans.push({ g, n: 1 });
      }
      groupRow = `<tr role="row"><th class="rowh" scope="col" role="columnheader"></th>${spans.map((s) => `<th class="grp" colspan="${s.n}" scope="colgroup" role="columnheader">${esc(s.g)}</th>`).join('')}${heat ? '' : '<th role="columnheader"></th>'}</tr>`;
    }

    const body = rows
      .map((r, ri) => {
        const sev = heat && r.severity ? severityPill(r.severity, sch) : '';
        const rc = isMaterial(r.material) ? chip(r.material, r.glyphName ?? 'layers') : '';
        const tds = cols
          .map((c, ci) => {
            const cell = map.get(`${r.id}\u0000${c.id}`);
            const v = cell?.value;
            const k = kindOf(v);
            const count = k === 'num' ? (v as number) : null;
            const excessive = count !== null && isExcessive(count, this._excessAt);
            const word = k === 'num' ? String(v) : (COVERAGE[k]?.word ?? 'not applicable');
            const label = `${r.label} × ${c.label}: ${word}${cell?.note ? `, ${cell.note}` : ''}${excessive ? ', Excessive' : ''}`;
            let cls = k;
            let style = '';
            let inner: string;
            let data = '';
            if (count !== null) {
              const i = intensity(count);
              const paint = paintCell(count, this._bands, min, max, sch);
              const shadows = [
                paint.outline === null ? '' : `inset 0 0 0 1px ${paint.outline}`,
                excessive ? `inset 0 0 0 2px ${EXCESS_COLOR}` : '',
              ].filter((part) => part !== '');
              const shadow = shadows.length === 0 ? '' : `;box-shadow:${shadows.join(',')}`;
              style = ` style="background:${paint.background};color:${paint.color}${shadow}"`;
              data = ` data-intensity="${i.toFixed(3)}"`;
              const mark = excessive
                ? `<span class="bang" aria-hidden="true">!</span><span class="sr">Excessive</span>`
                : '';
              inner = `${this._showCounts ? esc(count) : ''}${mark}`;
            } else if (heat) {
              cls = 'na';
              inner = '–';
            } else {
              const d = COVERAGE[k]!;
              inner = `<span aria-hidden="true">${d.mark}</span>${d.text ? `<span>${d.text}</span>` : ''}`;
            }
            return `<td role="gridcell"><button class="cell ${cls}" type="button" tabindex="${ri === fr && ci === fc ? 0 : -1}" data-act="cell" data-row="${esc(r.id)}" data-col="${esc(c.id)}" data-r="${ri}" data-c="${ci}"${data}${style} aria-label="${esc(label)}">${inner}</button></td>`;
          })
          .join('');
        const total = heat
          ? ''
          : `<td class="tot" role="gridcell" data-total="row">${rowTot[ri]!.met}/${rowTot[ri]!.req}</td>`;
        return `<tr role="row"><th class="rowh" scope="row" role="rowheader"><div class="rl">${rc}<div>${sev && r.severity?.toLowerCase() === r.label.trim().toLowerCase() ? '' : esc(r.label)}${r.sublabel ? `<small>${esc(r.sublabel)}</small>` : ''}${sev ? `<div>${sev}</div>` : ''}</div></div></th>${tds}${total}</tr>`;
      })
      .join('');

    const colTotals = heat
      ? ''
      : `<tr role="row"><th class="rowh" scope="row" role="rowheader">Total</th>${colTot.map((t) => `<td class="tot" role="gridcell" data-total="col">${t.met}/${t.req}</td>`).join('')}<td class="tot" role="gridcell" data-total="all">${met}/${required}</td></tr>`;

    const head = `<thead role="rowgroup">${groupRow}<tr role="row"><th class="rowh" scope="col" role="columnheader"></th>${cols.map((c) => `<th scope="col" role="columnheader">${esc(c.label)}</th>`).join('')}${heat ? '' : '<th scope="col" role="columnheader">Total</th>'}</tr></thead>`;

    let key = '';
    if (heat && nums.length) {
      const steps =
        this._bands.length > 0
          ? this._bands
              .map((band) => {
                const paint = paintCell(band.min, this._bands, min, max, sch);
                return `<span class="sw" title="${esc(band.label)}" style="background:${paint.background}"></span>`;
              })
              .join('')
          : sch.ramp
              .map((color) => `<span class="sw" style="background:${color}"></span>`)
              .join('');
      key = `<div class="scale"><span>${esc(min)}</span>${steps}<span>${esc(max)}</span></div>`;
    } else if (!heat)
      key = `<div class="keyed">${legend([
        {
          label: 'Met',
          color: 'var(--k-surface-2)',
          swatchStyle: 'border:1px solid var(--k-hairline-2)',
          count: kinds['met'] ?? 0,
        },
        { label: 'Partial', color: 'var(--k-warn-soft)', count: kinds['partial'] ?? 0 },
        { label: 'Missing', color: 'var(--k-bad-soft)', count: kinds['missing'] ?? 0 },
        {
          label: 'Unknown (not yet assessed)',
          color: 'var(--k-neutral-soft)',
          swatchStyle: 'border:1px dashed var(--k-neutral)',
          count: kinds['unknown'] ?? 0,
        },
        {
          label: 'Not applicable',
          color: 'transparent',
          swatchStyle: `background-image:${HATCH}`,
          count: kinds['na'] ?? 0,
        },
      ])}</div>`;

    return `<div class="card">${header}<div class="scroll"><table role="grid" aria-label="${esc(eyebrow)}. ${esc(title)}">${head}<tbody role="rowgroup">${body}${colTotals}</tbody></table></div>${key}${foot}</div>`;
  }
}

defineElement('henoyo-matrix', HenoyoMatrix);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-matrix': HenoyoMatrix;
  }
}
