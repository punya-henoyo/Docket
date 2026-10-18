// <henoyo-severity-age>: a two-grouping report as a heatmap. Severity words keep
// their colours; known age bands read paper to oxblood in solid steps.

import { HenoyoElement, defineElement, esc, inkOn } from './henoyoKit';
import { formatCount, type SeverityAgeAxis, type SeverityAgeCell } from './vizGroupB.binding';

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function asAxes(value: unknown): SeverityAgeAxis[] {
  if (!Array.isArray(value)) return [];
  const axes: SeverityAgeAxis[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    const id = text(row['id']);
    if (id === undefined) continue;
    axes.push({ id, label: text(row['label']) ?? id, tone: text(row['tone']) ?? '' });
  }
  return axes;
}

function asCells(value: unknown): SeverityAgeCell[] {
  if (!Array.isArray(value)) return [];
  const cells: SeverityAgeCell[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    const r = text(row['row']);
    const c = text(row['col']);
    if (r === undefined || c === undefined) continue;
    const n = typeof row['value'] === 'number' ? row['value'] : Number(row['value']);
    cells.push({ row: r, col: c, value: Number.isFinite(n) ? n : 0 });
  }
  return cells;
}

function stepOf(value: number, max: number): number {
  if (value <= 0 || max <= 0) return 0;
  const t = value / max;
  if (t < 0.25) return 1;
  if (t < 0.5) return 2;
  if (t < 0.75) return 3;
  return 4;
}

/** The finding: critical items older than the cut-off, or the report's own sentence when it is not severity by age. */
export function ageFinding(oldCritical: number | null, age: string, sentence: string): string {
  if (oldCritical === null) return sentence === '' ? 'Severity by age' : sentence;
  return oldCritical === 0
    ? `No critical older than ${age}`
    : `${formatCount(oldCritical)} critical older than ${age}`;
}

export class HenoyoSeverityAge extends HenoyoElement {
  private _heading: string | undefined;
  private _sentence = '';
  private _oldCritical: number | null = null;
  private _oldAge = '90 days';
  private _rows: SeverityAgeAxis[] = [];
  private _columns: SeverityAgeAxis[] = [];
  private _cells: SeverityAgeCell[] = [];
  private _truncated = false;
  private _selected: string | undefined;

  constructor() {
    super();
    this.root.addEventListener('click', (event) => {
      const node = event.target instanceof Element ? event.target : null;
      const button = node?.closest('button');
      if (button?.dataset['act'] !== 'cell') return;
      const key = `${button.dataset['row'] ?? ''}\u0000${button.dataset['col'] ?? ''}`;
      this._selected = this._selected === key ? undefined : key;
      this.invalidate();
    });
  }

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(value: string | undefined) {
    this._heading = text(value);
    this.invalidate();
  }
  get sentence(): string {
    return this._sentence;
  }
  set sentence(value: string) {
    this._sentence = text(value) ?? '';
    this.invalidate();
  }
  get oldCritical(): number | null {
    return this._oldCritical;
  }
  set oldCritical(value: number | null | undefined) {
    this._oldCritical = typeof value === 'number' && Number.isFinite(value) ? value : null;
    this.invalidate();
  }
  get oldAge(): string {
    return this._oldAge;
  }
  set oldAge(value: string) {
    this._oldAge = text(value) ?? '90 days';
    this.invalidate();
  }
  get rows(): SeverityAgeAxis[] {
    return this._rows;
  }
  set rows(value: SeverityAgeAxis[]) {
    this._rows = asAxes(value);
    this.invalidate();
  }
  get columns(): SeverityAgeAxis[] {
    return this._columns;
  }
  set columns(value: SeverityAgeAxis[]) {
    this._columns = asAxes(value);
    this.invalidate();
  }
  get cells(): SeverityAgeCell[] {
    return this._cells;
  }
  set cells(value: SeverityAgeCell[]) {
    this._cells = asCells(value);
    this._selected = undefined;
    this.invalidate();
  }
  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(value: boolean | undefined) {
    this._truncated = value === true;
    this.invalidate();
  }

  protected override styles(): string {
    return `
.scroll { overflow-x:auto; }
table { border-collapse:separate; border-spacing:4px; width:100%; font-size:13px; }
th { font-weight:600; text-align:center; font-size:12px; color:var(--k-text-2); padding:4px 6px; }
th.rowh { text-align:left; white-space:nowrap; position:sticky; left:0; z-index:1; background:var(--k-surface); }
@media (max-width:560px) { .cell { min-width:3.25rem; } th { padding:4px 3px; } table { border-spacing:3px; } }
.sev-critical, .sev-high, .sev-medium, .sev-low, .sev-info { display:inline-block; }
.sev-critical { color:var(--k-surface); background:var(--k-sev-critical); border-radius:999px; padding:2px 8px; }
.sev-high { color:var(--k-sev-high); box-shadow:inset 0 0 0 1px var(--k-sev-high); border-radius:999px; padding:2px 8px; }
.sev-medium { color:var(--k-sev-medium); }
.sev-low { color:var(--k-sev-low); }
.sev-info { color:var(--k-sev-info); }
.cell { min-width:4.5rem; min-height:2.4rem; border:1px solid var(--k-hairline); border-radius:6px; font:inherit; font-variant-numeric:tabular-nums; font-weight:600; cursor:pointer; }
.cell[aria-pressed="true"] { outline:2px solid var(--k-brand); outline-offset:1px; }
.tot { font-variant-numeric:tabular-nums; color:var(--k-text-2); }
.key { display:flex; align-items:center; gap:4px; margin:12px 0 0; font-size:12px; color:var(--k-text-2); font-variant-numeric:tabular-nums; }
.key .sw { border:1px solid var(--k-hairline); }
.key .lo { margin-right:4px; }
.key .hi { margin-left:4px; }
.detail { margin:10px 0 0; font-size:13px; }`;
  }

  protected override view(): string {
    const eyebrow = this._heading ?? 'Severity by age';
    if (this._rows.length === 0 || this._columns.length === 0)
      return this.emptyCard(eyebrow, 'Nothing to show yet');
    const values = new Map(this._cells.map((cell) => [`${cell.row}\u0000${cell.col}`, cell.value]));
    const max = this._cells.reduce((hi, cell) => Math.max(hi, cell.value), 0);
    const rowTotal = new Map<string, number>();
    const colTotal = new Map<string, number>();
    let grand = 0;
    for (const cell of this._cells) {
      rowTotal.set(cell.row, (rowTotal.get(cell.row) ?? 0) + cell.value);
      colTotal.set(cell.col, (colTotal.get(cell.col) ?? 0) + cell.value);
      grand += cell.value;
    }
    const head = `<tr><th></th>${this._columns.map((col) => `<th scope="col">${esc(col.label)}</th>`).join('')}<th scope="col">Total</th></tr>`;
    const steps = this.scheme().ramp;
    const body = this._rows
      .map((row) => {
        const tone = row.tone === '' ? '' : ` sev-${row.tone}`;
        const cells = this._columns
          .map((col) => {
            const value = values.get(`${row.id}\u0000${col.id}`) ?? 0;
            const step = stepOf(value, max);
            const key = `${row.id}\u0000${col.id}`;
            const pressed = this._selected === key ? 'true' : 'false';
            const fill = steps[step] ?? steps[0] ?? '';
            const ink = inkOn(fill);
            return `<td><button type="button" class="cell" data-act="cell" data-row="${esc(row.id)}" data-col="${esc(col.id)}" data-step="${step}" aria-pressed="${pressed}" aria-label="${esc(`${row.label}, ${col.label}, ${formatCount(value)}`)}" style="background:${fill};color:${ink}">${esc(formatCount(value))}</button></td>`;
          })
          .join('');
        return `<tr><th class="rowh" scope="row"><span class="${tone.trim()}">${esc(row.label)}</span></th>${cells}<td class="tot">${esc(formatCount(rowTotal.get(row.id) ?? 0))}</td></tr>`;
      })
      .join('');
    const totals = `<tr><th class="rowh" scope="row">Total</th>${this._columns.map((col) => `<td class="tot">${esc(formatCount(colTotal.get(col.id) ?? 0))}</td>`).join('')}<td class="tot">${esc(formatCount(grand))}</td></tr>`;
    const swatches = steps
      .map((fill) => `<span class="sw" style="background:${fill}"></span>`)
      .join('');
    const selected = this._selected?.split('\u0000');
    const selectedRow = this._rows.find((row) => row.id === selected?.[0]);
    const selectedCol = this._columns.find((col) => col.id === selected?.[1]);
    const selectedValue =
      selectedRow !== undefined && selectedCol !== undefined
        ? (values.get(`${selectedRow.id}\u0000${selectedCol.id}`) ?? 0)
        : undefined;
    const detail =
      selectedRow === undefined || selectedCol === undefined || selectedValue === undefined
        ? ''
        : `<p class="detail">${esc(selectedRow.label)} × ${esc(selectedCol.label)} — ${esc(formatCount(selectedValue))}.</p>`;
    const finding = ageFinding(this._oldCritical, this._oldAge, this._sentence);
    const sub = this._oldCritical === null ? undefined : this._sentence;
    return `<div class="card">${this.head(eyebrow, finding, {
      ...(sub === undefined ? {} : { sub }),
      stats: [{ text: `${formatCount(grand)} total` }],
    })}<div class="body">
      <div class="scroll"><table aria-label="${esc(eyebrow)}"><thead>${head}</thead><tbody>${body}${totals}</tbody></table></div>
      <p class="key"><span class="lo">0</span>${swatches}<span class="hi">${esc(formatCount(max))}</span></p>${detail}</div>${this.foot(this._truncated ? '<span>The report is showing a partial result.</span>' : '')}</div>`;
  }
}

defineElement('henoyo-severity-age', HenoyoSeverityAge);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-severity-age': HenoyoSeverityAge;
  }
}
