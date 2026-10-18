// <henoyo-kpi-bar>: one report grouping as horizontal bars. At most six, then Other.

import { HenoyoElement, defineElement, emit, esc, finite, truncatedSpan } from './henoyoKit';
import { fmt } from './vizPalette';

export interface KpiRow {
  key: string;
  label: string;
  value: number;
}

/** The finding: the largest value and who holds it. */
export function kpiFinding(rows: readonly { label: string; value: number }[]): string {
  const top = rows.reduce<{ label: string; value: number } | null>(
    (best, row) => (best === null || row.value > best.value ? row : best),
    null,
  );
  return top === null || top.value <= 0
    ? 'Nothing counted yet'
    : `${top.label} leads with ${fmt(top.value)}`;
}

export class HenoyoKpiBar extends HenoyoElement {
  private _heading = 'Comparison';
  private _rows: KpiRow[] = [];
  private _truncated = false;

  constructor() {
    super();
    this.root.addEventListener('click', (event) => {
      const raw = event.target;
      if (!(raw instanceof Element)) return;
      const row = raw.closest('[data-key]');
      if (row === null) return;
      emit(this, 'henoyo:part-selected', {
        label: row.getAttribute('data-label') ?? '',
        value: row.getAttribute('data-key') ?? '',
      });
      const note = this.root.querySelector('.note');
      if (note) note.textContent = row.getAttribute('data-tip') ?? '';
    });
  }

  get heading(): string {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v && v.trim() !== '' ? v : 'Comparison';
    this.invalidate();
  }
  get rows(): KpiRow[] {
    return this._rows;
  }
  set rows(v: KpiRow[] | undefined) {
    this._rows = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(v: boolean | undefined) {
    this._truncated = v === true;
    this.invalidate();
  }

  protected styles(): string {
    return `.rows { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:4px; }
.row { display:grid; grid-template-columns:minmax(6rem, 9rem) 1fr 4rem; gap:12px; align-items:center; width:100%; min-height:28px;
  background:none; border:0; padding:2px 0; text-align:left; cursor:pointer; font:inherit; color:inherit; }
.lab { font-size:13px; }
.track { display:block; height:12px; }
.bar { display:block; height:100%; min-width:2px; border-radius:0 2px 2px 0; background:var(--k-text-3); opacity:.45; }
.bar.top { background:var(--k-accent); opacity:1; }
.num { text-align:right; white-space:nowrap; font-variant-numeric:tabular-nums; font-size:13px; font-weight:600; }
`;
  }

  protected view(): string {
    const rows = this._rows
      .map((row) => ({ ...row, value: finite(row?.value) ?? 0 }))
      .filter((row) => row && typeof row.label === 'string' && row.value >= 0);
    if (rows.length === 0) {
      return this.emptyCard(
        this._heading,
        'Nothing to show yet',
        'No records match this report yet.',
      );
    }
    const max = Math.max(...rows.map((row) => row.value), 1);
    const total = rows.reduce((sum, row) => sum + row.value, 0);
    const top = rows.findIndex((row) => row.value === max);
    const finding = kpiFinding(rows);
    const stats =
      total > 0 && max > 0
        ? [{ text: `${Math.round((max / total) * 100)}% of ${fmt(total)}` }]
        : [];
    const list = rows
      .map((row, index) => {
        const width = Math.max(2, Math.round((row.value / max) * 100));
        const tip = `${row.label} — ${fmt(row.value)}`;
        return `<li><button type="button" class="row" data-key="${esc(row.key)}" data-label="${esc(row.label)}" data-tip="${esc(tip)}"><span class="lab">${esc(row.label)}</span><span class="track"><span class="bar${index === top ? ' top' : ''}" style="width:${width}%"></span></span><span class="num">${fmt(row.value)}</span></button></li>`;
      })
      .join('');
    return `<div class="card">${this.head(this._heading, finding, { stats })}<div class="body"><ul class="rows" aria-label="${esc(`${this._heading}. ${finding}`)}">${list}</ul><p class="note"></p></div>${this.foot(truncatedSpan(this._truncated))}</div>`;
  }
}

defineElement('henoyo-kpi-bar', HenoyoKpiBar);
