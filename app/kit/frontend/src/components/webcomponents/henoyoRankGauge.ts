// <henoyo-rank-gauge>: ranked rows and how many sit strictly above the median.

import { HenoyoElement, defineElement, esc, legend } from './henoyoKit';
import { formatCount } from './vizGroupB.binding';

export interface RankGaugeRow {
  id: string;
  label: string;
  value: number;
}

export interface RankedBar extends RankGaugeRow {
  rank: number;
  above: boolean;
}

export interface RankReading {
  median: number;
  above: number;
  total: number;
  ranked: RankedBar[];
}

const FILTERS = [
  ['all', 'All'],
  ['above', 'Above the median'],
  ['typical', 'Typical'],
] as const;

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function medianOf(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const upper = sorted[mid] ?? 0;
  if (sorted.length % 2 === 1) return upper;
  return ((sorted[mid - 1] ?? 0) + upper) / 2;
}

export function rankReading(rows: readonly RankGaugeRow[]): RankReading {
  const ordered = [...rows].sort(
    (a, b) => b.value - a.value || (a.label < b.label ? -1 : a.label > b.label ? 1 : 0),
  );
  const median = medianOf(ordered.map((row) => row.value));
  const ranked = ordered.map((row, index) => ({
    ...row,
    rank: index + 1,
    above: row.value > median,
  }));
  return {
    median,
    above: ranked.filter((row) => row.above).length,
    total: ranked.length,
    ranked,
  };
}

/** The finding: how many rows sit strictly above the median. */
export function rankFinding(above: number, total: number): string {
  return total === 0 ? 'Nothing to rank yet' : `${above} of ${total} above the median`;
}

function asRows(value: unknown): RankGaugeRow[] {
  if (!Array.isArray(value)) return [];
  const rows: RankGaugeRow[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    const id = text(row['id']);
    if (id === undefined) continue;
    const n = typeof row['value'] === 'number' ? row['value'] : Number(row['value']);
    rows.push({
      id,
      label: text(row['label']) ?? id,
      value: Number.isFinite(n) ? n : 0,
    });
  }
  return rows;
}

function limitOf(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return 10;
  return Math.min(24, Math.max(1, Math.trunc(n)));
}

export class HenoyoRankGauge extends HenoyoElement {
  private _rows: RankGaugeRow[] = [];
  private _limit = 10;
  private _heading: string | undefined;
  private _groupLabel = '';
  private _measureLabel = '';
  private _truncated = false;
  private _filter: 'all' | 'above' | 'typical' = 'all';
  private _selected: string | undefined;

  constructor() {
    super();
    this.root.addEventListener('click', (event) => {
      const node = event.target instanceof Element ? event.target : null;
      const button = node?.closest('button');
      if (button === null || button === undefined) return;
      const act = button.dataset['act'];
      if (act === 'filter') {
        const arg = button.dataset['arg'];
        if (arg === 'all' || arg === 'above' || arg === 'typical') this._filter = arg;
        this.invalidate();
        return;
      }
      if (act !== 'bar') return;
      const id = button.dataset['id'];
      this._selected = this._selected === id ? undefined : id;
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
  get rows(): RankGaugeRow[] {
    return this._rows;
  }
  set rows(value: RankGaugeRow[]) {
    this._rows = asRows(value);
    this._filter = 'all';
    this._selected = undefined;
    this.invalidate();
  }
  get limit(): number {
    return this._limit;
  }
  set limit(value: number) {
    this._limit = limitOf(value);
    this.invalidate();
  }
  get groupLabel(): string {
    return this._groupLabel;
  }
  set groupLabel(value: string) {
    this._groupLabel = text(value) ?? '';
    this.invalidate();
  }
  get measureLabel(): string {
    return this._measureLabel;
  }
  set measureLabel(value: string) {
    this._measureLabel = text(value) ?? '';
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
.filters { display:flex; flex-wrap:wrap; gap:6px; margin:0 0 8px; }
.bars { list-style:none; margin:0; padding:0; }
.bar { display:grid; grid-template-columns:1.6rem minmax(0,1.1fr) minmax(6rem,1.6fr) auto; gap:8px; align-items:center;
  width:100%; text-align:left; background:transparent; border:0; border-bottom:1px solid var(--k-hairline); padding:7px 2px; cursor:pointer; font:inherit; color:inherit; }
.bar[aria-pressed="true"] { background:var(--k-surface-2); }
.rk { font-variant-numeric:tabular-nums; color:var(--k-text-3); font-size:12px; }
.name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:13px; }
.val { font-variant-numeric:tabular-nums; font-size:13px; font-weight:600; text-align:right; }
.trackbar { position:relative; height:8px; background:var(--k-surface-2); border-radius:2px; }
.fillbar { position:absolute; left:0; top:0; bottom:0; border-radius:2px; }
.fillbar.above { background:var(--k-accent); }
.fillbar.typical { background:var(--k-text-3); opacity:.5; }
.med { position:absolute; top:-3px; bottom:-3px; width:0; border-left:1px dashed var(--k-text-3); }
.detail { margin:10px 0 0; font-size:13px; }
@media (max-width: 720px) { .bar { grid-template-columns:1.4rem minmax(0,1fr) auto; } .trackbar { display:none; } }`;
  }

  protected override view(): string {
    const reading = rankReading(this._rows);
    const eyebrow = this._heading ?? (this._measureLabel || 'Rank');
    if (reading.total === 0) return this.emptyCard(eyebrow, rankFinding(0, 0));
    const by = [this._groupLabel ? `By ${this._groupLabel}` : '', this._measureLabel]
      .filter((part) => part !== '')
      .join(' · ');
    const max = Math.max(0, ...reading.ranked.map((row) => row.value));
    const shown = reading.ranked
      .filter(
        (row) => this._filter === 'all' || (this._filter === 'above' ? row.above : !row.above),
      )
      .slice(0, this._limit);
    const totalValue = reading.ranked.reduce((sum, row) => sum + row.value, 0);
    const bars = shown
      .map((row) => {
        const width = max <= 0 ? 0 : (Math.max(0, row.value) / max) * 100;
        const mark =
          max > 0 && reading.median > 0
            ? `<span class="med" style="left:${Math.min(100, (reading.median / max) * 100).toFixed(2)}%"></span>`
            : '';
        const band = row.above ? 'above' : 'typical';
        const pressed = this._selected === row.id ? 'true' : 'false';
        return `<li><button type="button" class="bar" data-act="bar" data-id="${esc(row.id)}" data-rank="${row.rank}" data-above="${row.above ? '1' : '0'}" aria-pressed="${pressed}"><span class="rk">${row.rank}</span><span class="name">${esc(row.label)}</span><span class="trackbar"><span class="fillbar ${band}" style="width:${width.toFixed(2)}%"></span>${mark}</span><span class="val">${esc(formatCount(row.value))}</span></button></li>`;
      })
      .join('');
    const selected = reading.ranked.find((row) => row.id === this._selected);
    const share =
      selected === undefined || totalValue === 0
        ? 0
        : Math.round((selected.value / totalValue) * 100);
    const detail =
      selected === undefined
        ? ''
        : `<p class="detail">Rank ${selected.rank} · ${esc(selected.label)} · ${esc(formatCount(selected.value))} (${share}% of the total).</p>`;
    const emptyBand = shown.length === 0 ? `<p class="muted">Nothing in this band.</p>` : '';
    const filters = FILTERS.map(
      ([arg, label]) =>
        `<button type="button" class="btn${this._filter === arg ? ' primary' : ''}" data-act="filter" data-arg="${arg}" aria-pressed="${this._filter === arg ? 'true' : 'false'}">${label}</button>`,
    ).join('');
    const key = legend([
      { label: 'Above the median', color: 'var(--k-accent)' },
      { label: 'Typical', color: 'var(--k-text-3)', swatchStyle: 'opacity:.5' },
      {
        label: 'Median',
        color: 'transparent',
        swatchStyle: 'width:0;border-radius:0;border-left:1px dashed var(--k-text-3)',
      },
    ]);
    return `<div class="card">${this.head(eyebrow, rankFinding(reading.above, reading.total), {
      sub: by,
      stats: [{ text: `Median ${formatCount(reading.median)}` }],
    })}<div class="body">
      <div class="filters">${filters}</div>
      <ol class="bars" aria-label="${esc(rankFinding(reading.above, reading.total))}">${bars}</ol>${emptyBand}${detail}${key}
      </div>${this.foot(this._truncated ? '<span>The report is showing a partial result.</span>' : '')}</div>`;
  }
}

defineElement('henoyo-rank-gauge', HenoyoRankGauge);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-rank-gauge': HenoyoRankGauge;
  }
}
