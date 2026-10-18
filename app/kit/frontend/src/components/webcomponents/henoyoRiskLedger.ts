// <henoyo-risk-ledger>: the highest rows of one report measure, in rank order.

import { kitLocale } from './colourScheme';
import { HenoyoElement, defineElement, esc } from './henoyoKit';

export interface LedgerRow {
  rank: number;
  label: string;
  value: number;
  share: number;
}

function isRow(value: unknown): value is LedgerRow {
  if (value === null || typeof value !== 'object') return false;
  const row = value as LedgerRow;
  return (
    Number.isFinite(row.rank) &&
    typeof row.label === 'string' &&
    Number.isFinite(row.value) &&
    Number.isFinite(row.share)
  );
}

const TOP = 3;

/** The finding: how much of the whole the leading rows carry. */
export function ledgerFinding(rows: readonly LedgerRow[], sum: number, measure: string): string {
  const lead = rows.slice(0, TOP);
  if (lead.length === 0 || !(sum > 0)) return 'Nothing ranked yet';
  const pct = Math.round((lead.reduce((acc, row) => acc + row.value, 0) / sum) * 100);
  const what = measure === '' ? 'the total' : measure;
  return lead.length === 1
    ? `The top row carries ${pct}% of ${what}`
    : `Top ${lead.length} carry ${pct}% of ${what}`;
}

function formatValue(value: number): string {
  return value.toLocaleString(kitLocale(), { maximumFractionDigits: 2 });
}

export class HenoyoRiskLedger extends HenoyoElement {
  private _heading: string | undefined;
  private _rows: LedgerRow[] = [];
  private _valueLabel = '';
  private _total = 0;
  private _sum = 0;
  private _truncated = false;

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(value: string | undefined) {
    this._heading = typeof value === 'string' && value !== '' ? value : undefined;
    this.invalidate();
  }

  get rows(): LedgerRow[] {
    return this._rows;
  }
  set rows(value: LedgerRow[]) {
    this._rows = Array.isArray(value) ? value.filter(isRow) : [];
    this.invalidate();
  }

  get valueLabel(): string {
    return this._valueLabel;
  }
  set valueLabel(value: string | undefined) {
    this._valueLabel = typeof value === 'string' ? value : '';
    this.invalidate();
  }

  get total(): number {
    return this._total;
  }
  set total(value: number | undefined) {
    this._total = typeof value === 'number' && Number.isFinite(value) ? value : 0;
    this.invalidate();
  }

  get sum(): number {
    return this._sum;
  }
  set sum(value: number | undefined) {
    this._sum = typeof value === 'number' && Number.isFinite(value) ? value : 0;
    this.invalidate();
  }

  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(value: boolean | undefined) {
    this._truncated = value === true;
    this.invalidate();
  }

  protected styles(): string {
    return `
.rows { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:8px; }
.row { display:grid; grid-template-columns:1.5rem minmax(0,1fr) minmax(80px,1.2fr) 6.5rem; gap:10px; align-items:center; font-size:13px; }
.rank { font-variant-numeric:tabular-nums; color:var(--k-text-3); font-size:12px; }
.name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.track { height:8px; background:var(--k-surface-2); border-radius:999px; overflow:hidden; }
.fill { display:block; height:100%; border-radius:2px; background:var(--k-text-3); opacity:.5; }
.fill.top { background:var(--k-accent); opacity:1; }
.val { font-variant-numeric:tabular-nums; text-align:right; white-space:nowrap; }
`;
  }

  protected view(): string {
    const eyebrow = this._heading ?? 'Ranking';
    if (this._rows.length === 0) return this.emptyCard(eyebrow, 'Nothing ranked yet');
    const rows = this._rows
      .map((row, index) => {
        const width = Math.max(0, Math.min(1, row.share)) * 100;
        return `<li class="row">
          <span class="rank">${esc(row.rank)}</span>
          <span class="name">${esc(row.label)}</span>
          <span class="track" aria-hidden="true"><span class="fill${index < TOP ? ' top' : ''}" style="width:${width.toFixed(1)}%"></span></span>
          <span class="val">${esc(formatValue(row.value))}</span>
        </li>`;
      })
      .join('');
    const notes: string[] = [];
    if (this._total > this._rows.length) {
      notes.push(
        `<span>Showing the top ${this._rows.length.toLocaleString(kitLocale())} of ${this._total.toLocaleString(kitLocale())}.</span>`,
      );
    }
    if (this._truncated) notes.push('<span>Some groups are not in this ranking.</span>');
    return `<div class="card">${this.head(eyebrow, ledgerFinding(this._rows, this._sum, this._valueLabel))}<div class="body"><ol class="rows" aria-label="${esc(this._heading ?? (this._valueLabel || 'Ranking'))}">${rows}</ol></div>${this.foot(notes.join(''))}</div>`;
  }
}

defineElement('henoyo-risk-ledger', HenoyoRiskLedger);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-risk-ledger': HenoyoRiskLedger;
  }
}
