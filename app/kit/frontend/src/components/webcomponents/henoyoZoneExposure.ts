// <henoyo-zone-exposure>: two report groupings as a matrix. Paper is empty, oxblood is the peak.

import {
  HenoyoElement,
  defineElement,
  esc,
  finite,
  truncatedSpan,
  type KitStat,
} from './henoyoKit';
import { fmt } from './vizPalette';

export interface ZoneAxis {
  key: string;
  label: string;
}

export interface ZoneCell {
  row: string;
  col: string;
  value: number;
  fill: string;
  ink: string;
  diagonal: boolean;
  crosses: boolean;
}

/** The finding: the largest flow between two different zones. */
export function zoneFinding(zones: readonly ZoneAxis[], cells: readonly ZoneCell[]): string {
  let best: ZoneCell | undefined;
  for (const cell of cells) {
    const value = finite(cell.value) ?? 0;
    if (cell.row === cell.col || value <= 0) continue;
    if (best === undefined || value > (finite(best.value) ?? 0)) best = cell;
  }
  if (best === undefined) return 'Nothing crosses between zones';
  const name = (key: string): string => zones.find((zone) => zone.key === key)?.label ?? key;
  const value = finite(best.value) ?? 0;
  return `${fmt(value)} cross${value === 1 ? 'es' : ''} from ${name(best.row)} to ${name(best.col)}`;
}

export class HenoyoZoneExposure extends HenoyoElement {
  private _heading = 'Zone exposure';
  private _zones: ZoneAxis[] = [];
  private _cells: ZoneCell[] = [];
  private _truncated = false;

  constructor() {
    super();
    this.root.addEventListener('click', (event) => {
      const raw = event.target;
      if (!(raw instanceof Element)) return;
      const cell = raw.closest('[data-tip]');
      for (const other of this.root.querySelectorAll('.cell.sel')) other.classList.remove('sel');
      cell?.classList.add('sel');
      const note = this.root.querySelector('.note');
      if (note) note.textContent = cell?.getAttribute('data-tip') ?? '';
    });
  }

  get heading(): string {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v && v.trim() !== '' ? v : 'Zone exposure';
    this.invalidate();
  }
  get zones(): ZoneAxis[] {
    return this._zones;
  }
  set zones(v: ZoneAxis[] | undefined) {
    this._zones = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get cells(): ZoneCell[] {
    return this._cells;
  }
  set cells(v: ZoneCell[] | undefined) {
    this._cells = Array.isArray(v) ? v : [];
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
    return `.sc { overflow-x:auto; padding-bottom:4px; }
.mx { display:grid; gap:3px; align-items:stretch; min-width:max-content; }
.mx > .hd:not(.col) { position:sticky; left:0; z-index:1; background:var(--k-surface); padding-right:6px; }
.hd, .cell { font-size:12px; }
.hd { color:var(--k-text-2); display:flex; align-items:center; }
.hd.col { justify-content:center; text-align:center; align-items:flex-end; }
.cell { min-height:2.2rem; border:0; border-radius:6px; font-variant-numeric:tabular-nums; font-weight:600; cursor:pointer; }
.cell.sel { box-shadow:0 0 0 2px var(--k-brand); }
`;
  }

  protected view(): string {
    const zones = this._zones.filter((zone) => zone && typeof zone.label === 'string');
    if (zones.length === 0) {
      return this.emptyCard(
        this._heading,
        'Nothing to show yet',
        'No records match this report yet.',
      );
    }
    const byKey = new Map(this._cells.map((cell) => [`${cell.row}\0${cell.col}`, cell]));
    const crossing = this._cells.filter(
      (cell) => cell.crosses && (finite(cell.value) ?? 0) > 0,
    ).length;
    const total = this._cells.reduce((sum, cell) => sum + (finite(cell.value) ?? 0), 0);
    const stats: KitStat[] = [{ text: `${fmt(total)} connections` }];
    if (crossing > 0)
      stats.push({ text: `${fmt(crossing)} cross more than one boundary`, tone: 'warn' });
    const columns = `minmax(5.5rem, 7.5rem) repeat(${zones.length}, minmax(2.6rem, 1fr))`;
    const heads = zones.map((zone) => `<div class="hd col">${esc(zone.label)}</div>`).join('');
    const body = zones
      .map((row) => {
        const label = `<div class="hd">${esc(row.label)}</div>`;
        const cells = zones
          .map((col) => {
            const cell = byKey.get(`${row.key}\0${col.key}`);
            const value = finite(cell?.value) ?? 0;
            const fill = cell?.fill ?? 'var(--k-surface-2)';
            const ink = cell?.ink ?? 'var(--k-text)';
            const tip = `${row.label} → ${col.label} — ${fmt(value)}.${cell?.diagonal === true ? ' Same zone.' : ''}${cell?.crosses === true ? ' Crosses more than one boundary.' : ''}`;
            return `<button type="button" class="cell" style="background:${esc(fill)};color:${esc(ink)}" data-tip="${esc(tip)}" aria-label="${esc(tip)}">${fmt(value)}</button>`;
          })
          .join('');
        return label + cells;
      })
      .join('');
    return `<div class="card">${this.head(this._heading, zoneFinding(zones, this._cells), { stats, sub: 'Read from the row zone across to the column zone.' })}<div class="body"><div class="sc"><div class="mx" style="grid-template-columns:${columns}"><div></div>${heads}${body}</div></div><p class="note"></p></div>${this.foot(truncatedSpan(this._truncated))}</div>`;
  }
}

defineElement('henoyo-zone-exposure', HenoyoZoneExposure);
