// <henoyo-zone-enclosure>: related records grouped into zones, with a line when one points at another.

import { HenoyoElement, defineElement, esc, truncatedSpan, type KitStat } from './henoyoKit';
import { openAttrs, wireRecordOpen } from './vizGraph';

export interface EnclosureNode {
  id: string;
  label: string;
  fill: string;
  stroke: string;
  outline: boolean;
  objectApiName: string;
  recordId: string;
  openable: boolean;
  tip: string;
}

export interface EnclosureBand {
  key: string;
  label: string;
  nodes: EnclosureNode[];
}

export interface EnclosureLink {
  from: string;
  to: string;
}

const MAX_CHIPS = 12;

/** The finding: how many records sit in the busiest zone. */
export function zoneMapFinding(bands: readonly Pick<EnclosureBand, 'label' | 'nodes'>[]): string {
  const top = bands.reduce<(typeof bands)[number] | undefined>(
    (best, band) => (best === undefined || band.nodes.length > best.nodes.length ? band : best),
    undefined,
  );
  const n = top?.nodes.length ?? 0;
  return `${n} record${n === 1 ? '' : 's'} in ${top?.label ?? 'no zone'}`;
}

export class HenoyoZoneEnclosure extends HenoyoElement {
  private _heading = 'Zones';
  private _bands: EnclosureBand[] = [];
  private _links: EnclosureLink[] = [];
  private _truncated = false;

  constructor() {
    super();
    wireRecordOpen(this.root, this);
    this.root.addEventListener('mouseover', (event) => {
      const raw = event.target;
      if (!(raw instanceof Element)) return;
      const node = raw.closest('[data-tip]');
      const note = this.root.querySelector('.note');
      if (note) note.textContent = node?.getAttribute('data-tip') ?? '';
    });
  }

  get heading(): string {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v && v.trim() !== '' ? v : 'Zones';
    this.invalidate();
  }
  get bands(): EnclosureBand[] {
    return this._bands;
  }
  set bands(v: EnclosureBand[] | undefined) {
    this._bands = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get links(): EnclosureLink[] {
    return this._links;
  }
  set links(v: EnclosureLink[] | undefined) {
    this._links = Array.isArray(v) ? v : [];
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
    return `.zones { display:grid; grid-template-columns:repeat(auto-fit, minmax(190px, 1fr)); gap:10px; }
.zone { border:1px solid var(--k-hairline); border-radius:10px; padding:10px 12px 12px; background:var(--k-surface); }
.zh { display:flex; align-items:center; gap:6px; margin-bottom:8px; font-size:12px; font-weight:600; }
.zh .sw { width:10px; height:10px; }
.zh .ct { margin-left:auto; color:var(--k-text-3); font-variant-numeric:tabular-nums; font-weight:400; }
.recs { display:flex; flex-wrap:wrap; gap:6px; }
.rec { display:inline-flex; align-items:center; gap:6px; max-width:100%; padding:3px 9px; border-radius:999px; font-size:12px;
  background:var(--k-surface-2); border:1px solid var(--k-hairline); cursor:pointer; }
.rec:hover { border-color:var(--k-hairline-2); }
.rec .dot { width:8px; height:8px; border-radius:999px; flex:none; }
.rec .nm { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.more { padding:3px 4px; font-size:12px; color:var(--k-text-3); }
`;
  }

  protected view(): string {
    const bands = this._bands.filter((band) => band && Array.isArray(band.nodes));
    const count = bands.reduce((sum, band) => sum + band.nodes.length, 0);
    if (count === 0) {
      return this.emptyCard(
        this._heading,
        'Nothing to show yet',
        'No related records have been placed in a zone yet.',
      );
    }
    const sch = this.scheme();
    const byId = new Map(bands.flatMap((band) => band.nodes.map((node) => [node.id, node])));
    const target = new Map(this._links.map((link) => [link.from, byId.get(link.to)?.label]));
    const panels = bands
      .map((band, index) => {
        const paint = sch.series[index % sch.series.length] ?? sch.other;
        const chips = band.nodes
          .slice(0, MAX_CHIPS)
          .map((node) => {
            const to = target.get(node.id);
            const tip = to === undefined ? node.tip : `${node.tip} — points at ${to}`;
            return `<span class="rec" data-tip="${esc(tip)}"${openAttrs(node)}><span class="dot" style="background:${esc(node.stroke)}"></span><span class="nm">${esc(node.label)}</span></span>`;
          })
          .join('');
        const more =
          band.nodes.length > MAX_CHIPS
            ? `<span class="more">+${band.nodes.length - MAX_CHIPS} more</span>`
            : '';
        return `<section class="zone"><div class="zh"><span class="sw" style="background:${esc(paint.stroke)}"></span>${esc(band.label)}<span class="ct">${band.nodes.length}</span></div><div class="recs">${chips}${more}</div></section>`;
      })
      .join('');
    const linked = this._links.filter((link) => byId.has(link.from) && byId.has(link.to)).length;
    const stats: KitStat[] = [{ text: `${bands.length} zone${bands.length === 1 ? '' : 's'}` }];
    const sub =
      linked > 0 ? 'Point at a record to see what it points at.' : 'Select a record to open it.';
    const finding = zoneMapFinding(bands);
    return `<div class="card">${this.head(this._heading, finding, { stats, sub })}<div class="body"><div class="zones" role="group" aria-label="${esc(`${this._heading}. ${finding}`)}">${panels}</div><p class="note"></p></div>${this.foot(truncatedSpan(this._truncated))}</div>`;
  }
}

defineElement('henoyo-zone-enclosure', HenoyoZoneEnclosure);
