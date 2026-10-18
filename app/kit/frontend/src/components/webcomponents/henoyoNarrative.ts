// <henoyo-narrative>: one sentence from a grouped report, then the largest values.

import { HenoyoElement, defineElement, esc } from './henoyoKit';
import { formatCount, type NarrativeItem } from './vizGroupB.binding';

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function asItems(value: unknown): NarrativeItem[] {
  if (!Array.isArray(value)) return [];
  const items: NarrativeItem[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    const id = text(row['id']);
    if (id === undefined) continue;
    const valueN = typeof row['value'] === 'number' ? row['value'] : Number(row['value']);
    const shareN = typeof row['share'] === 'number' ? row['share'] : Number(row['share']);
    items.push({
      id,
      label: text(row['label']) ?? id,
      value: Number.isFinite(valueN) ? valueN : 0,
      share: Number.isFinite(shareN) ? shareN : 0,
    });
  }
  return items.slice(0, 6);
}

export class HenoyoNarrative extends HenoyoElement {
  private _heading: string | undefined;
  private _groupLabel = '';
  private _measureLabel = '';
  private _sentence = '';
  private _total = 0;
  private _count = 0;
  private _items: NarrativeItem[] = [];
  private _truncated = false;
  private _selected: string | undefined;

  constructor() {
    super();
    this.root.addEventListener('click', (event) => {
      const node = event.target instanceof Element ? event.target : null;
      const button = node?.closest('button');
      if (button?.dataset['act'] !== 'item') return;
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
  get sentence(): string {
    return this._sentence;
  }
  set sentence(value: string) {
    this._sentence = text(value) ?? '';
    this.invalidate();
  }
  get total(): number {
    return this._total;
  }
  set total(value: number) {
    const n = typeof value === 'number' ? value : Number(value);
    this._total = Number.isFinite(n) ? n : 0;
    this.invalidate();
  }
  get count(): number {
    return this._count;
  }
  set count(value: number) {
    const n = typeof value === 'number' ? value : Number(value);
    this._count = Number.isFinite(n) ? n : 0;
    this.invalidate();
  }
  get items(): NarrativeItem[] {
    return this._items;
  }
  set items(value: NarrativeItem[]) {
    this._items = asItems(value);
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
.bars { list-style:none; margin:0; padding:0; }
.item { display:grid; grid-template-columns:1.4rem minmax(0,1.2fr) minmax(5rem,1.4fr) 4.5rem 3rem; gap:8px; align-items:center;
  width:100%; text-align:left; background:transparent; border:0; border-bottom:1px solid var(--k-hairline); padding:7px 2px; cursor:pointer; font:inherit; color:inherit; font-size:13px; }
.item[aria-pressed="true"] { background:var(--k-surface-2); }
.rk, .share { font-variant-numeric:tabular-nums; color:var(--k-text-3); }
.rk { font-size:12px; }
.share { text-align:right; }
.val { text-align:right; white-space:nowrap; font-variant-numeric:tabular-nums; font-weight:600; }
.name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.track { height:8px; background:var(--k-surface-2); border-radius:2px; }
.fill { display:block; height:100%; border-radius:2px; background:var(--k-text-3); opacity:.5; }
.fill.top { background:var(--k-accent); opacity:1; }
.detail { margin:10px 0 0; font-size:13px; }
@media (max-width: 720px) { .item { grid-template-columns:1.2rem minmax(0,1fr) auto; } .track, .share { display:none; } }`;
  }

  protected override view(): string {
    const eyebrow =
      this._heading ?? (this._groupLabel === '' ? 'In one reading' : `By ${this._groupLabel}`);
    if (this._sentence === '' && this._items.length === 0)
      return this.emptyCard(eyebrow, 'Nothing to summarise yet');
    const title = this._sentence === '' ? eyebrow : this._sentence;
    const selected = this._items.find((item) => item.id === this._selected);
    const detail =
      selected === undefined
        ? ''
        : `<p class="detail">${esc(selected.label)} · ${esc(formatCount(selected.value))} (${selected.share}% of the total).</p>`;
    const notes: string[] = [];
    if (this._count > this._items.length)
      notes.push(`<span>Showing the largest ${this._items.length} of ${this._count}.</span>`);
    if (this._truncated) notes.push('<span>The report is showing a partial result.</span>');
    const bars = this._items
      .map((item, index) => {
        const pressed = this._selected === item.id ? 'true' : 'false';
        return `<li><button type="button" class="item" data-act="item" data-id="${esc(item.id)}" aria-pressed="${pressed}"><span class="rk">${index + 1}</span><span class="name">${esc(item.label)}</span><span class="track"><span class="fill${index === 0 ? ' top' : ''}" style="width:${Math.max(0, Math.min(100, item.share))}%"></span></span><span class="val">${esc(formatCount(item.value))}</span><span class="share">${item.share}%</span></button></li>`;
      })
      .join('');
    const total = `${formatCount(this._total)}${this._measureLabel === '' ? '' : ` ${this._measureLabel}`}`;
    return `<div class="card">${this.head(eyebrow, title, { stats: [{ text: total }] })}<div class="body"><ol class="bars" aria-label="${esc(title)}">${bars}</ol>${detail}</div>${this.foot(notes.join(''))}</div>`;
  }
}

defineElement('henoyo-narrative', HenoyoNarrative);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-narrative': HenoyoNarrative;
  }
}
