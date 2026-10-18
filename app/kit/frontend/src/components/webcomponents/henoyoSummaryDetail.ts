// <henoyo-summary-detail>: a list of items beside the one that is open.

import { HenoyoElement, defineElement, emit, esc, glyph } from './henoyoKit';

export type SummaryTone = 'neutral' | 'info' | 'success' | 'warning' | 'danger';

export interface HenoyoSummaryPair {
  label: string;
  value: string;
}

export interface HenoyoSummaryStatus {
  label: string;
  tone: SummaryTone;
}

export interface HenoyoSummaryItem {
  id: string;
  title: string;
  subtitle?: string;
  status?: HenoyoSummaryStatus;
  details: HenoyoSummaryPair[];
  actionLabel?: string;
}

const TONES: Record<SummaryTone, string> = {
  neutral: 'minus',
  info: 'info',
  success: 'check',
  warning: 'triangle-alert',
  danger: 'circle-alert',
};

const isTone = (v: unknown): v is SummaryTone => typeof v === 'string' && Object.hasOwn(TONES, v);

const text = (v: unknown): string | undefined =>
  typeof v === 'string' && v !== '' ? v : undefined;

function normalize(raw: unknown): HenoyoSummaryItem | undefined {
  if (raw === null || typeof raw !== 'object') return undefined;
  const row = raw as Record<string, unknown>;
  const id = text(row['id']);
  const title = text(row['title']);
  if (id === undefined || title === undefined) return undefined;
  const item: HenoyoSummaryItem = { id, title, details: [] };
  const subtitle = text(row['subtitle']);
  if (subtitle !== undefined) item.subtitle = subtitle;
  const status = row['status'];
  if (status !== null && typeof status === 'object') {
    const label = text((status as Record<string, unknown>)['label']);
    if (label !== undefined) {
      const tone = (status as Record<string, unknown>)['tone'];
      item.status = { label, tone: isTone(tone) ? tone : 'neutral' };
    }
  }
  if (Array.isArray(row['details'])) {
    const pairs: HenoyoSummaryPair[] = [];
    for (const pair of row['details']) {
      if (pair === null || typeof pair !== 'object') continue;
      const label = text((pair as Record<string, unknown>)['label']);
      const value = text((pair as Record<string, unknown>)['value']);
      if (label === undefined || value === undefined) continue;
      pairs.push({ label, value });
    }
    item.details = pairs;
  }
  const actionLabel = text(row['actionLabel']);
  if (actionLabel !== undefined) item.actionLabel = actionLabel;
  return item;
}

let seq = 0;

export class HenoyoSummaryDetail extends HenoyoElement {
  private _items: HenoyoSummaryItem[] = [];
  private _selected: string | undefined;
  /** The row the reader opened. The `selected` prop sets it. */
  private _at: string | undefined;
  private _emptyText: string | undefined;
  private _focus = false;
  private readonly uid = `sd${(seq += 1)}`;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      const act = target.closest<HTMLElement>('[data-act]');
      if (act?.dataset['act'] === 'action') {
        const id = this.currentId();
        if (id !== undefined) emit(this, 'henoyo:summary-action', { id });
        return;
      }
      const opt = target.closest<HTMLElement>('[role="option"]');
      const id = opt?.dataset['id'];
      if (id !== undefined) this.select(id, true);
    });
    this.root.addEventListener('keydown', (e) => {
      const key = (e as KeyboardEvent).key;
      if ((e.target as HTMLElement).closest('[role="option"]') === null) return;
      if (key !== 'ArrowDown' && key !== 'ArrowUp' && key !== 'Home' && key !== 'End') return;
      e.preventDefault();
      const items = this._items;
      if (items.length === 0) return;
      const i = this.index();
      const next =
        key === 'Home'
          ? 0
          : key === 'End'
            ? items.length - 1
            : key === 'ArrowDown'
              ? Math.min(items.length - 1, i + 1)
              : Math.max(0, i - 1);
      this.select(items[next]!.id, true);
    });
  }

  get items(): HenoyoSummaryItem[] {
    return this._items;
  }
  set items(v: HenoyoSummaryItem[]) {
    const seen = new Set<string>();
    const items: HenoyoSummaryItem[] = [];
    for (const raw of Array.isArray(v) ? v : []) {
      const item = normalize(raw);
      if (item === undefined || seen.has(item.id)) continue;
      seen.add(item.id);
      items.push(item);
    }
    this._items = items;
    this.invalidate();
  }

  get selected(): string | undefined {
    return this._selected;
  }
  set selected(v: string | undefined) {
    this._selected = text(v);
    this._at = this._selected;
    this.invalidate();
  }

  get emptyText(): string | undefined {
    return this._emptyText;
  }
  set emptyText(v: string | undefined) {
    this._emptyText = text(v);
    this.invalidate();
  }

  private index(): number {
    const at = this._at;
    const found = at === undefined ? -1 : this._items.findIndex((item) => item.id === at);
    return found >= 0 ? found : 0;
  }

  private currentId(): string | undefined {
    return this._items[this.index()]?.id;
  }

  private select(id: string, focus: boolean): void {
    if (!this._items.some((item) => item.id === id) || this.currentId() === id) {
      if (focus) {
        this._focus = true;
        this.invalidate();
      }
      return;
    }
    this._at = id;
    this._focus = focus;
    emit(this, 'henoyo:summary-select', { id });
    this.invalidate();
  }

  protected afterRender(): void {
    if (!this._focus) return;
    this._focus = false;
    this.root.querySelector<HTMLElement>('[role="option"][aria-selected="true"]')?.focus();
  }

  protected styles(): string {
    return `
:host { display:block; container-type:inline-size; container-name:summary-detail; }
.split { display:grid; grid-template-columns:minmax(0,38%) minmax(0,1fr); gap:calc(var(--h-kit-gap, 12px) + 4px); align-items:start; }
.list { display:flex; flex-direction:column; gap:var(--h-space-1, 4px); min-width:0; }
.opt { display:flex; flex-direction:column; gap:var(--h-space-half, 2px); min-width:0; text-align:left; cursor:pointer;
  padding:calc(var(--h-kit-row-py, 10px) - 2px) var(--h-kit-gap, 12px); border-radius:var(--h-radius-control, 8px); border:1px solid transparent;
  background:transparent; color:var(--k-text); }
.opt[aria-selected="true"] { background:var(--k-surface-2); border-color:var(--k-hairline-2); box-shadow:inset 3px 0 0 var(--k-text); }
.row { display:flex; align-items:center; gap:var(--h-space-2, 8px); min-width:0; }
.name { flex:1 1 auto; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:14px; font-weight:600; }
.opt[aria-selected="true"] .name { font-weight:700; }
.sub { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:12.5px; color:var(--k-text-3); }
.st { display:inline-flex; align-items:center; gap:var(--h-space-1, 4px); flex:none; max-width:45%; font-size:12px; font-weight:700; }
.st .word { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.st.success { color:var(--k-ok); }
.st.warning { color:var(--k-warn); }
.st.danger { color:var(--k-bad); }
.st.info { color:var(--k-info); }
.st.neutral { color:var(--k-neutral); }
.detail { min-width:0; padding:var(--h-kit-gap, 12px) calc(var(--h-kit-gap, 12px) + 4px); background:var(--k-surface);
  border:1px solid var(--k-hairline); border-radius:var(--h-radius-card, 12px); color:var(--k-text); }
.detail .heading { margin:0; font-size:calc(var(--h-kit-title-size, 20px) - 4px); font-weight:700; overflow-wrap:anywhere; }
.detail .sub { margin-top:var(--h-space-half, 2px); white-space:normal; }
.pairs { margin:var(--h-space-3, 12px) 0 0; }
.pair { display:grid; grid-template-columns:minmax(0,9rem) minmax(0,1fr); gap:var(--h-space-1, 4px) var(--h-space-3, 12px);
  padding:calc(var(--h-kit-row-py, 10px) - 2px) 0; border-top:1px solid var(--k-hairline); }
.pair dt { font-size:12px; font-weight:700; color:var(--k-text-3); overflow-wrap:anywhere; }
.pair dd { margin:0; font-size:14px; overflow-wrap:anywhere; }
.act { margin-top:var(--h-space-3, 12px); }
.act .btn { max-width:100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.empty { padding:var(--h-space-5, 20px) var(--h-space-4, 16px); border:1px dashed var(--k-hairline-2);
  border-radius:var(--h-radius-card, 12px); color:var(--k-text-3); font-size:14px; }
/* The detail takes the row after the selected option; the listbox stays the accessible parent. */
@container summary-detail (max-width: 640px) {
  .split { display:flex; flex-direction:column; gap:var(--h-space-2, 8px); }
  .list { display:contents; }
  .opt { order:calc(var(--i) * 2); }
  .detail { order:calc(var(--at) * 2 + 1); }
}
`;
  }

  protected view(): string {
    const items = this._items;
    if (items.length === 0) {
      const message = this._emptyText ?? 'Nothing to show yet';
      return `<div class="empty" role="status">${esc(message)}</div>`;
    }
    const open = this.index();
    const options = items
      .map((item, i) => {
        const on = i === open;
        const full = [item.title, item.subtitle, item.status?.label].filter(Boolean).join('. ');
        const hover = item.subtitle ? `${item.title} — ${item.subtitle}` : item.title;
        const status = item.status
          ? `<span class="st ${item.status.tone}" title="${esc(item.status.label)}">${glyph(TONES[item.status.tone], 14)}<span class="word">${esc(item.status.label)}</span></span>`
          : '';
        return `<div class="opt" role="option" id="${this.uid}-o${i}" data-id="${esc(item.id)}" style="--i:${i}" tabindex="${on ? '0' : '-1'}" aria-selected="${on ? 'true' : 'false'}"${on ? ` aria-controls="${this.uid}-detail"` : ''} aria-label="${esc(full)}" title="${esc(hover)}"><span class="row"><span class="name">${esc(item.title)}</span>${status}</span>${item.subtitle ? `<span class="sub">${esc(item.subtitle)}</span>` : ''}</div>`;
      })
      .join('');
    const item = items[open]!;
    const pairs = item.details
      .map(
        (pair) =>
          `<div class="pair"><dt title="${esc(pair.label)}">${esc(pair.label)}</dt><dd title="${esc(pair.value)}">${esc(pair.value)}</dd></div>`,
      )
      .join('');
    const action = item.actionLabel
      ? `<div class="act"><button class="btn primary" type="button" data-act="action" title="${esc(item.actionLabel)}">${esc(item.actionLabel)}</button></div>`
      : '';
    return `<div class="split"><div class="list" role="listbox" aria-label="Items" aria-orientation="vertical">${options}</div><div class="detail" id="${this.uid}-detail" role="region" aria-label="${esc(item.title)} details" style="--at:${open}"><h3 class="heading">${esc(item.title)}</h3>${item.subtitle ? `<p class="sub">${esc(item.subtitle)}</p>` : ''}${item.status ? `<p class="st ${item.status.tone}" style="margin-top:var(--h-space-2, 8px)">${glyph(TONES[item.status.tone], 14)}<span class="word">${esc(item.status.label)}</span></p>` : ''}${pairs === '' ? '' : `<dl class="pairs">${pairs}</dl>`}${action}</div></div>`;
  }
}

defineElement('henoyo-summary-detail', HenoyoSummaryDetail);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-summary-detail': HenoyoSummaryDetail;
  }
}
