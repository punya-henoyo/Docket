// <henoyo-board>: a queue of records as columns, one per status, so people can see what is in each state.

import {
  DAY_MS,
  HenoyoElement,
  defineElement,
  emit,
  esc,
  fmtDate,
  glyph,
  humanize,
  ms,
  span,
} from './henoyoKit';

export type BoardRole =
  | 'stage'
  | 'outcome_positive'
  | 'outcome_negative'
  | 'outcome_neutral'
  | 'hold';

export interface HenoyoBoardColumn {
  value: string;
  label: string;
  /** Absent reads as a stage. */
  role?: BoardRole;
}

export interface HenoyoBoardCard {
  id: string;
  title: string;
  /** The value of the column the card sits in. */
  column: string;
  /** Owner's display name, shown as plain text. */
  owner?: string;
  severity?: string;
  due?: string;
  /** When the card entered its column; shows as "N days here". */
  since?: string;
}

/** Cards shown per column before "N more". */
export const BOARD_PER_COLUMN = 8;

const SEVERITY: Record<string, { word: string; icon: string }> = {
  critical: { word: 'Critical', icon: 'circle-alert' },
  high: { word: 'High', icon: 'triangle-alert' },
  medium: { word: 'Medium', icon: 'info' },
  low: { word: 'Low', icon: 'minus' },
};

const ROLE_WORD: Partial<Record<BoardRole, string>> = {
  outcome_positive: 'Outcome',
  outcome_negative: 'Outcome',
  outcome_neutral: 'Outcome',
  hold: 'On hold',
};

export class HenoyoBoard extends HenoyoElement {
  private _heading: string | undefined;
  private _columns: HenoyoBoardColumn[] = [];
  private _cards: HenoyoBoardCard[] = [];
  private _editable = false;
  private _decisionControlled: string[] = [];
  private _maxPerColumn = BOARD_PER_COLUMN;
  private _expanded = new Set<string>();
  /** The card whose "Move to" menu is open. */
  private _menu: string | null = null;
  private _drag: string | null = null;
  /** Optimistic placements: card id -> column it was moved to, until the host settles or data refreshes. */
  private _pending = new Map<string, string>();
  /** Card picked up with the keyboard, and the column it is currently over. */
  private _held: string | null = null;
  private _heldOver: string | null = null;
  /** Spoken (live region) and shown message about the last move. */
  private _notice = '';
  private _noticeBad = false;
  private _refocus: string | null = null;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-act]');
      if (!target) return;
      const arg = target.dataset.arg;
      const to = target.dataset.to;
      switch (target.dataset.act) {
        case 'menu':
          this._menu = this._menu === arg ? null : (arg ?? null);
          this.invalidate();
          break;
        case 'move':
          if (arg !== undefined && to !== undefined) this.request(arg, to);
          break;
        case 'reopen':
          if (arg !== undefined && this._editable)
            emit(this, 'henoyo:decision-requested', { id: arg, value: null });
          break;
        case 'more':
          if (arg !== undefined) {
            if (!this._expanded.delete(arg)) this._expanded.add(arg);
            this.invalidate();
          }
          break;
        case 'jump':
          this.root
            .querySelector<HTMLElement>(`[data-col="${CSS.escape(arg ?? '')}"]`)
            ?.scrollIntoView?.({ inline: 'start', block: 'nearest' });
          for (const b of this.root.querySelectorAll<HTMLElement>('.switch [data-act="jump"]'))
            b.toggleAttribute('aria-current', b === target);
          target.scrollIntoView?.({ inline: 'center', block: 'nearest' });
          break;
      }
    });
    this.root.addEventListener(
      'scroll',
      (e) => {
        if ((e.target as HTMLElement).classList?.contains('cols')) this.edge();
      },
      true,
    );
    this.root.addEventListener('keydown', (e) => {
      const ev = e as KeyboardEvent;
      const cardEl = (ev.target as HTMLElement).closest<HTMLElement>('[data-card]');
      if (this._held !== null || (cardEl !== null && ev.target === cardEl)) {
        if (this.cardKey(ev, cardEl)) return;
      }
      if (ev.key !== 'Escape' || this._menu === null) return;
      const id = this._menu;
      this._menu = null;
      this.invalidate();
      queueMicrotask(() =>
        queueMicrotask(() =>
          this.root
            .querySelector<HTMLElement>(`[data-act="menu"][data-arg="${CSS.escape(id)}"]`)
            ?.focus(),
        ),
      );
    });
    this.root.addEventListener('dragstart', (e) => {
      const card = (e.target as HTMLElement).closest<HTMLElement>('[data-card]');
      if (!card || !this._editable) return;
      this._drag = card.dataset.card ?? null;
      (e as DragEvent).dataTransfer?.setData('text/plain', this._drag ?? '');
    });
    this.root.addEventListener('dragend', () => {
      this._drag = null;
      this.mark(null);
    });
    this.root.addEventListener('dragover', (e) => {
      const col = (e.target as HTMLElement).closest<HTMLElement>('[data-col]');
      if (this._drag === null || !col) return;
      e.preventDefault();
      this.mark(col.dataset.col ?? null);
    });
    this.root.addEventListener('dragleave', (e) => {
      const rel = (e as DragEvent).relatedTarget as Node | null;
      if (rel === null || !this.root.contains(rel)) this.mark(null);
    });
    this.root.addEventListener('drop', (e) => {
      const col = (e.target as HTMLElement).closest<HTMLElement>('[data-col]');
      this.mark(null);
      if (!col || this._drag === null) return;
      e.preventDefault();
      const id = this._drag;
      this._drag = null;
      if (col.dataset.col !== undefined) this.request(id, col.dataset.col);
    });
  }

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v;
    this.invalidate();
  }
  get columns(): HenoyoBoardColumn[] {
    return this._columns;
  }
  set columns(v: HenoyoBoardColumn[]) {
    this._columns = Array.isArray(v) ? v.filter((c) => c && typeof c.value === 'string') : [];
    this.invalidate();
  }
  get cards(): HenoyoBoardCard[] {
    return this._cards;
  }
  set cards(v: HenoyoBoardCard[]) {
    this._cards = Array.isArray(v)
      ? v.filter((c) => c && typeof c.id === 'string' && typeof c.column === 'string')
      : [];
    this._menu = null;
    this._pending.clear();
    this.invalidate();
  }
  get editable(): boolean {
    return this._editable;
  }
  set editable(v: boolean | undefined) {
    this._editable = v === true;
    this.invalidate();
  }
  /** Values that only a decision can set; a card is never moved to one. */
  get decisionControlled(): string[] {
    return this._decisionControlled;
  }
  set decisionControlled(v: string[] | undefined) {
    this._decisionControlled = Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    this.invalidate();
  }
  get maxPerColumn(): number {
    return this._maxPerColumn;
  }
  set maxPerColumn(v: number | undefined) {
    this._maxPerColumn =
      typeof v === 'number' && Number.isFinite(v) && v >= 1 ? Math.floor(v) : BOARD_PER_COLUMN;
    this.invalidate();
  }

  private colOf(c: HenoyoBoardCard): string {
    return this._pending.get(c.id) ?? c.column;
  }

  /** Highlights the column a card would land in; touches the DOM only, so a drag is not interrupted. */
  private mark(value: string | null): void {
    for (const col of this.root.querySelectorAll<HTMLElement>('[data-col]'))
      col.classList.toggle('drop', value !== null && col.dataset.col === value);
  }

  private say(text: string, bad = false): void {
    this._notice = text;
    this._noticeBad = bad;
    const live = this.root.querySelector<HTMLElement>('.live');
    if (live) {
      live.textContent = text;
    }
    const err = this.root.querySelector<HTMLElement>('.err');
    if (err) err.textContent = bad ? text : '';
  }

  /** Columns a keyboard move can land on, in order; decision-only ones are skipped as in the menu. */
  private landings(): string[] {
    return this._columns.filter((k) => !this.controlled(k.value)).map((k) => k.value);
  }

  /** Space picks up, arrows choose a column, Space drops, Escape cancels. Returns true when handled. */
  private cardKey(e: KeyboardEvent, cardEl: HTMLElement | null): boolean {
    if (!this._editable) return false;
    const key = e.key;
    if (this._held === null) {
      if (key !== ' ' && key !== 'Spacebar') return false;
      const id = cardEl?.dataset.card;
      const card = this._cards.find((c) => c.id === id);
      if (card === undefined || this.controlled(this.colOf(card))) return false;
      e.preventDefault();
      this._held = card.id;
      this._heldOver = this.colOf(card);
      cardEl?.classList.add('held');
      cardEl?.setAttribute('aria-grabbed', 'true');
      this.mark(this._heldOver);
      this.say(
        `Picked up ${card.title}. Use the left and right arrow keys to choose a column, Space to drop, Escape to cancel.`,
      );
      return true;
    }
    const card = this._cards.find((c) => c.id === this._held);
    const cancel = (): void => {
      this._held = null;
      this._heldOver = null;
      this.mark(null);
      this.root.querySelector('.held')?.classList.remove('held');
      this.root.querySelector('[aria-grabbed]')?.removeAttribute('aria-grabbed');
    };
    if (card === undefined) {
      cancel();
      return false;
    }
    if (key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      cancel();
      this.say(`Move cancelled. ${card.title} stays where it was.`);
      return true;
    }
    if (key === 'ArrowLeft' || key === 'ArrowRight') {
      e.preventDefault();
      const cols = this.landings();
      const at = Math.max(0, cols.indexOf(this._heldOver ?? ''));
      const next =
        cols[Math.min(cols.length - 1, Math.max(0, at + (key === 'ArrowRight' ? 1 : -1)))];
      if (next === undefined) return true;
      this._heldOver = next;
      this.mark(next);
      const label = this._columns.find((k) => k.value === next)?.label ?? next;
      this.say(`Over ${label}.`);
      return true;
    }
    if (key === ' ' || key === 'Spacebar' || key === 'Enter') {
      e.preventDefault();
      const to = this._heldOver ?? this.colOf(card);
      cancel();
      this._refocus = card.id;
      this.request(card.id, to);
      return true;
    }
    return false;
  }

  /** Puts a card back after the host reports that the save failed. */
  private rollback(id: string, to: string, error: unknown): void {
    if (this._pending.get(id) === to) this._pending.delete(id);
    const card = this._cards.find((c) => c.id === id);
    const reason =
      error instanceof Error && error.message !== ''
        ? error.message
        : 'The server refused the change.';
    this._refocus = id;
    this.say(`Could not move ${card?.title ?? 'the card'}: ${reason}`, true);
    this.invalidate();
  }

  private controlled(value: string): boolean {
    return this._decisionControlled.includes(value);
  }

  /** One path for the menu and for a drop, so a drag cannot reach what the menu does not. */
  private request(id: string, to: string): void {
    this._menu = null;
    const card = this._cards.find((c) => c.id === id);
    if (!this._editable || card === undefined || this.colOf(card) === to) {
      this.invalidate();
      return;
    }
    if (!this._columns.some((c) => c.value === to)) return;
    const from = this.colOf(card);
    if (this.controlled(to)) emit(this, 'henoyo:decision-requested', { id, value: to });
    else if (this.controlled(from)) emit(this, 'henoyo:decision-requested', { id, value: null });
    else {
      // Move at once; the host calls track() with the save, and a failure puts the card back.
      this._pending.set(id, to);
      const track = (done: Promise<unknown>): void => {
        done.then(
          () => {
            this.say(
              `Moved ${card.title} to ${this._columns.find((k) => k.value === to)?.label ?? to}.`,
            );
          },
          (error: unknown) => this.rollback(id, to, error),
        );
      };
      emit(this, 'henoyo:card-move', { id, from, to, track });
    }
    this.invalidate();
  }

  /** Shows the fade at the right edge only while more columns lie beyond it. */
  private edge(): void {
    const cols = this.root.querySelector<HTMLElement>('.cols');
    const body = this.root.querySelector<HTMLElement>('.body');
    if (!cols || !body) return;
    body.classList.toggle('more-right', cols.scrollLeft + cols.clientWidth < cols.scrollWidth - 2);
  }

  protected afterRender(): void {
    this.edge();
    const menuItem = this.root.querySelector<HTMLElement>('[role="menuitem"]');
    if (menuItem) menuItem.focus();
    else if (this._refocus !== null) {
      this.root.querySelector<HTMLElement>(`[data-card="${CSS.escape(this._refocus)}"]`)?.focus();
      this._refocus = null;
    }
  }

  protected styles(): string {
    return `
.body { container-type:inline-size; position:relative; min-width:0; }
.body::after { content:""; position:absolute; top:0; right:0; bottom:14px; width:32px; pointer-events:none; opacity:0; transition:opacity .15s; background:linear-gradient(to right, transparent, var(--k-surface, #fff)); }
.body.more-right::after { opacity:1; }
.cols { display:flex; gap:0; align-items:stretch; overflow-x:auto; overscroll-behavior-x:contain; padding-bottom:8px; scroll-snap-type:x proximity; scrollbar-width:thin; scrollbar-color:var(--k-text-3) transparent; }
.cols::-webkit-scrollbar { height:8px; }
.cols::-webkit-scrollbar-thumb { background:var(--k-text-3); border-radius:4px; }
.col { flex:1 0 220px; min-width:220px; padding:0 var(--h-kit-row-px, 14px); border-left:1px solid var(--k-hairline); scroll-snap-align:start; }
.col:first-child { border-left:0; padding-left:0; }
.col:last-child { padding-right:0; }
.ch { display:flex; align-items:baseline; gap:8px; margin:0 0 4px; min-width:0; height:24px; }
.ct { font-family:var(--k-serif); font-size:16px; font-weight:500; margin:0; min-width:0; flex:0 1 auto; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.cn { flex:none; font-size:12px; color:var(--k-text-3); font-variant-numeric:tabular-nums; }
.cw { font-size:11px; line-height:16px; height:16px; color:var(--k-text-3); margin-bottom:8px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.cards { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:var(--h-kit-gap-sm, 8px); }
.bc { position:relative; min-width:0; overflow:hidden; padding:var(--h-kit-row-py, 10px) var(--h-kit-gap, 12px); border:1px solid var(--k-hairline); border-radius:8px; background:var(--k-surface); font-size:13px; }
.bc[draggable="true"] { cursor:grab; }
.bc:focus-visible { outline:2px solid var(--k-brand); outline-offset:2px; }
.bc.held { box-shadow:0 4px 12px rgba(0,0,0,.18); border-color:var(--k-brand); }
.col.drop { background:var(--k-surface-2); outline:2px dashed var(--k-brand); outline-offset:-2px; border-radius:8px; }
.live { position:absolute; width:1px; height:1px; margin:-1px; padding:0; overflow:hidden; clip:rect(0 0 0 0); clip-path:inset(50%); white-space:nowrap; border:0; }
.err { font-size:12.5px; color:var(--k-bad); font-weight:600; margin-bottom:8px; }
.err:empty { display:none; }
.bt { font-weight:600; overflow-wrap:anywhere; }
.bm { display:flex; flex-wrap:wrap; gap:2px 10px; margin-top:4px; font-size:12px; color:var(--k-text-3); min-width:0; }
.bm > * { min-width:0; }
.bm .own { max-width:100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.sev { display:inline-flex; align-items:center; gap:4px; font-weight:600; }
.sev svg { width:12px; height:12px; }
.sev.critical { color:var(--k-bad); } .sev.high { color:var(--k-warn); } .sev.medium { color:var(--k-info); } .sev.low { color:var(--k-text-3); }
.od { color:var(--k-bad); font-weight:600; }
.mv { margin-top:6px; }
.menu { list-style:none; margin:4px 0 0; padding:4px; border:1px solid var(--k-hairline); border-radius:8px; background:var(--k-surface); }
.menu button { all:unset; box-sizing:border-box; display:block; width:100%; padding:6px 8px; border-radius:6px; cursor:pointer; font-size:12.5px; }
.menu button:hover, .menu button:focus-visible { background:var(--k-surface-2); }
.menu button:focus-visible { outline:2px solid var(--k-brand); }
.none { font-size:12.5px; color:var(--k-text-3); padding:8px 0; }
.more { margin-top:8px; }
.switch { display:none; gap:6px; overflow-x:auto; margin-bottom:10px; }
@container (max-width: 640px) { .switch { display:flex; flex-wrap:nowrap; scrollbar-width:none; -webkit-mask-image:linear-gradient(to right,#000 calc(100% - 28px),transparent); mask-image:linear-gradient(to right,#000 calc(100% - 28px),transparent); } .switch::-webkit-scrollbar { display:none; } .switch { padding-right:32px; } .switch .btn { flex:none; white-space:nowrap; } .switch [aria-current] { font-weight:600; border-color:var(--k-brand); } .col { flex:0 0 100%; min-width:100%; scroll-snap-align:start; } .cols { scroll-snap-type:x mandatory; } }
`;
  }

  private severity(raw: string | undefined): string {
    if (raw === undefined || raw === '') return '';
    const key = raw.toLowerCase();
    const known = Object.hasOwn(SEVERITY, key) ? SEVERITY[key] : undefined;
    const { word, icon } = known ?? { word: humanize(raw), icon: 'minus' };
    return `<span class="sev ${known ? key : 'low'}">${glyph(icon, 12)}${esc(word)}</span>`;
  }

  private card(c: HenoyoBoardCard): string {
    const since = ms(c.since);
    const due = ms(c.due);
    const late = due !== null && due < Date.now();
    const meta = [
      this.severity(c.severity),
      c.owner ? `<span class="own" title="${esc(c.owner)}">Owner ${esc(c.owner)}</span>` : '',
      since === null ? '' : `<span>${esc(span((Date.now() - since) / DAY_MS))} here</span>`,
      due === null
        ? ''
        : late
          ? `<span class="od">Overdue since ${esc(fmtDate(due))}</span>`
          : `<span>Due ${esc(fmtDate(due))}</span>`,
    ].join('');
    const col = this.colOf(c);
    const locked = this.controlled(col);
    const open = this._menu === c.id;
    const targets = this._columns.filter((k) => k.value !== col && !this.controlled(k.value));
    let move = '';
    if (this._editable && locked)
      move = `<div class="mv"><button class="linkbtn" type="button" data-act="reopen" data-arg="${esc(c.id)}">Reopen…</button></div>`;
    else if (this._editable && targets.length > 0)
      move = `<div class="mv"><button class="linkbtn" type="button" data-act="menu" data-arg="${esc(c.id)}" aria-haspopup="menu" aria-expanded="${open}">Move to…</button>${
        open
          ? `<ul class="menu" role="menu" aria-label="${esc(`Move ${c.title} to`)}">${targets
              .map(
                (k) =>
                  `<li role="none"><button type="button" role="menuitem" data-act="move" data-arg="${esc(c.id)}" data-to="${esc(k.value)}">${esc(k.label)}</button></li>`,
              )
              .join('')}</ul>`
          : ''
      }</div>`;
    const drag = this._editable && !locked ? ' draggable="true" tabindex="0"' : '';
    return `<li class="bc" data-card="${esc(c.id)}"${drag}><div class="bt">${esc(c.title)}</div><div class="bm">${meta}</div>${move}</li>`;
  }

  private column(k: HenoyoBoardColumn): string {
    const all = this._cards.filter((c) => this.colOf(c) === k.value);
    const open = this._expanded.has(k.value);
    const shown = open ? all : all.slice(0, this._maxPerColumn);
    const hidden = all.length - this._maxPerColumn;
    const note = this.controlled(k.value) ? 'Decision only' : (ROLE_WORD[k.role ?? 'stage'] ?? '');
    const body =
      all.length === 0
        ? '<div class="none">Nothing here</div>'
        : `<ul class="cards">${shown.map((c) => this.card(c)).join('')}</ul>${
            hidden > 0
              ? `<div class="more"><button class="linkbtn" type="button" data-act="more" data-arg="${esc(k.value)}" aria-expanded="${open}">${open ? 'Show fewer' : `${hidden} more`}</button></div>`
              : ''
          }`;
    return `<section class="col" data-col="${esc(k.value)}" aria-label="${esc(`${k.label}, ${all.length} ${all.length === 1 ? 'card' : 'cards'}`)}">
      <div class="ch"><h4 class="ct" title="${esc(k.label)}">${esc(k.label)}</h4><span class="cn">${all.length}</span></div>
      <div class="cw">${esc(note)}</div>${body}</section>`;
  }

  protected view(): string {
    const title = this._heading ?? 'Board';
    if (this._columns.length === 0)
      return this.emptyCard(title, 'No columns', 'No status values to show.');
    const jump = this._columns
      .map(
        (k) =>
          `<button class="btn" type="button" data-act="jump" data-arg="${esc(k.value)}"${k === this._columns[0] ? ' aria-current="true"' : ''}>${esc(k.label)}</button>`,
      )
      .join('');
    const n = this._cards.length;
    return `<div class="card">${this.head(title, `${n} ${n === 1 ? 'card' : 'cards'} across ${this._columns.length} columns`)}<div class="body">
      <div class="live" role="status" aria-live="polite">${esc(this._notice)}</div>
      <div class="err" aria-hidden="true">${this._noticeBad ? esc(this._notice) : ''}</div>
      <nav class="switch" aria-label="Jump to column">${jump}</nav>
      <div class="cols">${this._columns.map((k) => this.column(k)).join('')}</div></div>${this.foot()}</div>`;
  }
}

defineElement('henoyo-board', HenoyoBoard);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-board': HenoyoBoard;
  }
}
