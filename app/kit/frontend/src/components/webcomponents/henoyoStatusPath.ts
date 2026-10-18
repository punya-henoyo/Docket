// <henoyo-status-path>: where one record sits in its lifecycle, from a picklist's own order.

import {
  DAY_MS,
  HenoyoElement,
  defineElement,
  emit,
  esc,
  fmtDate,
  glyph,
  helpMarkup,
  ms,
  span,
} from './henoyoKit';

export type StatusRole =
  | 'stage'
  | 'outcome_positive'
  | 'outcome_negative'
  | 'outcome_neutral'
  | 'hold';

export interface HenoyoStatusValue {
  value: string;
  label: string;
  /** Absent reads as a stage. */
  role?: StatusRole;
  /** What the value means; shown as the tooltip of its stage. */
  description?: string;
}

export type SegmentState = 'done' | 'current' | 'hold' | 'upcoming';

export interface StatusSegment {
  value: string;
  label: string;
  state: SegmentState;
}

export type OutcomeState = 'pending' | 'positive' | 'negative' | 'neutral';

export interface StatusLayout {
  segments: StatusSegment[];
  /** Null when no picklist value is an outcome: the last stage is then the end. */
  outcome: { state: OutcomeState; label: string; value?: string } | null;
  /** Position of the current segment among the segments, or -1 when the record has no known value. */
  currentIndex: number;
}

const OUTCOME_STATE: Partial<Record<StatusRole, Exclude<OutcomeState, 'pending'>>> = {
  outcome_positive: 'positive',
  outcome_negative: 'negative',
  outcome_neutral: 'neutral',
};

const roleOf = (v: HenoyoStatusValue): StatusRole => v.role ?? 'stage';

/**
 * Stages in picklist order. A hold value only appears while it is current, in its own place,
 * and takes the place of that stage's "current" fill.
 */
export function statusLayout(
  values: readonly HenoyoStatusValue[],
  current: string | undefined,
): StatusLayout {
  const now = values.find((v) => v.value === current);
  const resolved = now !== undefined && roleOf(now) in OUTCOME_STATE;
  const shown = values.filter(
    (v) => roleOf(v) === 'stage' || (roleOf(v) === 'hold' && v.value === current),
  );
  const at = shown.findIndex((v) => v.value === current);
  const segments = shown.map<StatusSegment>((v, i) => ({
    value: v.value,
    label: v.label,
    state: resolved
      ? 'done'
      : at < 0
        ? 'upcoming'
        : i < at
          ? 'done'
          : i > at
            ? 'upcoming'
            : roleOf(v) === 'hold'
              ? 'hold'
              : 'current',
  }));
  const hasOutcome = values.some((v) => roleOf(v) in OUTCOME_STATE);
  // "Decision" only when a value records a decision; a neutral-only set is just an "Outcome".
  const decides = values.some((v) => ['outcome_positive', 'outcome_negative'].includes(roleOf(v)));
  const state = now === undefined ? undefined : OUTCOME_STATE[roleOf(now)];
  const outcome = !hasOutcome
    ? null
    : state === undefined || now === undefined
      ? { state: 'pending' as const, label: decides ? 'Decision' : 'Outcome' }
      : { state, label: now.label, value: now.value };
  return { segments, outcome, currentIndex: resolved ? segments.length : at };
}

export class HenoyoStatusPath extends HenoyoElement {
  private _heading: string | undefined;
  private _values: HenoyoStatusValue[] = [];
  private _current: string | undefined;
  private _editable = false;
  private _decisionControlled: string[] = [];
  private _since: string | undefined;
  private _owner: string | undefined;
  private _ownerLabel = 'Owner';
  private _variant: 'card' | 'bar' = 'card';
  /** A forward jump waiting on its one-line confirmation. */
  private _confirm: string | null = null;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-act]');
      if (!target) return;
      const arg = target.dataset.arg;
      switch (target.dataset.act) {
        case 'go':
          if (arg !== undefined) this.request(arg);
          break;
        case 'confirm':
          if (this._confirm !== null) this.move(this._confirm);
          break;
        case 'cancel':
          this._confirm = null;
          this.invalidate();
          break;
        case 'decide':
          emit(this, 'henoyo:decision-requested', { value: arg ?? null });
          break;
        case 'reopen':
          this.reopen();
          break;
      }
    });
  }

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v;
    this.invalidate();
  }
  get values(): HenoyoStatusValue[] {
    return this._values;
  }
  set values(v: HenoyoStatusValue[]) {
    this._values = Array.isArray(v) ? v.filter((x) => x && typeof x.value === 'string') : [];
    this.invalidate();
  }
  get current(): string | undefined {
    return this._current;
  }
  set current(v: string | undefined) {
    this._current = v;
    this._confirm = null;
    this.invalidate();
  }
  get editable(): boolean {
    return this._editable;
  }
  set editable(v: boolean | undefined) {
    this._editable = v === true;
    this.invalidate();
  }
  /** Values that only a decision can set; the path never moves a record to one. */
  get decisionControlled(): string[] {
    return this._decisionControlled;
  }
  set decisionControlled(v: string[] | undefined) {
    this._decisionControlled = Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    this.invalidate();
  }
  get since(): string | undefined {
    return this._since;
  }
  set since(v: string | undefined) {
    this._since = v;
    this.invalidate();
  }
  get owner(): string | undefined {
    return this._owner;
  }
  set owner(v: string | undefined) {
    this._owner = v;
    this.invalidate();
  }

  get ownerLabel(): string {
    return this._ownerLabel;
  }
  set ownerLabel(v: string | undefined) {
    this._ownerLabel = typeof v === 'string' && v.trim() !== '' ? v : 'Owner';
    this.invalidate();
  }
  /** 'card' is the framed widget; 'bar' is the headerless strip for a record page. */
  get variant(): 'card' | 'bar' {
    return this._variant;
  }
  set variant(v: 'card' | 'bar' | undefined) {
    this._variant = v === 'bar' ? 'bar' : 'card';
    this.invalidate();
  }

  private controlled(value: string): boolean {
    return this._decisionControlled.includes(value);
  }

  /** The current value is itself a decision's result, so only the decision dialog can leave it. */
  private locked(): boolean {
    return this._current !== undefined && this.controlled(this._current);
  }

  private move(to: string): void {
    this._confirm = null;
    emit(this, 'henoyo:status-move', { from: this._current ?? null, to });
    this.invalidate();
  }

  private request(to: string): void {
    if (!this._editable || to === this._current) return;
    if (this.controlled(to)) {
      emit(this, 'henoyo:decision-requested', { value: to });
      return;
    }
    if (this.locked()) return;
    const { segments, currentIndex } = statusLayout(this._values, this._current);
    const target = segments.findIndex((s) => s.value === to);
    if (target > currentIndex + 1 && currentIndex >= 0) {
      this._confirm = to;
      this.invalidate();
      return;
    }
    this.move(to);
  }

  private reopen(): void {
    if (!this._editable) return;
    if (this.locked()) {
      emit(this, 'henoyo:decision-requested', { value: null });
      return;
    }
    const last = [...this._values].reverse().find((v) => roleOf(v) === 'stage');
    if (last !== undefined) this.move(last.value);
  }

  protected afterRender(): void {
    this.root.querySelector<HTMLElement>('[data-act="confirm"]')?.focus();
  }

  protected styles(): string {
    return `
:host { --k-on-solid:rgb(var(--h-brand-fg, 255 254 251)); }
.path { --notch:8px; list-style:none; margin:4px 0 0; padding:0; display:flex; align-items:stretch; gap:2px; }
.path li { flex:1 1 0; min-width:0; }
.seg { all:unset; box-sizing:border-box; width:100%; height:calc(var(--h-kit-row, 36px) + 4px); display:flex; align-items:center; justify-content:center; gap:6px;
  padding:0 calc(var(--notch) + 6px) 0 calc(var(--notch) + 4px); font-size:13px; font-weight:500; white-space:nowrap;
  background:var(--k-surface-2); color:var(--k-text-3); transition:background 150ms;
  clip-path:polygon(0 0, calc(100% - var(--notch)) 0, 100% 50%, calc(100% - var(--notch)) 100%, 0 100%, var(--notch) 50%); }
.path li:first-child .seg { clip-path:polygon(0 0, calc(100% - var(--notch)) 0, 100% 50%, calc(100% - var(--notch)) 100%, 0 100%); border-radius:8px 0 0 8px; }
.path li:last-child .seg { clip-path:polygon(0 0, 100% 0, 100% 100%, 0 100%, var(--notch) 50%); border-radius:0 8px 8px 0; }
.path li:only-child .seg { clip-path:none; border-radius:8px; }
.seg > span:not(.sr) { min-width:0; overflow:hidden; display:-webkit-box; -webkit-box-orient:vertical; -webkit-line-clamp:2; line-clamp:2; line-height:1.15; text-align:center; white-space:normal; overflow-wrap:anywhere; }
.seg { white-space:normal; font-size:12.5px; }
.bar .path { --notch:6px; margin-top:0; }
.bar .seg { height:calc(var(--h-kit-row, 36px) + 4px); gap:4px; padding:0 calc(var(--notch) + 4px) 0 calc(var(--notch) + 2px); }
.bar { background:transparent; }
.bar .line { margin-top:var(--h-kit-gap-sm, 6px); font-size:12.5px; }
.bar .compact { margin-top:0; }
.bar .helpwrap { margin-left:0; }
.bar .tip { left:auto; right:-8px; }
.seg svg { width:14px; height:14px; flex:none; }
button.seg { cursor:pointer; }
button.seg:hover { filter:brightness(.96); }
button.seg:focus-visible { outline:2px solid var(--k-brand); outline-offset:-3px; border-radius:0; }
[data-s="done"] .seg { background:var(--k-ok-soft); color:var(--k-ok); }
[data-s="current"] .seg { background:var(--k-brand); color:var(--k-on-solid); font-weight:600; }
[data-s="hold"] .seg { background:var(--k-warn-soft); color:var(--k-warn); font-weight:600; }
[data-s="pending"] .seg { background:repeating-linear-gradient(135deg, var(--k-surface-2) 0 6px, var(--k-surface) 6px 12px); font-style:italic; }
[data-s="positive"] .seg { background:var(--k-ok); color:var(--k-on-solid); font-weight:600; }
[data-s="negative"] .seg { background:var(--k-bad); color:var(--k-on-solid); font-weight:600; }
[data-s="neutral"] .seg { background:var(--k-neutral); color:var(--k-on-solid); font-weight:600; }
.compact { display:none; align-items:center; gap:10px; margin-top:4px; padding:var(--h-kit-row-py, 10px) var(--h-kit-gap, 12px); border-radius:8px; background:var(--k-surface-2); font-size:14px; }
.dots { display:flex; gap:3px; }
.dots i { width:14px; height:4px; border-radius:2px; background:var(--k-hairline-2); }
.dots i.on { background:var(--k-brand); }
.line { display:flex; flex-wrap:wrap; align-items:center; gap:8px 16px; margin-top:var(--h-kit-gap, 12px); font-size:13px; color:var(--k-text-3); }
.line b { color:var(--k-text); font-weight:600; }
.line .sp { flex:1; }
.confirm { margin-top:var(--h-kit-row-py, 10px); display:flex; flex-wrap:wrap; align-items:center; gap:8px 12px; font-size:13px; padding:8px 12px; border-radius:8px; background:var(--k-surface-2); }
/* The element's own width decides, so a narrow column gets the compact view too. */
.body { container-type:inline-size; }
@container (max-width: 640px) { .path { display:none; } .compact { display:flex; } }
`;
  }

  private stateWord(state: SegmentState): string {
    return state === 'done' ? ' (completed)' : state === 'current' ? ' (current)' : '';
  }

  private segment(s: StatusSegment, clickable: boolean): string {
    const hold = s.state === 'hold';
    const text = hold ? 'On hold' : s.label;
    const icon = s.state === 'done' ? glyph('check', 14) : hold ? glyph('pause', 14) : '';
    const word = hold ? ' (on hold)' : this.stateWord(s.state);
    const inner = `${icon}<span>${esc(text)}</span><span class="sr">${esc(word)}</span>`;
    const aria = s.state === 'current' || hold ? ' aria-current="step"' : '';
    const full = esc(`${s.label}${word}`);
    const note = this._values.find((v) => v.value === s.value)?.description;
    const tip = esc(note === undefined ? s.label : `${s.label}: ${note}`);
    const body = clickable
      ? `<button class="seg" type="button" title="${tip}" aria-label="${full}" data-act="go" data-arg="${esc(s.value)}">${inner}</button>`
      : `<span class="seg" title="${tip}">${inner}</span>`;
    return `<li data-s="${s.state}"${aria}>${body}</li>`;
  }

  private outcomeSegment(outcome: NonNullable<StatusLayout['outcome']>): string {
    const icon =
      outcome.state === 'positive'
        ? glyph('check', 14)
        : outcome.state === 'negative'
          ? glyph('x', 14)
          : outcome.state === 'neutral'
            ? glyph('minus', 14)
            : '';
    const inner = `${icon}<span>${esc(outcome.label)}</span>`;
    const body =
      outcome.state === 'pending' && this._editable
        ? `<button class="seg" type="button" title="${esc(outcome.label)}" aria-label="${esc(outcome.label)}" data-act="decide">${inner}</button>`
        : `<span class="seg" title="${esc(outcome.label)}">${inner}</span>`;
    return `<li data-s="${outcome.state}">${body}</li>`;
  }

  private statusLine(layout: StatusLayout, shownLabel: string): string {
    const at = ms(this._since);
    const bar = this._variant === 'bar';
    const when =
      at === null
        ? ''
        : ` ${layout.outcome !== null && layout.outcome.state !== 'pending' ? 'on' : 'since'} ${esc(fmtDate(at))}${
            bar || (layout.outcome !== null && layout.outcome.state !== 'pending')
              ? ''
              : ` (${esc(span((Date.now() - at) / DAY_MS))})`
          }`;
    const resolved = layout.outcome !== null && layout.outcome.state !== 'pending';
    const lead = resolved
      ? `<b>${esc(shownLabel)}</b>${when}`
      : `In <b>${esc(shownLabel)}</b>${when}`;
    const owner =
      this._owner === undefined
        ? ''
        : `<span>${esc(this._ownerLabel)} <b>${esc(this._owner)}</b></span>`;
    const help = bar ? helpMarkup(this.frameId, this.helpText) : '';
    return `<div class="line"><span>${lead}</span>${owner}<span class="sp"></span>${this.action(layout)}${help}</div>`;
  }

  private action(layout: StatusLayout): string {
    if (!this._editable) return '';
    if (layout.outcome !== null && layout.outcome.state !== 'pending')
      return '<button class="btn" type="button" data-act="reopen">Reopen</button>';
    const next = layout.segments[layout.currentIndex + 1];
    if (next !== undefined)
      return `<button class="btn primary" type="button" data-act="go" data-arg="${esc(next.value)}">Move to ${esc(next.label)}</button>`;
    return layout.outcome !== null
      ? '<button class="btn primary" type="button" data-act="decide">Record decision…</button>'
      : '';
  }

  protected view(): string {
    const title = this._heading ?? 'Status';
    const bar = this._variant === 'bar';
    if (this._values.length === 0)
      return bar
        ? '<div class="bar"><div class="line">No status values to show.</div></div>'
        : this.emptyCard(title, 'No status', 'No status values to show.');
    const layout = statusLayout(this._values, this._current);
    const cur = layout.segments[layout.currentIndex];
    const known = this._values.find((v) => v.value === this._current);
    const shownLabel =
      layout.outcome?.value !== undefined ? layout.outcome.label : (cur?.label ?? '');
    const finding = known?.label ?? 'No status yet';
    const canMove = this._editable && !this.locked();
    const items = layout.segments
      .map((s) => this.segment(s, canMove && s.state !== 'current' && s.state !== 'hold'))
      .join('');
    const total = layout.segments.length + (layout.outcome === null ? 0 : 1);
    const step = layout.currentIndex < 0 ? 0 : Math.min(layout.currentIndex + 1, total);
    const dots = Array.from(
      { length: total },
      (_, i) => `<i${i < step ? ' class="on"' : ''}></i>`,
    ).join('');
    const line = known === undefined ? '' : this.statusLine(layout, shownLabel);
    const confirm =
      this._confirm === null
        ? ''
        : `<div class="confirm" role="alert"><span>Skip ahead to <b>${esc(this._values.find((v) => v.value === this._confirm)?.label ?? this._confirm)}</b>?</span><button class="btn primary" type="button" data-act="confirm">Move</button><button class="btn" type="button" data-act="cancel">Cancel</button></div>`;
    const frame = bar
      ? (inner: string): string => `<div class="bar"><div class="body">${inner}</div></div>`
      : (inner: string): string =>
          `<div class="card">${this.head(title, finding)}<div class="body">${inner}</div>${this.foot()}</div>`;
    return frame(`
      <ol class="path" aria-label="${esc(`Status: ${finding}`)}">${items}${layout.outcome === null ? '' : this.outcomeSegment(layout.outcome)}</ol>
      <div class="compact"><span class="dots" aria-hidden="true">${dots}</span><span>Step ${step} of ${total} · <b>${esc(finding)}</b></span></div>
      ${confirm}${line}`);
  }
}

defineElement('henoyo-status-path', HenoyoStatusPath);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-status-path': HenoyoStatusPath;
  }
}
