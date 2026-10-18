// <henoyo-visual-picker>: one choice among a few options that each need an explanation.

import { HenoyoElement, defineElement, emit, esc, glyph } from './henoyoKit';

export interface HenoyoPickerOption {
  value: string;
  label: string;
  description?: string;
  glyph?: string;
  disabled?: boolean;
}

const isOption = (v: unknown): v is HenoyoPickerOption =>
  !!v &&
  typeof v === 'object' &&
  typeof (v as HenoyoPickerOption).value === 'string' &&
  (v as HenoyoPickerOption).value !== '' &&
  typeof (v as HenoyoPickerOption).label === 'string' &&
  (v as HenoyoPickerOption).label !== '';

function normalize(raw: HenoyoPickerOption): HenoyoPickerOption {
  const option: HenoyoPickerOption = { value: raw.value, label: raw.label };
  if (typeof raw.description === 'string' && raw.description !== '')
    option.description = raw.description;
  if (typeof raw.glyph === 'string' && raw.glyph !== '') option.glyph = raw.glyph;
  if (raw.disabled === true) option.disabled = true;
  return option;
}

const MOVE_KEYS = ['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End'];

export class HenoyoVisualPicker extends HenoyoElement {
  private _heading: string | undefined;
  private _options: HenoyoPickerOption[] = [];
  private _selected: string | undefined;
  private _editable = false;
  private _confirm = false;
  private _decisionControlled: string[] = [];
  /** A choice waiting on the Choose button. */
  private _pending: string | undefined;
  /** Restored after a render so a key press does not drop focus. */
  private _focusValue: string | undefined;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => this.onClick(e));
    this.root.addEventListener('keydown', (e) => this.onKey(e as KeyboardEvent));
  }

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = typeof v === 'string' && v !== '' ? v : undefined;
    this.invalidate();
  }
  get options(): HenoyoPickerOption[] {
    return this._options;
  }
  set options(v: HenoyoPickerOption[]) {
    const seen = new Set<string>();
    this._options = Array.isArray(v)
      ? v.filter(isOption).flatMap((raw) => {
          if (seen.has(raw.value)) return [];
          seen.add(raw.value);
          return [normalize(raw)];
        })
      : [];
    if (this._pending !== undefined && !seen.has(this._pending)) this._pending = undefined;
    this.invalidate();
  }
  get selected(): string | undefined {
    return this._selected;
  }
  set selected(v: string | undefined) {
    this._selected = typeof v === 'string' && v !== '' ? v : undefined;
    this._pending = undefined;
    this.invalidate();
  }
  get editable(): boolean {
    return this._editable;
  }
  set editable(v: boolean | undefined) {
    this._editable = v === true;
    this.invalidate();
  }
  /** When true, a choice is kept until the Choose button. */
  get confirm(): boolean {
    return this._confirm;
  }
  set confirm(v: boolean | undefined) {
    this._confirm = v === true;
    if (!this._confirm) this._pending = undefined;
    this.invalidate();
  }
  /** Values that only a decision can set; the picker never writes one. */
  get decisionControlled(): string[] {
    return this._decisionControlled;
  }
  set decisionControlled(v: string[] | undefined) {
    this._decisionControlled = Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    this.invalidate();
  }

  private controlled(value: string): boolean {
    return this._decisionControlled.includes(value);
  }

  /** The current value is a decision's result, so only the decision dialog can leave it. */
  private locked(): boolean {
    return this._selected !== undefined && this.controlled(this._selected);
  }

  private shown(): string | undefined {
    return this._pending ?? this._selected;
  }

  private tabValue(): string | undefined {
    const shown = this.shown();
    if (shown !== undefined && this._options.some((o) => o.value === shown)) return shown;
    return this._options.find((o) => o.disabled !== true)?.value ?? this._options[0]?.value;
  }

  private onClick(event: Event): void {
    const node = event.target;
    if (!(node instanceof Element)) return;
    const target = node.closest<HTMLElement>('[data-act]');
    if (target === null || (target as HTMLButtonElement).disabled) return;
    const value = target.dataset.value;
    if (target.dataset.act === 'pick' && value !== undefined) this.choose(value);
    else if (target.dataset.act === 'choose') this.commit();
  }

  private onKey(event: KeyboardEvent): void {
    const node = event.target;
    if (!(node instanceof Element)) return;
    const target = node.closest<HTMLElement>('[role="radio"]');
    if (target === null) return;
    const key = event.key;
    if (key === ' ' || key === 'Enter') {
      event.preventDefault();
      const value = target.dataset.value;
      if (value !== undefined) this.choose(value);
      return;
    }
    if (!MOVE_KEYS.includes(key)) return;
    const radios = [...this.root.querySelectorAll<HTMLElement>('[role="radio"]')];
    const pool = radios.filter(
      (r) => r.dataset.disabled !== 'true' || r.getAttribute('aria-checked') === 'true',
    );
    if (pool.length === 0) return;
    event.preventDefault();
    const at = pool.indexOf(target);
    const back = key === 'ArrowLeft' || key === 'ArrowUp';
    let next = 0;
    if (key === 'End' || (at < 0 && back)) next = pool.length - 1;
    else if (key === 'Home' || at < 0) next = 0;
    else if (key === 'ArrowRight' || key === 'ArrowDown') next = (at + 1) % pool.length;
    else next = (at - 1 + pool.length) % pool.length;
    const el = pool[next];
    if (el === undefined) return;
    for (const radio of radios) radio.tabIndex = radio === el ? 0 : -1;
    el.focus();
  }

  private choose(to: string): void {
    const option = this._options.find((o) => o.value === to);
    if (option === undefined || option.disabled === true || !this._editable) return;
    this._focusValue = to;
    if (to === this.shown()) return;
    if (this.controlled(to)) {
      emit(this, 'henoyo:decision-requested', { value: to });
      return;
    }
    if (this.locked()) return;
    if (this._confirm) {
      this._pending = to === this._selected ? undefined : to;
      this.invalidate();
      return;
    }
    this.emitPick(to);
  }

  private commit(): void {
    const to = this._pending;
    if (!this._editable || !this._confirm || to === undefined || to === this._selected) return;
    if (this.controlled(to) || this.locked()) return;
    this._focusValue = to;
    this.emitPick(to);
  }

  private emitPick(to: string): void {
    const from = this._selected ?? null;
    this._pending = undefined;
    emit(this, 'henoyo:pick', { from, to });
    this.invalidate();
  }

  protected afterRender(): void {
    const want = this._focusValue;
    if (want === undefined) return;
    const el = [...this.root.querySelectorAll<HTMLElement>('[role="radio"]')].find(
      (r) => r.dataset.value === want,
    );
    el?.focus();
  }

  protected styles(): string {
    return `
.opts { display:grid; grid-template-columns:repeat(auto-fit, minmax(min(100%, 16rem), 1fr)); gap:var(--h-kit-gap, 12px); }
.opt { all:unset; box-sizing:border-box; display:flex; flex-direction:column; gap:var(--h-space-1, 4px); min-width:0;
  padding:calc(var(--h-kit-row-py, 10px) + 2px); border:1px solid var(--k-hairline-2); border-radius:12px; background:var(--k-surface);
  color:var(--k-text); cursor:pointer; text-align:left; }
.opt[aria-disabled="true"] { cursor:not-allowed; color:var(--k-text-3); }
.opts[aria-readonly="true"] .opt { cursor:default; }
.opt[aria-checked="true"] { background:var(--k-brand); color:rgb(var(--h-brand-fg, 255 254 251)); border-color:transparent; }
.top { display:flex; align-items:center; gap:var(--h-space-2, 8px); min-width:0; }
.top svg { flex:none; }
.lab { font-family:var(--k-serif); font-size:calc(var(--h-kit-title-size, 20px) - 4px); font-weight:500; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.mark { display:inline-flex; flex:none; }
.desc { font-size:13px; line-height:1.4; color:var(--k-text-2); display:-webkit-box; -webkit-line-clamp:3; -webkit-box-orient:vertical; overflow:hidden; }
.opt[aria-checked="true"] .desc { color:inherit; }
.flag { display:inline-flex; align-items:center; gap:4px; font-size:12px; font-weight:700; }
.choose { margin-top:var(--h-space-3, 12px); display:flex; justify-content:flex-end; }
`;
  }

  private option(o: HenoyoPickerOption, tab: string | undefined): string {
    const on = o.value === this.shown();
    const controlled = this.controlled(o.value);
    const bits = [o.label];
    if (o.description !== undefined) bits.push(o.description);
    if (o.disabled === true) bits.push('Unavailable');
    if (controlled) bits.push('Decision');
    if (on) bits.push('Selected');
    const full = o.description === undefined ? o.label : `${o.label}. ${o.description}`;
    const icon = o.glyph === undefined ? '' : glyph(o.glyph, 18);
    const mark = on
      ? `<span class="mark">${glyph('check', 16)}<span class="sr">Selected</span></span>`
      : '';
    const flags = [
      o.disabled === true ? `<span class="flag">${glyph('lock', 14)}Unavailable</span>` : '',
      controlled ? `<span class="flag">${glyph('gavel', 14)}Decision</span>` : '',
    ].join('');
    return `<button type="button" class="opt" role="radio" data-act="pick" data-value="${esc(o.value)}"${
      o.disabled === true ? ' data-disabled="true"' : ''
    } aria-checked="${on ? 'true' : 'false'}" aria-disabled="${o.disabled === true ? 'true' : 'false'}" aria-label="${esc(bits.join('. '))}" title="${esc(full)}" tabindex="${
      o.value === tab ? '0' : '-1'
    }"><span class="top">${icon}<span class="lab">${esc(o.label)}</span>${mark}</span>${
      o.description === undefined ? '' : `<span class="desc">${esc(o.description)}</span>`
    }${flags}</button>`;
  }

  protected view(): string {
    const title = this._heading ?? 'Choice';
    if (this._options.length === 0)
      return this.emptyCard(title, 'No options', 'Nothing to show yet.');
    const known = this._options.find((o) => o.value === this._selected);
    const finding = known === undefined ? 'Nothing chosen yet' : known.label;
    const tab = this.tabValue();
    const items = this._options.map((o) => this.option(o, tab)).join('');
    const canChoose = this._editable && this._confirm && !this.locked();
    const pending = this._pending !== undefined && this._pending !== this._selected;
    const pendingLabel = this._options.find((o) => o.value === this._pending)?.label;
    const chooseLabel =
      pendingLabel === undefined ? '' : ` aria-label="${esc('Choose ' + pendingLabel)}"`;
    const choose = canChoose
      ? `<div class="choose"><button class="btn primary" type="button" data-act="choose"${
          pending ? '' : ' disabled'
        }${chooseLabel}>Choose</button></div>`
      : '';
    const readonly = this._editable ? '' : ' aria-readonly="true"';
    return `<div class="card">${this.head(title, finding)}<div class="body"><div class="opts" role="radiogroup" aria-label="${esc(title)}"${readonly}>${items}</div>${choose}</div>${this.foot()}</div>`;
  }
}

defineElement('henoyo-visual-picker', HenoyoVisualPicker);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-visual-picker': HenoyoVisualPicker;
  }
}
