// <henoyo-stepper>: a guided multi-step flow. Where am I, what is left, can I go back.
// The host puts the open step's content in the `step` slot; the last step is the review.

import { HenoyoElement, defineElement, emit, esc, fmtDate, glyph, ms } from './henoyoKit';

export interface HenoyoStep {
  id: string;
  label: string;
  complete?: boolean;
  /** Set to flag the step "Needs attention". */
  error?: boolean;
  /** The step's answers, listed with an Edit link on the review step. */
  summary?: string;
  /** What the step is for; shown under the step list while the step is open. */
  description?: string;
}

const isStep = (v: unknown): v is HenoyoStep =>
  !!v &&
  typeof v === 'object' &&
  typeof (v as HenoyoStep).id === 'string' &&
  !!(v as HenoyoStep).label;

export class HenoyoStepper extends HenoyoElement {
  private _steps: HenoyoStep[] = [];
  private _current: string | undefined;
  private _draftSavedAt: string | undefined;
  /** Where the user has navigated to; the `current` prop sets it. */
  private _at: string | undefined;
  /** Bound to a record picklist and the user may edit it: moving to a step moves the record. */
  private _editable = false;
  private _decisionControlled: string[] = [];

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-act]');
      if (!target || (target as HTMLButtonElement).disabled) return;
      const act = target.dataset.act;
      if (act === 'goto' && target.dataset.arg !== undefined) return this.goId(target.dataset.arg);
      const i = this.index();
      if (act === 'back') this.go(i - 1);
      else if (act === 'next') this.go(i + 1);
      else if (act === 'edit' && target.dataset.arg !== undefined) this.goId(target.dataset.arg);
      else if (act === 'submit') emit(this, 'henoyo:step-submit', {});
    });
    this.root.addEventListener('change', (e) => {
      const t = e.target as HTMLSelectElement;
      if (t.dataset?.act === 'menu') this.goId(t.value);
    });
  }

  get steps(): HenoyoStep[] {
    return this._steps;
  }
  set steps(v: HenoyoStep[]) {
    this._steps = Array.isArray(v) ? v.filter(isStep) : [];
    this.invalidate();
  }
  get current(): string | undefined {
    return this._current;
  }
  set current(v: string | undefined) {
    this._current = typeof v === 'string' && v !== '' ? v : undefined;
    this._at = this._current;
    this.invalidate();
  }
  get editable(): boolean {
    return this._editable;
  }
  set editable(v: boolean | undefined) {
    this._editable = v === true;
    this.invalidate();
  }
  /** Values that only a decision can set; the stepper asks for the decision instead of moving. */
  get decisionControlled(): string[] {
    return this._decisionControlled;
  }
  set decisionControlled(v: string[] | undefined) {
    this._decisionControlled = Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    this.invalidate();
  }
  get draftSavedAt(): string | undefined {
    return this._draftSavedAt;
  }
  set draftSavedAt(v: string | undefined) {
    this._draftSavedAt = typeof v === 'string' && v !== '' ? v : undefined;
    this.invalidate();
  }

  /** The open step: the one navigated to, else the first incomplete (a resumed draft), else the first. */
  private index(): number {
    const steps = this._steps;
    const named = steps.findIndex((s) => s.id === this._at);
    if (named >= 0) return named;
    const open = steps.findIndex((s) => !s.complete);
    return open >= 0 ? open : 0;
  }

  private go(to: number): void {
    const steps = this._steps;
    if (to < 0 || to >= steps.length) return;
    this.goId(steps[to]!.id);
  }

  private goId(id: string): void {
    const from = this._steps[this.index()];
    const to = this._steps.find((s) => s.id === id);
    if (!from || !to || from.id === to.id) return;
    if (this._editable && this._decisionControlled.includes(to.id)) {
      emit(this, 'henoyo:decision-requested', { value: to.id });
      return;
    }
    this._at = to.id;
    emit(this, 'henoyo:step-change', { from: from.id, to: to.id });
    if (this._editable) emit(this, 'henoyo:step-move', { from: from.id, to: to.id });
    this.invalidate();
  }

  protected styles(): string {
    return `
:host { display:block; }
.card { background:var(--k-surface); border:1px solid var(--k-hairline-2); border-radius:12px; padding:calc(var(--h-kit-pad-y, 18px) - 2px) var(--h-kit-pad-y, 18px); color:var(--k-text); }
.top { display:flex; flex-wrap:wrap; align-items:baseline; justify-content:space-between; gap:6px 16px; }
.count { font-size:13px; font-weight:700; }
.saved { font-size:12px; color:var(--k-text-3); }
.steps { list-style:none; margin:var(--h-kit-gap, 12px) 0 0; padding:0; display:flex; flex-wrap:wrap; gap:6px 18px; }
.step { display:inline-flex; align-items:center; gap:6px; font-size:13px; color:var(--k-text-3); padding:2px 0; border-bottom:2px solid transparent; }
.step button { all:unset; display:inline-flex; align-items:center; gap:6px; cursor:pointer; }
.step button:focus-visible { outline:2px solid var(--k-text); outline-offset:2px; }
.desc { margin:var(--h-kit-gap-sm, 8px) 0 0; font-size:13px; color:var(--k-text-2, var(--k-text-3)); }
.step.on { color:var(--k-text); font-weight:700; border-bottom-color:var(--k-text); }
.step .n { font-variant-numeric:tabular-nums; }
.step .flag { font-size:12px; font-weight:700; color:var(--k-bad); display:inline-flex; align-items:center; gap:4px; }
.step .done { color:var(--k-ok); display:inline-flex; }
.compact { display:none; margin-top:12px; }
.compact select { font:inherit; font-size:13px; padding:6px 8px; border:1px solid var(--k-hairline-2); border-radius:8px; background:var(--k-surface); color:var(--k-text); max-width:100%; }
.body { margin-top:calc(var(--h-kit-gap, 12px) + 4px); padding-top:calc(var(--h-kit-gap, 12px) + 4px); border-top:1px solid var(--k-hairline-2); }
.review { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:10px; }
.review li { display:flex; flex-wrap:wrap; align-items:baseline; gap:4px 12px; }
.review .lab { font-weight:700; font-size:13px; flex:0 0 140px; }
.review .ans { flex:1 1 200px; min-width:0; overflow-wrap:anywhere; font-size:14px; }
.review .none { color:var(--k-text-3); }
.nav { display:flex; justify-content:space-between; gap:var(--h-kit-gap-sm, 8px); margin-top:calc(var(--h-kit-gap, 12px) + 4px); }
.btn[disabled] { opacity:.5; cursor:not-allowed; }
.note { margin-top:8px; font-size:12px; color:var(--k-bad); }
@media (max-width:640px) {
  .steps { display:none; }
  .compact { display:block; }
}
`;
  }

  protected view(): string {
    const steps = this._steps;
    if (steps.length === 0) return '';
    const i = this.index();
    const last = i === steps.length - 1;
    const saved = ms(this._draftSavedAt);
    const items = steps
      .map((s, k) => {
        const mark = s.error
          ? `<span class="flag">${glyph('circle-alert', 14)}Needs attention</span>`
          : s.complete
            ? `<span class="done">${glyph('check', 14)}<span class="sr">Complete</span></span>`
            : '';
        const inner = `<span class="n">${k + 1}</span> ${esc(s.label)} ${mark}`;
        const tip = s.description ? ` title="${esc(s.description)}"` : '';
        const body = this._editable
          ? `<button type="button" data-act="goto" data-arg="${esc(s.id)}"${tip}>${inner}</button>`
          : inner;
        return `<li class="step${k === i ? ' on' : ''}"${k === i ? ' aria-current="step"' : ''}${this._editable ? '' : tip}>${body}</li>`;
      })
      .join('');
    const options = steps
      .map((s, k) => {
        const tag = s.error ? ' (Needs attention)' : s.complete ? ' (Complete)' : '';
        return `<option value="${esc(s.id)}"${k === i ? ' selected' : ''}>${k + 1} ${esc(s.label)}${tag}</option>`;
      })
      .join('');
    const review = steps
      .slice(0, -1)
      .map(
        (s) =>
          `<li><span class="lab">${esc(s.label)}</span><span class="ans${s.summary ? '' : ' none'}">${esc(s.summary || 'No answers yet')}</span><button class="linkbtn" type="button" data-act="edit" data-arg="${esc(s.id)}" aria-label="Edit ${esc(s.label)}">Edit</button></li>`,
      )
      .join('');
    const blocked = steps.some((s) => s.error);
    const body = last
      ? `<ul class="review">${review}</ul><slot name="step"></slot>`
      : '<slot name="step"></slot>';
    return `<section class="card" aria-label="Guided steps">
      <div class="top"><span class="count" aria-live="polite">Step ${i + 1} of ${steps.length}</span>${
        saved === null ? '' : `<span class="saved">Draft saved ${esc(fmtDate(saved))}</span>`
      }</div>
      <ol class="steps">${items}</ol>${
        steps[i]?.description ? `<p class="desc">${esc(steps[i]!.description!)}</p>` : ''
      }
      <div class="compact"><label class="sr" for="menu">Go to step</label><select id="menu" data-act="menu">${options}</select></div>
      <div class="body">${body}</div>
      <div class="nav">
        <button class="btn" type="button" data-act="back"${i === 0 ? ' disabled' : ''}>Back</button>
        ${
          last
            ? `<button class="btn primary" type="button" data-act="submit"${blocked ? ' disabled' : ''}>Submit</button>`
            : '<button class="btn primary" type="button" data-act="next">Continue</button>'
        }
      </div>${blocked && last ? '<div class="note">Fix the steps marked Needs attention before you submit.</div>' : ''}
    </section>`;
  }
}

defineElement('henoyo-stepper', HenoyoStepper);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-stepper': HenoyoStepper;
  }
}
