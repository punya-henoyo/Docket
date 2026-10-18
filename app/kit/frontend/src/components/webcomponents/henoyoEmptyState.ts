// <henoyo-empty-state>: what a list with no rows is for, where its rows come from, and what to do.

import { HenoyoElement, defineElement, emit, esc } from './henoyoKit';

export class HenoyoEmptyState extends HenoyoElement {
  private _heading = '';
  private _body = '';
  private _actionLabel: string | undefined;
  private _learnMoreHref: string | undefined;
  private _filtered = false;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      if ((e.target as HTMLElement).closest('[data-act="action"]'))
        emit(this, 'henoyo:empty-action', { filtered: this._filtered });
    });
  }

  get heading(): string {
    return this._heading;
  }
  set heading(v: string) {
    this._heading = typeof v === 'string' ? v : '';
    this.invalidate();
  }
  get body(): string {
    return this._body;
  }
  set body(v: string) {
    this._body = typeof v === 'string' ? v : '';
    this.invalidate();
  }
  get actionLabel(): string | undefined {
    return this._actionLabel;
  }
  set actionLabel(v: string | undefined) {
    this._actionLabel = typeof v === 'string' && v !== '' ? v : undefined;
    this.invalidate();
  }
  get learnMoreHref(): string | undefined {
    return this._learnMoreHref;
  }
  /** Only https links are drawn. */
  set learnMoreHref(v: string | undefined) {
    this._learnMoreHref = typeof v === 'string' && /^https:\/\//i.test(v) ? v : undefined;
    this.invalidate();
  }
  /** Rows exist but the filters hide them: the heading and action switch to "Clear filters". */
  get filtered(): boolean {
    return this._filtered;
  }
  set filtered(v: boolean) {
    this._filtered = v === true;
    this.invalidate();
  }

  protected styles(): string {
    return `
:host { display:block; }
.empty-state { border:1px dashed var(--k-hairline-2); border-radius:var(--k-radius); background:var(--k-surface);
  padding:var(--h-kit-empty-py, 32px) 20px; text-align:center; color:var(--k-text); }
.h { margin:0; font-family:var(--k-serif); font-size:var(--h-kit-title-size, 20px); font-weight:600; }
.b { margin:8px auto 0; max-width:52ch; font-size:14px; color:var(--k-text-2); }
.acts { margin-top:calc(var(--h-kit-gap, 12px) + 4px); display:flex; flex-wrap:wrap; justify-content:center; align-items:center; gap:8px 16px; }
.act { min-height:32px; padding:0 14px; border-radius:8px; border:1px solid var(--k-link); background:none; color:var(--k-link); font-weight:600; font-size:13px; cursor:pointer; }
.act:hover { text-decoration:underline; }
.learn { font-size:13px; color:var(--k-text-2); }
`;
  }

  protected view(): string {
    const filtered = this._filtered;
    const heading = filtered ? 'No rows match these filters' : this._heading;
    if (heading === '') return '';
    const label = filtered ? 'Clear filters' : this._actionLabel;
    const action = label
      ? `<button class="act" type="button" data-act="action">${esc(label)}</button>`
      : '';
    const learn = this._learnMoreHref
      ? `<a class="learn" href="${esc(this._learnMoreHref)}" target="_blank" rel="noopener noreferrer">Learn more</a>`
      : '';
    const body = filtered ? '' : this._body;
    return `<section class="empty-state" aria-label="${esc(heading)}"><h3 class="h">${esc(heading)}</h3>${
      body ? `<p class="b">${esc(body)}</p>` : ''
    }${action || learn ? `<div class="acts">${action}${learn}</div>` : ''}</section>`;
  }
}

defineElement('henoyo-empty-state', HenoyoEmptyState);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-empty-state': HenoyoEmptyState;
  }
}
