// <henoyo-record-banner>: what needs attention on this record, and why, above the record body.

import { HenoyoElement, defineElement, emit, esc, glyph } from './henoyoKit';

export type BannerLevel = 'info' | 'warning' | 'danger' | 'success';

export interface HenoyoBannerRow {
  id: string;
  level: BannerLevel;
  message: string;
  /** The rule behind the row, in quieter text. */
  reason?: string;
  /** With a label the row carries one action; the host handles `henoyo:banner-action`. */
  actionLabel?: string;
  /** Docket patch: overrides the level's word (danger reads "Overdue", which is wrong for a proven exploit). */
  word?: string;
  /** Where the action goes: a path inside the app. Without it the action does nothing. */
  href?: string;
}

/** Rows shown before "and N more". */
export const BANNER_VISIBLE = 3;

const LEVELS: Record<BannerLevel, { word: string; icon: string }> = {
  info: { word: 'Notice', icon: 'info' },
  warning: { word: 'Attention', icon: 'triangle-alert' },
  danger: { word: 'Overdue', icon: 'circle-alert' },
  success: { word: 'Done', icon: 'check' },
};

const isLevel = (v: unknown): v is BannerLevel => typeof v === 'string' && Object.hasOwn(LEVELS, v);

export class HenoyoRecordBanner extends HenoyoElement {
  private _rows: HenoyoBannerRow[] = [];
  private _expanded = false;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-act]');
      if (!target) return;
      if (target.dataset.act === 'action' && target.dataset.arg !== undefined)
        emit(this, 'henoyo:banner-action', { id: target.dataset.arg });
      else if (target.dataset.act === 'more') {
        this._expanded = !this._expanded;
        this.invalidate();
      }
    });
  }

  get rows(): HenoyoBannerRow[] {
    return this._rows;
  }
  set rows(v: HenoyoBannerRow[]) {
    this._rows = Array.isArray(v)
      ? v.filter((r) => r && typeof r === 'object' && isLevel(r.level) && r.message)
      : [];
    this.invalidate();
  }

  protected styles(): string {
    return `
:host { display:block; }
.stack { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:var(--h-kit-gap-sm, 8px); }
.row { display:flex; flex-wrap:wrap; align-items:baseline; gap:6px var(--h-kit-gap, 12px); padding:var(--h-kit-row-py, 10px) var(--h-kit-row-px, 14px); border-radius:8px;
  border-left:4px solid var(--b); background:var(--b-soft); color:var(--k-text); }
.row.info { --b:var(--k-info); --b-soft:var(--k-info-soft); }
.row.warning { --b:var(--k-warn); --b-soft:var(--k-warn-soft); }
.row.danger { --b:var(--k-bad); --b-soft:var(--k-bad-soft); }
.row.success { --b:var(--k-ok); --b-soft:var(--k-ok-soft); }
.lvl { display:inline-flex; align-items:baseline; line-height:20px; gap:6px; flex:none; font-size:12px; font-weight:700; color:var(--b); }
.txt { flex:1 1 240px; min-width:0; overflow-wrap:anywhere; }
.msg { font-size:14px; font-weight:600; line-height:20px; }
.why { margin-top:2px; font-size:12.5px; color:var(--k-text-3); }
.act { flex:none; align-self:center; }
.more { margin-top:8px; }
`;
  }

  protected view(): string {
    const rows = this._rows;
    if (rows.length === 0) return '';
    const shown = this._expanded ? rows : rows.slice(0, BANNER_VISIBLE);
    const hidden = rows.length - BANNER_VISIBLE;
    const items = shown
      .map((r) => {
        const { word: levelWord, icon } = LEVELS[r.level];
        const word = r.word ? esc(r.word) : levelWord;
        return `<li class="row ${r.level}" data-level="${r.level}">
          <span class="lvl">${glyph(icon, 16)}${word}</span>
          <span class="txt"><span class="msg">${esc(r.message)}</span>${r.reason ? `<span class="why" style="display:block">${esc(r.reason)}</span>` : ''}</span>
          ${r.actionLabel ? `<button class="linkbtn act" type="button" data-act="action" data-arg="${esc(r.id)}">${esc(r.actionLabel)}</button>` : ''}
        </li>`;
      })
      .join('');
    const more =
      hidden > 0
        ? `<div class="more"><button class="linkbtn" type="button" data-act="more" aria-expanded="${this._expanded}">${this._expanded ? 'Show fewer' : `and ${hidden} more`}</button></div>`
        : '';
    return `<section aria-label="Needs attention"><ul class="stack">${items}</ul>${more}</section>`;
  }
}

defineElement('henoyo-record-banner', HenoyoRecordBanner);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-record-banner': HenoyoRecordBanner;
  }
}
