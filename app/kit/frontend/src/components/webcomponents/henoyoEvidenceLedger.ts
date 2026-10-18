// <henoyo-evidence-ledger>: the evidence attached to a control, when it expires and who reviewed it.

import {
  DAY_MS,
  HenoyoElement,
  defineElement,
  emit,
  esc,
  fmtDate,
  glyph,
  ms,
  span,
} from './henoyoKit';

export type EvidenceVerdict = 'accepted' | 'rejected' | 'awaiting';

export interface HenoyoEvidenceItem {
  id: string;
  name: string;
  /** What sort of file it is, as text: "PDF", "Screenshot", "Export". */
  kind: string;
  collectedAt: string;
  expiresAt?: string;
  reviewer?: string;
  verdict: EvidenceVerdict;
}

const VERDICTS: Record<EvidenceVerdict, { word: string; icon: string }> = {
  accepted: { word: 'Accepted', icon: 'check' },
  rejected: { word: 'Rejected', icon: 'circle-x' },
  awaiting: { word: 'Awaiting review', icon: 'clock' },
};

const isVerdict = (v: unknown): v is EvidenceVerdict =>
  typeof v === 'string' && Object.hasOwn(VERDICTS, v);

type Expiry = { state: 'none' | 'ok' | 'soon' | 'expired'; text: string; at: number | null };

/** Expiry written out. "Soon" is inside 30 days; it carries an icon and the word, never colour alone. */
export function expiryOf(expiresAt: string | undefined, now: number): Expiry {
  const t = ms(expiresAt);
  if (t === null) return { state: 'none', text: 'No expiry', at: null };
  if (t < now) return { state: 'expired', text: `Expired ${span((now - t) / DAY_MS)} ago`, at: t };
  const state = t - now < 30 * DAY_MS ? 'soon' : 'ok';
  return { state, text: `Expires ${fmtDate(t)}`, at: t };
}

/** Expired first, then soonest expiry, then files that never expire; ties keep the given order. */
export function sortEvidence(
  items: readonly HenoyoEvidenceItem[],
  now: number,
): HenoyoEvidenceItem[] {
  const rank = (i: HenoyoEvidenceItem): number => {
    const e = expiryOf(i.expiresAt, now);
    return e.state === 'expired' ? 0 : e.state === 'none' ? 2 : 1;
  };
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => {
      const d = rank(a.item) - rank(b.item);
      if (d !== 0) return d;
      const ea = ms(a.item.expiresAt) ?? 0;
      const eb = ms(b.item.expiresAt) ?? 0;
      return ea - eb || a.index - b.index;
    })
    .map((x) => x.item);
}

export class HenoyoEvidenceLedger extends HenoyoElement {
  private _items: HenoyoEvidenceItem[] = [];
  private _editable = false;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-act]');
      if (!target) return;
      if (target.dataset.act === 'add') emit(this, 'henoyo:evidence-add', {});
      else if (target.dataset.act === 'open' && target.dataset.arg !== undefined)
        emit(this, 'henoyo:evidence-open', { id: target.dataset.arg });
    });
  }

  get items(): HenoyoEvidenceItem[] {
    return this._items;
  }
  set items(v: HenoyoEvidenceItem[]) {
    this._items = Array.isArray(v)
      ? v.filter((i) => i && typeof i === 'object' && i.id && i.name && isVerdict(i.verdict))
      : [];
    this.invalidate();
  }

  get editable(): boolean {
    return this._editable;
  }
  set editable(v: boolean) {
    this._editable = v === true;
    this.invalidate();
  }

  protected styles(): string {
    return `
:host { display:block; container-type:inline-size; }
.head { display:flex; justify-content:flex-end; margin-bottom:8px; }
.add { display:inline-flex; align-items:center; gap:6px; }
.ledger { list-style:none; margin:0; padding:0; border:1px solid var(--k-line); border-radius:8px; overflow:hidden; }
.item { display:grid; grid-template-columns:minmax(0,2fr) minmax(0,1.2fr) minmax(0,1.2fr) minmax(0,1.2fr); gap:var(--h-kit-gap-sm, 6px) 16px;
  align-items:start; padding:var(--h-kit-row-py, 10px) var(--h-kit-row-px, 14px); border-top:1px solid var(--k-line); color:var(--k-text); }
.item:first-child { border-top:0; }
.open { all:unset; cursor:pointer; display:block; min-width:0; }
.open:focus-visible { outline:2px solid var(--k-link); outline-offset:2px; }
.name { font-size:14px; font-weight:600; overflow-wrap:break-word; word-break:normal; }
.kind, .coll, .rev { font-size:12.5px; color:var(--k-text-3); overflow-wrap:break-word; word-break:normal; min-width:0; }
.item > * { min-width:0; }
.exp { display:inline-flex; align-items:center; gap:6px; font-size:13px; font-weight:600; }
.exp.expired { color:var(--k-bad); }
.exp.soon { color:var(--k-warn); }
.v { display:inline-flex; align-items:center; gap:6px; font-size:13px; font-weight:600; }
.v.accepted { color:var(--k-ok); }
.v.rejected { color:var(--k-bad); }
.v.awaiting { color:var(--k-info); }
.empty { padding:var(--h-kit-pad-y, 18px) var(--h-kit-row-px, 14px); border:1px dashed var(--k-line); border-radius:8px; color:var(--k-text-3); font-size:14px; }
@container (max-width:560px) { .item { grid-template-columns:minmax(0,1fr); gap:4px; } }
@media (max-width:560px) { .item { grid-template-columns:minmax(0,1fr); gap:4px; } }
`;
  }

  protected view(): string {
    const add = this._editable
      ? `<div class="head"><button class="linkbtn add" type="button" data-act="add">${glyph('plus', 14)}Add evidence</button></div>`
      : '';
    if (this._items.length === 0)
      return `<section aria-label="Evidence">${add}<div class="empty">No evidence attached. Add the document that shows this control works.</div></section>`;
    const now = Date.now();
    const rows = sortEvidence(this._items, now)
      .map((i) => {
        const ex = expiryOf(i.expiresAt, now);
        const exIcon =
          ex.state === 'expired'
            ? glyph('circle-alert', 14)
            : ex.state === 'soon'
              ? glyph('hourglass', 14)
              : '';
        const v = VERDICTS[i.verdict];
        const collected = ms(i.collectedAt);
        return `<li class="item" data-expiry="${ex.state}" data-verdict="${i.verdict}">
          <button class="open" type="button" data-act="open" data-arg="${esc(i.id)}"><span class="name">${esc(i.name)}</span><span class="kind" style="display:block">${esc(i.kind)}</span></button>
          <span class="coll">${collected === null ? '' : `Collected ${esc(fmtDate(collected))}`}</span>
          <span class="exp ${ex.state}">${exIcon}${esc(ex.text)}</span>
          <span><span class="v ${i.verdict}">${glyph(v.icon, 14)}${v.word}</span>${i.reviewer ? `<span class="rev" style="display:block">${esc(i.reviewer)}</span>` : ''}</span>
        </li>`;
      })
      .join('');
    return `<section aria-label="Evidence">${add}<ul class="ledger">${rows}</ul></section>`;
  }
}

defineElement('henoyo-evidence-ledger', HenoyoEvidenceLedger);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-evidence-ledger': HenoyoEvidenceLedger;
  }
}
