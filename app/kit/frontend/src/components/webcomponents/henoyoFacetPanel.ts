// <henoyo-facet-panel>: which slices a list has, how many rows each, and what is showing now.

import { HenoyoElement, defineElement, emit, esc, glyph } from './henoyoKit';

export interface HenoyoFacetValue {
  value: string;
  label: string;
  count: number;
}

export interface HenoyoFacet {
  id: string;
  label: string;
  /** Optional wording for the sentence, with {values} where the picks go, e.g. 'owned by {values}'. */
  phrase?: string;
  values: HenoyoFacetValue[];
  selected: string[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Drops a group or value the panel cannot draw, and keeps selected values that exist. */
export function normalizeFacets(raw: unknown): HenoyoFacet[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: HenoyoFacet[] = [];
  for (const item of raw) {
    const facet = normalizeFacet(item);
    if (!facet || seen.has(facet.id)) continue;
    seen.add(facet.id);
    out.push(facet);
  }
  return out;
}

function normalizeFacet(raw: unknown): HenoyoFacet | undefined {
  if (!isRecord(raw)) return undefined;
  const id = typeof raw['id'] === 'string' ? raw['id'] : '';
  const label = typeof raw['label'] === 'string' ? raw['label'] : '';
  if (id === '' || label === '') return undefined;
  const values: HenoyoFacetValue[] = [];
  const seen = new Set<string>();
  if (Array.isArray(raw['values'])) {
    for (const item of raw['values']) {
      if (!isRecord(item)) continue;
      const value = typeof item['value'] === 'string' ? item['value'] : '';
      const valueLabel = typeof item['label'] === 'string' ? item['label'] : '';
      const count = item['count'];
      if (value === '' || valueLabel === '' || seen.has(value)) continue;
      if (typeof count !== 'number' || !Number.isFinite(count) || count < 0) continue;
      seen.add(value);
      values.push({ value, label: valueLabel, count });
    }
  }
  if (values.length === 0) return undefined;
  const allowed = new Set(values.map((v) => v.value));
  const picked = new Set<string>();
  if (Array.isArray(raw['selected'])) {
    for (const item of raw['selected']) {
      if (typeof item === 'string' && allowed.has(item)) picked.add(item);
    }
  }
  const phrase = typeof raw['phrase'] === 'string' ? raw['phrase'].trim() : '';
  return {
    id,
    label,
    ...(phrase.includes('{values}') ? { phrase } : {}),
    values,
    selected: values.map((v) => v.value).filter((v) => picked.has(v)),
  };
}

function joinLabels(labels: readonly string[]): string {
  if (labels.length <= 1) return labels[0] ?? '';
  if (labels.length === 2) return `${labels[0]} and ${labels[1]}`;
  return `${labels.slice(0, -1).join(', ')} and ${labels[labels.length - 1]}`;
}

/**
 * The sentence the panel writes when the host did not pass one. A group with a phrase reads as
 * that phrase ('owned by A. Patel'); a group without one reads '<Label>: <values>'. Groups are
 * joined with ', ' when every one has a phrase, and with '; ' otherwise.
 */
export function facetSentence(facets: readonly HenoyoFacet[]): string {
  const parts: string[] = [];
  let allPhrased = true;
  for (const facet of facets) {
    const labels = facet.values.filter((v) => facet.selected.includes(v.value)).map((v) => v.label);
    if (labels.length === 0) continue;
    const values = joinLabels(labels);
    if (facet.phrase !== undefined) parts.push(facet.phrase.split('{values}').join(values));
    else {
      allPhrased = false;
      parts.push(`${facet.label}: ${values}`);
    }
  }
  return parts.join(allPhrased ? ', ' : '; ');
}

function selectedWord(count: number): string {
  if (count === 0) return 'None selected';
  return count === 1 ? '1 selected' : `${count} selected`;
}

function rowWord(count: number): string {
  return count === 1 ? '1 row' : `${count} rows`;
}

function sel(facetId: string, value?: string): string {
  const id = CSS.escape(facetId);
  if (value === undefined) return `button[data-act="toggle"][data-arg="${id}"]`;
  return `input[type="checkbox"][data-facet="${id}"][data-value="${CSS.escape(value)}"]`;
}

export class HenoyoFacetPanel extends HenoyoElement {
  private _facets: HenoyoFacet[] = [];
  private _sentence: string | undefined;
  private _editable = false;
  /** Groups the reader has opened. A group starts open. */
  private _open = new Set<string>();
  private _seen = new Set<string>();
  /** True after a click, so a host sentence does not hide the new selection. */
  private _dirty = false;
  private _focus: string | undefined;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement | null)?.closest<HTMLElement>('[data-act]');
      if (!target) return;
      if (target.dataset.act === 'toggle' && target.dataset.arg !== undefined)
        this.toggleOpen(target.dataset.arg);
      else if (target.dataset.act === 'clear') this.clearAll();
    });
    this.root.addEventListener('change', (e) => {
      if (!this._editable) return;
      const input = e.target;
      if (!(input instanceof HTMLInputElement) || input.type !== 'checkbox') return;
      const facetId = input.dataset.facet;
      const value = input.dataset.value;
      if (facetId === undefined || value === undefined) return;
      this.toggleValue(facetId, value, input.checked);
    });
    this.root.addEventListener('keydown', (e) => {
      if (e instanceof KeyboardEvent) this.onKey(e);
    });
  }

  get facets(): HenoyoFacet[] {
    return this._facets;
  }
  set facets(v: HenoyoFacet[]) {
    this._facets = normalizeFacets(v);
    const open = new Set<string>();
    for (const facet of this._facets) {
      if (!this._seen.has(facet.id) || this._open.has(facet.id)) open.add(facet.id);
    }
    this._seen = new Set(this._facets.map((facet) => facet.id));
    this._open = open;
    this._dirty = false;
    this.invalidate();
  }
  get sentence(): string | undefined {
    return this._sentence;
  }
  set sentence(v: string | undefined) {
    this._sentence = typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
    this._dirty = false;
    this.invalidate();
  }
  get editable(): boolean {
    return this._editable;
  }
  set editable(v: boolean) {
    this._editable = v === true;
    this.invalidate();
  }

  private toggleOpen(id: string): void {
    if (!this._facets.some((facet) => facet.id === id)) return;
    if (this._open.has(id)) this._open.delete(id);
    else this._open.add(id);
    this._focus = sel(id);
    this.invalidate();
  }

  private setOpen(id: string, open: boolean): void {
    if (!this._facets.some((facet) => facet.id === id)) return;
    if (this._open.has(id) === open) return;
    if (open) this._open.add(id);
    else this._open.delete(id);
    this._focus = sel(id);
    this.invalidate();
  }

  private toggleValue(facetId: string, value: string, on: boolean): void {
    const facet = this._facets.find((item) => item.id === facetId);
    if (!facet || !facet.values.some((item) => item.value === value)) return;
    const picked = new Set(facet.selected);
    if (on) picked.add(value);
    else picked.delete(value);
    facet.selected = facet.values.map((item) => item.value).filter((item) => picked.has(item));
    this._dirty = true;
    this._focus = sel(facetId, value);
    emit(this, 'henoyo:facets-change', { facetId, selected: [...facet.selected] });
    this.invalidate();
  }

  private clearAll(): void {
    if (!this._editable || !this._facets.some((facet) => facet.selected.length > 0)) return;
    for (const facet of this._facets) facet.selected = [];
    this._dirty = true;
    this._focus = 'button[data-act="toggle"]';
    emit(this, 'henoyo:facets-clear', {});
    this.invalidate();
  }

  private boxes(facetId: string): HTMLInputElement[] {
    return [
      ...this.root.querySelectorAll<HTMLInputElement>(
        `input[type="checkbox"][data-facet="${CSS.escape(facetId)}"]`,
      ),
    ];
  }

  private onKey(e: KeyboardEvent): void {
    const target = e.target;
    if (target instanceof HTMLButtonElement && target.dataset.act === 'toggle') {
      const id = target.dataset.arg;
      if (id === undefined) return;
      if (e.key === 'ArrowLeft') {
        e.preventDefault();
        this.setOpen(id, false);
      } else if (e.key === 'ArrowRight' || (e.key === 'ArrowDown' && !this._open.has(id))) {
        e.preventDefault();
        const wasOpen = this._open.has(id);
        this.setOpen(id, true);
        if (wasOpen && e.key === 'ArrowDown') this.boxes(id)[0]?.focus();
        else if (e.key === 'ArrowDown') this._focus = sel(id, this.firstValue(id));
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        this.boxes(id)[0]?.focus();
      }
      return;
    }
    if (!(target instanceof HTMLInputElement) || target.type !== 'checkbox') return;
    const facetId = target.dataset.facet;
    if (facetId === undefined) return;
    const boxes = this.boxes(facetId);
    const index = boxes.indexOf(target);
    if (index < 0) return;
    if (e.key === 'ArrowLeft') {
      e.preventDefault();
      this.root.querySelector<HTMLButtonElement>(sel(facetId))?.focus();
      return;
    }
    const last = boxes.length - 1;
    let next = index;
    if (e.key === 'ArrowDown') next = Math.min(last, index + 1);
    else if (e.key === 'ArrowUp') next = Math.max(0, index - 1);
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = last;
    else return;
    if (next !== index) {
      e.preventDefault();
      boxes[next]?.focus();
    }
  }

  private firstValue(id: string): string | undefined {
    return this._facets.find((facet) => facet.id === id)?.values[0]?.value;
  }

  private shownSentence(): string {
    if (!this._dirty && this._sentence !== undefined) return this._sentence;
    const built = facetSentence(this._facets);
    return built === '' ? 'No active filters' : built;
  }

  protected afterRender(): void {
    const target = this._focus;
    if (target === undefined) return;
    this._focus = undefined;
    this.root.querySelector<HTMLElement>(target)?.focus();
  }

  protected styles(): string {
    return `
:host { display:block; max-width:22rem; }
.panel { background:var(--k-surface); color:var(--k-text); border:1px solid var(--k-hairline);
  border-radius:var(--h-radius-card, 10px); padding:var(--h-kit-gap, 12px) calc(var(--h-kit-gap, 12px) + 4px); }
.active { display:flex; flex-wrap:wrap; align-items:flex-start; justify-content:space-between;
  gap:var(--h-space-2, 8px); margin-bottom:var(--h-kit-gap, 12px); }
.sentence { margin:0; min-width:0; flex:1 1 12rem; }
.kicker { display:block; font-size:11px; letter-spacing:.06em; text-transform:uppercase;
  color:var(--k-text-3); font-weight:700; }
.words { display:block; margin-top:var(--h-space-1, 4px); font-size:var(--h-text-base, 14.5px); overflow-wrap:anywhere; }
.mode { display:inline-flex; align-items:center; gap:var(--h-space-1, 4px); flex:none;
  font-size:12px; font-weight:700; }
.groups { display:flex; flex-direction:column; gap:var(--h-space-2, 8px); }
.group { border-top:1px solid var(--k-hairline); padding-top:var(--h-space-2, 8px); }
.group:first-child { border-top:0; padding-top:0; }
.gh { margin:0; font-size:inherit; font-weight:inherit; }
.gtoggle { display:flex; align-items:center; gap:var(--h-space-2, 8px); width:100%;
  min-height:var(--h-row-height-compact, 32px); margin:0; padding:0; border:0; background:transparent;
  color:inherit; font:inherit; text-align:left; cursor:pointer; }
.gtoggle svg { flex:none; }
.gtitle { font-family:var(--k-serif); font-size:var(--h-text-base, 14.5px); font-weight:600;
  min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.picked { margin-left:auto; flex:none; font-size:12px; font-weight:700; color:var(--k-text-2);
  font-variant-numeric:tabular-nums; }
.values { margin-top:var(--h-space-1, 4px); }
.row { display:flex; align-items:center; gap:var(--h-space-2, 8px); min-width:0;
  min-height:var(--h-row-height-compact, 32px); cursor:pointer; }
.row.zero { color:var(--k-text-3); }
.row input { flex:none; accent-color:var(--k-text); }
.row:has(input:disabled) { cursor:default; }
.lab { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  font-size:var(--h-text-base, 14.5px); }
.n { margin-left:auto; flex:none; font-size:12px; font-weight:700; font-variant-numeric:tabular-nums; }
.empty { margin:0; color:var(--k-text-2); font-size:var(--h-text-base, 14.5px); }
`;
  }

  protected view(): string {
    const facets = this._facets;
    if (facets.length === 0)
      return `<section class="panel" aria-label="Filters"><p class="empty">No filters to show yet.</p></section>`;
    const any = facets.some((facet) => facet.selected.length > 0);
    const action = this._editable
      ? any
        ? '<button class="linkbtn" type="button" data-act="clear">Clear all</button>'
        : ''
      : `<span class="mode">${glyph('lock', 14)}View only</span>`;
    const groups = facets
      .map((facet, index) => {
        const open = this._open.has(facet.id);
        const panelId = `fp-${index}`;
        const word = selectedWord(facet.selected.length);
        const rows = facet.values
          .map((value) => {
            const on = facet.selected.includes(value.value);
            const rowsWord = rowWord(value.count);
            return `<label class="row${value.count === 0 ? ' zero' : ''}"><input type="checkbox" data-facet="${esc(facet.id)}" data-value="${esc(value.value)}" aria-label="${esc(value.label)}, ${esc(rowsWord)}"${on ? ' checked' : ''}${this._editable ? '' : ' disabled'}><span class="lab" title="${esc(value.label)}">${esc(value.label)}</span><span class="n" title="${esc(rowsWord)}">${esc(value.count)}</span></label>`;
          })
          .join('');
        return `<div class="group"><h3 class="gh"><button class="gtoggle" type="button" data-act="toggle" data-arg="${esc(facet.id)}" aria-expanded="${open ? 'true' : 'false'}" aria-controls="${panelId}" aria-label="${esc(facet.label)}, ${esc(word)}, ${open ? 'Hide' : 'Show'}"><span aria-hidden="true">${glyph(open ? 'chevron-down' : 'chevron-right', 16)}</span><span class="gtitle" title="${esc(facet.label)}">${esc(facet.label)}</span><span class="picked">${esc(word)}</span></button></h3><div class="values" id="${panelId}" role="group" aria-label="${esc(facet.label)}"${open ? '' : ' hidden'}>${rows}</div></div>`;
      })
      .join('');
    return `<section class="panel" aria-label="Filters"><div class="active"><p class="sentence"><span class="kicker">Active filters</span><span class="words" aria-live="polite">${esc(this.shownSentence())}</span></p>${action}</div><div class="groups">${groups}</div></section>`;
  }
}

defineElement('henoyo-facet-panel', HenoyoFacetPanel);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-facet-panel': HenoyoFacetPanel;
  }
}
