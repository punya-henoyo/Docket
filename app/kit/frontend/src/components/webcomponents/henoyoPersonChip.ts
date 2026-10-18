// <henoyo-person-chip>: who someone is and what their role is here, as one consistent mark.

import { HenoyoElement, defineElement, esc, glyph, initials } from './henoyoKit';

export interface HenoyoPerson {
  name: string;
  role?: string;
  /** Tooltip only. */
  email?: string;
  /** Makes the chip a link; only http(s) and site-relative addresses are used. */
  href?: string;
}

type Size = 'sm' | 'md';

const DEFAULT_MAX = 4;

function clean(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

function person(v: unknown): HenoyoPerson | null {
  if (v === null || typeof v !== 'object') return null;
  const p = v as Record<string, unknown>;
  const name = clean(p['name']);
  if (name === undefined) return null;
  const out: HenoyoPerson = { name };
  for (const key of ['role', 'email', 'href'] as const) {
    const value = clean(p[key]);
    if (value !== undefined) out[key] = value;
  }
  return out;
}

const safeHref = (href: string | undefined): string | undefined =>
  href !== undefined && /^(https?:\/\/|\/(?!\/))/i.test(href) ? href : undefined;

/** "Name, Role": the accessible name, so the initials are never the only identifier. */
export function personLabel(p: HenoyoPerson): string {
  return p.role === undefined ? p.name : `${p.name}, ${p.role}`;
}

// The role prop is `personRole`: `role` is already the ARIA attribute on every element.
export class HenoyoPersonChip extends HenoyoElement {
  private _name: string | undefined;
  private _personRole: string | undefined;
  private _email: string | undefined;
  private _href: string | undefined;
  private _emptyText = 'No owner';
  private _size: Size = 'md';
  private _people: HenoyoPerson[] | undefined;
  private _max = DEFAULT_MAX;

  get name(): string | undefined {
    return this._name;
  }
  set name(v: string | undefined) {
    this._name = clean(v);
    this.invalidate();
  }
  get personRole(): string | undefined {
    return this._personRole;
  }
  set personRole(v: string | undefined) {
    this._personRole = clean(v);
    this.invalidate();
  }
  get email(): string | undefined {
    return this._email;
  }
  set email(v: string | undefined) {
    this._email = clean(v);
    this.invalidate();
  }
  get href(): string | undefined {
    return this._href;
  }
  set href(v: string | undefined) {
    this._href = clean(v);
    this.invalidate();
  }
  get emptyText(): string {
    return this._emptyText;
  }
  set emptyText(v: string | undefined) {
    this._emptyText = clean(v) ?? 'No owner';
    this.invalidate();
  }
  get size(): Size {
    return this._size;
  }
  set size(v: Size | undefined) {
    this._size = v === 'sm' ? 'sm' : 'md';
    this.invalidate();
  }
  get people(): HenoyoPerson[] | undefined {
    return this._people;
  }
  set people(v: HenoyoPerson[] | undefined) {
    this._people = Array.isArray(v)
      ? v.flatMap((p) => {
          const parsed = person(p);
          return parsed === null ? [] : [parsed];
        })
      : undefined;
    this.invalidate();
  }
  get max(): number {
    return this._max;
  }
  set max(v: number | undefined) {
    this._max = typeof v === 'number' && Number.isFinite(v) && v >= 1 ? Math.floor(v) : DEFAULT_MAX;
    this.invalidate();
  }

  protected styles(): string {
    return `
:host { display:inline-block; max-width:100%; }
.row { display:flex; flex-wrap:wrap; align-items:center; gap:var(--h-kit-gap-sm, 6px) var(--h-kit-gap, 12px); }
.p { display:inline-flex; align-items:center; gap:8px; min-width:0; max-width:100%; color:var(--k-text); text-decoration:none; font-size:14px; line-height:1.3; }
a.p:hover .nm { text-decoration:underline; }
.sm .p { gap:6px; font-size:13px; }
.mark { width:28px; height:28px; border-radius:999px; display:inline-grid; place-items:center; flex:none; font-size:11px; font-weight:700;
  background:var(--k-surface-2); color:var(--k-text-2); border:1px solid var(--k-hairline-2); }
.sm .mark { width:22px; height:22px; font-size:9px; }
.mark.none { background:transparent; color:var(--k-text-3); border-style:dashed; }
.mark svg { width:14px; height:14px; }
.sm .mark svg { width:12px; height:12px; }
.txt { display:flex; flex-direction:column; min-width:0; }
.nm { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:600; }
.rl { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:12px; color:var(--k-text-3); }
.empty-t { color:var(--k-text-3); font-style:italic; }
.more { display:inline-flex; align-items:center; padding:2px 9px; border-radius:999px; font-size:12px; font-weight:600; color:var(--k-text-2);
  background:var(--k-surface-2); border:1px solid var(--k-hairline-2); }
`;
  }

  private one(p: HenoyoPerson): string {
    const href = safeHref(p.href);
    const tip = p.email === undefined ? p.name : `${p.name} (${p.email})`;
    const body = `<span class="mark" aria-hidden="true">${esc(initials(p.name))}</span><span class="txt"><span class="nm">${esc(p.name)}</span>${
      p.role === undefined ? '' : `<span class="rl">${esc(p.role)}</span>`
    }</span>`;
    return href === undefined
      ? `<span class="p" role="group" aria-label="${esc(personLabel(p))}" title="${esc(tip)}">${body}</span>`
      : `<a class="p" href="${esc(href)}" aria-label="${esc(personLabel(p))}" title="${esc(tip)}">${body}</a>`;
  }

  private none(): string {
    return `<span class="p"><span class="mark none" aria-hidden="true">${glyph('user', 14)}</span><span class="nm empty-t">${esc(this._emptyText)}</span></span>`;
  }

  protected view(): string {
    const size = this._size;
    if (this._people !== undefined) {
      const all = this._people;
      if (all.length === 0) return `<span class="${size}">${this.none()}</span>`;
      const shown = all.slice(0, this._max);
      const rest = all.slice(this._max);
      const more =
        rest.length === 0
          ? ''
          : `<span class="more" title="${esc(rest.map((p) => p.name).join(', '))}"><span aria-hidden="true">+${rest.length}</span><span class="sr">${rest.length} more: ${esc(rest.map(personLabel).join('; '))}</span></span>`;
      return `<span class="row ${size}" role="group" aria-label="${esc(all.map(personLabel).join('; '))}">${shown.map((p) => this.one(p)).join('')}${more}</span>`;
    }
    if (this._name === undefined) return `<span class="${size}">${this.none()}</span>`;
    const p: HenoyoPerson = { name: this._name };
    if (this._personRole !== undefined) p.role = this._personRole;
    if (this._email !== undefined) p.email = this._email;
    if (this._href !== undefined) p.href = this._href;
    return `<span class="${size}">${this.one(p)}</span>`;
  }
}

defineElement('henoyo-person-chip', HenoyoPersonChip);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-person-chip': HenoyoPersonChip;
  }
}
