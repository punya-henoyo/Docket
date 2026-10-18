// Shared base for the Henoyo Visual Kit web components: helpers, the material
// palette (henoyo-design object-icon-palette), and one shadow-DOM stylesheet so
// every component reads as one family. Theme tokens are used when present
// (--h-*), with the palette's paper values as fallbacks for builds without them.

import {
  MATERIALS,
  VIZ_FALLBACK,
  kitDate,
  kitLocale,
  kitTime,
  kitZoneName,
  scheme,
  schemeVars,
  type ColourScheme,
  type Material,
} from './colourScheme';
import { GLYPHS, type GlyphName } from './henoyoGlyphs';

export * from './colourScheme';

/** Record-type families. Fixed pairs [chip, glyph]; the chip names the type, never the status. */
export function isMaterial(value: unknown): value is Material {
  return typeof value === 'string' && value in MATERIALS;
}

export const DAY_MS = 86_400_000;

export function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Parses a date or timestamp as UTC. Date-only and zone-less values are UTC, not local. */
export function ms(iso: unknown): number | null {
  if (typeof iso !== 'string' || iso.trim() === '') return null;
  const v = iso.trim();
  const normalised =
    v.length === 10 ? `${v}T00:00:00Z` : /[zZ]|[+-]\d\d:?\d\d$/.test(v) ? v : `${v}Z`;
  const value = Date.parse(normalised);
  return Number.isNaN(value) ? null : value;
}

export function humanize(value: string): string {
  if (!/^[a-z0-9_]+$/.test(value)) return value;
  const text = value.replace(/_/g, ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function span(days: number): string {
  const d = Math.abs(days);
  if (d < 1) {
    const h = Math.round(d * 24);
    return h <= 1 ? 'under an hour' : `${h} hours`;
  }
  if (d < 14) return `${Math.round(d)} day${Math.round(d) === 1 ? '' : 's'}`;
  if (d < 60) return `${Math.round(d / 7)} weeks`;
  return `${Math.round(d / 30.4)} months`;
}

export function fmtDate(t: number): string {
  return kitDate(t);
}

export function fmtDateTime(t: number): string {
  return `${kitDate(t)} ${kitTime(t)} ${kitZoneName(t)}`;
}

export function initials(actor: string): string {
  const local = actor.split('@')[0] ?? actor;
  const parts = local.split(/[._\-\s]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '') + (parts[1]?.[0] ?? '')).toUpperCase() || '·';
}

export function glyph(name: GlyphName | string, size = 16, cls = 'g'): string {
  const glyphs = GLYPHS as Record<string, string>;
  const body = glyphs[name] ?? glyphs['file-text'];
  if (body === undefined) return '';
  return `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

/** A material chip with an instrument glyph, as on a record header (lg) or in a list. */
export function chip(material: Material, glyphName: GlyphName | string, large = false): string {
  const [bg, fg] = MATERIALS[material];
  return `<span class="chip${large ? ' lg' : ''}" style="background:${bg};color:${fg}">${glyph(glyphName, large ? 24 : 14)}</span>`;
}

/** Severity keeps Core's existing colours. */
export function severityVar(severity: string | undefined): string {
  const s = (severity ?? '').toLowerCase();
  if (s.startsWith('crit')) return 'var(--k-sev-critical)';
  if (s.startsWith('high')) return 'var(--k-sev-high)';
  if (s.startsWith('med')) return 'var(--k-sev-medium)';
  if (s.startsWith('low')) return 'var(--k-sev-low)';
  return 'var(--k-sev-info)';
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function worstSeverity(values: (string | undefined)[]): string | undefined {
  let best = SEVERITY_ORDER.length;
  for (const v of values) {
    const i = SEVERITY_ORDER.indexOf((v ?? '').toLowerCase());
    if (i >= 0 && i < best) best = i;
  }
  return SEVERITY_ORDER[best];
}

export function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.find((a) => a === value) ?? fallback;
}

export function finite(n: unknown): number | null {
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
}

/** Caption for a view built from a capped fetch, so a partial count never reads as exact. */
export function truncatedNote(truncated: boolean): string {
  return truncated ? '<div class="foot">Showing the first 1,000 related records.</div>' : '';
}

/** The same caption as `truncatedNote`, as a footer segment for `foot()`. */
export function truncatedSpan(truncated: boolean): string {
  return truncated ? '<span>Showing the first 1,000 related records.</span>' : '';
}

export function emit(el: HTMLElement, type: string, detail: Record<string, unknown>): void {
  el.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
}

/** CSV download, formula-safe. Callers must check exportEnabled first. Emits henoyo:export for audit. */
export function downloadCsv(
  el: HTMLElement,
  name: string,
  header: string[],
  rows: (string | number | undefined)[][],
): void {
  const quote = (v: string | number | undefined): string => {
    const raw = v === undefined ? '' : String(v);
    const safe = /^[=+\-@\t\r]/.test(raw) && typeof v !== 'number' ? `'${raw}` : raw;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const text = [header.map(quote).join(','), ...rows.map((r) => r.map(quote).join(','))].join('\n');
  const a = document.createElement('a');
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
  a.href = url;
  a.download = `${name}-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  emit(el, 'henoyo:export', { component: el.localName, format: 'csv', rows: rows.length });
}

export type StatTone = 'ok' | 'warn' | 'bad' | 'info' | 'neutral';

export interface KitStat {
  text: string;
  tone?: StatTone;
  icon?: GlyphName | string;
  /** Extra data attributes, such as `data-outcome`. */
  data?: Record<string, string>;
}

export interface KitSource {
  label: string;
  href?: string;
}

export interface LegendItem {
  label: string;
  /** Any CSS colour; the swatch is a filled 10px square. */
  color: string;
  count?: number | string;
  /** Extra inline style on the swatch, for a stroke or outline the caller already computes. */
  swatchStyle?: string;
}

export interface HeadOptions {
  /** One line under the title: the so-what or what to do. */
  sub?: string;
  /** At most three are drawn. */
  stats?: readonly KitStat[];
  /** Markup left of the title, such as a material chip. */
  lead?: string;
  /** Markup right of the stat pills, such as an Export button. */
  actions?: string;
}

const compactFormats = new Map<string, Intl.NumberFormat>();

/** 12k, 1.2M: for axes and tight labels. */
export function compact(n: number): string {
  const locale = kitLocale();
  let format = compactFormats.get(locale);
  if (!format) {
    format = new Intl.NumberFormat(locale, { notation: 'compact', maximumFractionDigits: 1 });
    compactFormats.set(locale, format);
  }
  return format.format(n);
}

export function statPill(stat: KitStat): string {
  const icon = stat.icon === undefined || stat.icon === '' ? '' : glyph(stat.icon, 12);
  const data = Object.entries(stat.data ?? {})
    .map(([k, v]) => ` data-${esc(k)}="${esc(v)}"`)
    .join('');
  return `<span class="stat ${stat.tone ?? 'neutral'}"${data}>${icon}${esc(stat.text)}</span>`;
}

/** One legend style for every chart: swatch, label, then the count in tabular figures. */
export function legend(items: readonly LegendItem[]): string {
  if (items.length === 0) return '';
  const rows = items
    .map(
      (i) =>
        `<li><span class="sw" style="background:${esc(i.color)};${esc(i.swatchStyle ?? '')}"></span>${esc(i.label)}${
          i.count === undefined ? '' : `<span class="n">${esc(i.count)}</span>`
        }</li>`,
    )
    .join('');
  return `<ul class="legend">${rows}</ul>`;
}

function internalHref(href: string | undefined): string | undefined {
  return typeof href === 'string' && /^\/(?![/\\])/.test(href) && !/\s/.test(href)
    ? href
    : undefined;
}

let helpSeq = 0;

export function nextFrameId(): string {
  return `k${++helpSeq}`;
}

/** The help "i" and its tooltip: a button described by a role="tooltip", shown on hover and focus. */
export function helpMarkup(id: string, text: string | undefined): string {
  if (text === undefined) return '';
  return `<span class="helpwrap"><button type="button" class="help" aria-label="About this chart" aria-describedby="${id}-tip">i</button><span class="tip" role="tooltip" id="${id}-tip">${esc(text)}</span></span>`;
}

/** "From <source> · as of <time>" as one footer segment; empty when there is no source. */
export function sourceMarkup(src: KitSource | undefined, asOf: string | undefined): string {
  if (src === undefined || src.label === '') return '';
  const at = ms(asOf);
  const href = internalHref(src.href);
  return `<span>From ${href === undefined ? esc(src.label) : `<a data-nav href="${esc(href)}">${esc(src.label)}</a>`}${
    at === null ? '' : ` · as of ${esc(fmtDateTime(at))}`
  }</span>`;
}

/** Escape closes an open tooltip; it opens again on the next hover or focus. A source link asks the host to navigate. */
export function wireFrame(root: ShadowRoot, host: HTMLElement): void {
  root.addEventListener('keydown', (e) => {
    if ((e as KeyboardEvent).key !== 'Escape') return;
    for (const w of root.querySelectorAll('.helpwrap')) w.setAttribute('data-dismissed', '');
  });
  for (const type of ['pointerover', 'focusin'])
    root.addEventListener(type, (e) =>
      (e.target as Element | null)?.closest?.('.helpwrap')?.removeAttribute('data-dismissed'),
    );
  root.addEventListener('click', (e) => {
    const link = (e.target as Element | null)?.closest<HTMLAnchorElement>('a[data-nav]');
    if (link === null || link === undefined) return;
    const me = e as MouseEvent;
    if (me.button !== 0 || me.metaKey || me.ctrlKey || me.shiftKey || me.altKey) return;
    e.preventDefault();
    emit(host, 'henoyo:navigate', { href: link.getAttribute('href') ?? '' });
  });
}

export interface HelpTokens {
  surface: string;
  text: string;
  line: string;
  muted: string;
  serif: string;
}

/** The help tooltip's CSS for a stylesheet that does not use the kit's variables. */
export function helpCss(t: HelpTokens): string {
  return `.helpwrap { position:relative; display:inline-flex; margin-left:6px; vertical-align:middle; }
.help { width:18px; height:18px; padding:0; border-radius:999px; border:1px solid ${t.line}; background:${t.surface};
  color:${t.muted}; font-family:${t.serif}; font-style:italic; font-weight:600; font-size:11px; cursor:help; display:inline-grid; place-items:center; }
.help:hover, .help:focus-visible { color:${t.text}; border-color:${t.muted}; }
.tip { display:none; position:absolute; z-index:5; top:24px; left:-8px; width:max-content; max-width:min(260px, 70vw); padding:8px 10px;
  border-radius:8px; background:${t.text}; color:${t.surface}; font-size:12px; line-height:1.45; font-weight:400; font-style:normal; letter-spacing:0; text-transform:none; }
.helpwrap:hover .tip, .helpwrap:focus-within .tip { display:block; }
.helpwrap[data-dismissed] .tip { display:none; }`;
}

/** Base element: open shadow root, microtask-batched renders, render only while connected. */
export abstract class HenoyoElement extends HTMLElement {
  protected readonly root: ShadowRoot;
  private queued = false;
  private _colourScheme: string | undefined;
  private _helpText: string | undefined;
  private _source: KitSource | undefined;
  private _asOf: string | undefined;
  protected readonly frameId = nextFrameId();

  constructor() {
    super();
    this.root = this.attachShadow({ mode: 'open' });
    wireFrame(this.root, this);
  }

  get helpText(): string | undefined {
    return this._helpText;
  }
  set helpText(v: string | undefined) {
    this._helpText = typeof v === 'string' && v.trim() !== '' ? v : undefined;
    this.invalidate();
  }
  get source(): KitSource | undefined {
    return this._source;
  }
  set source(v: KitSource | undefined) {
    this._source = v;
    this.invalidate();
  }
  get asOf(): string | undefined {
    return this._asOf;
  }
  set asOf(v: string | undefined) {
    this._asOf = v;
    this.invalidate();
  }

  /** The shared header: eyebrow (the admin's title), finding as the title, help "i", up to three stat pills. */
  protected head(eyebrow: string, title: string, opts: HeadOptions = {}): string {
    const help = helpMarkup(this.frameId, this._helpText);
    const stats = (opts.stats ?? []).slice(0, 3).map(statPill).join('');
    return `<div class="head"><div class="head-l">${opts.lead ?? ''}<div class="head-t">${
      eyebrow === '' ? '' : `<div class="eyebrow">${esc(eyebrow)}</div>`
    }<div class="trow"><h3 class="title">${esc(title)}</h3>${help}</div>${
      opts.sub === undefined || opts.sub === '' ? '' : `<div class="sub">${esc(opts.sub)}</div>`
    }</div></div>${stats === '' && opts.actions === undefined ? '' : `<div class="stats">${stats}${opts.actions ?? ''}</div>`}</div>`;
  }

  /** "From <source> · as of <time>", then any extra note. Nothing when the binding gave no source. */
  protected foot(extra = ''): string {
    const from = sourceMarkup(this._source, this._asOf);
    return from === '' && extra === '' ? '' : `<div class="foot">${from}${extra}</div>`;
  }

  /** A card whose header stays when there is nothing to draw. */
  protected emptyCard(eyebrow: string, title: string, message = 'Nothing to show yet.'): string {
    return `<div class="card">${this.head(eyebrow, title)}<div class="empty">${esc(message)}</div>${this.foot()}</div>`;
  }

  connectedCallback(): void {
    this.invalidate();
  }

  get colourScheme(): string | undefined {
    return this._colourScheme;
  }
  set colourScheme(v: string | undefined) {
    this._colourScheme = v;
    this.invalidate();
  }

  protected scheme(): ColourScheme {
    return scheme(this._colourScheme, this);
  }

  protected invalidate(): void {
    if (this.queued) return;
    this.queued = true;
    queueMicrotask(() => {
      this.queued = false;
      if (this.isConnected)
        this.root.innerHTML = `<style>${KIT_STYLE}${this.schemeStyle()}${this.styles()}</style>${this.view()}`;
      this.afterRender();
    });
  }

  protected styles(): string {
    return '';
  }

  private schemeStyle(): string {
    const s = this.scheme();
    return s.id === 'editorial' ? '' : schemeVars(s);
  }

  protected afterRender(): void {}

  protected abstract view(): string;
}

export function defineElement(name: string, ctor: CustomElementConstructor): void {
  if (typeof customElements !== 'undefined' && customElements.get(name) === undefined)
    customElements.define(name, ctor);
}

const triplet = (hex: string): string =>
  [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16)).join(' ');
const RAMP_VARS = [
  ...VIZ_FALLBACK.seq.map((hex, i) => `--k-ramp-${i}:rgb(var(--h-viz-seq-${i}, ${triplet(hex)}));`),
  `--k-accent:rgb(var(--h-viz-1, ${triplet(VIZ_FALLBACK.categorical[0]!)}));`,
].join(' ');
const MAT_VARS = (Object.keys(MATERIALS) as Material[])
  .map((m) => `--m-${m}-bg:${MATERIALS[m][0]};--m-${m}-fg:${MATERIALS[m][1]};`)
  .join('');

const HELP_CSS = helpCss({
  surface: 'var(--k-surface)',
  text: 'var(--k-text)',
  line: 'var(--k-hairline-2)',
  muted: 'var(--k-text-3)',
  serif: 'var(--k-serif)',
});

export const KIT_STYLE = `
:host { display:block; min-width:0; max-width:100%; font-family:inherit; ${MAT_VARS}
  --k-surface:rgb(var(--h-surface, 255 254 251)); --k-surface-2:rgb(var(--h-surface-2, 246 243 236));
  --k-canvas:rgb(var(--h-canvas, 251 248 241)); --k-hairline:rgb(var(--h-hairline, 227 223 212)); --k-hairline-2:rgb(var(--h-hairline-2, 208 202 188));
  --k-text:rgb(var(--h-text, 26 31 28)); --k-text-2:rgb(var(--h-text-2, 58 67 60)); --k-text-3:rgb(var(--h-text-3, 92 86 76));
  --k-link:rgb(var(--h-text-link, 30 54 76)); --k-brand:rgb(var(--h-brand, 59 96 71));
  --k-ok:rgb(var(--h-status-success, 24 74 46)); --k-ok-soft:rgb(var(--h-status-success-soft, 211 227 216));
  --k-warn:rgb(var(--h-status-warning, 92 64 14)); --k-warn-soft:rgb(var(--h-status-warning-soft, 232 213 174));
  --k-bad:rgb(var(--h-status-danger, 110 46 40)); --k-bad-soft:rgb(var(--h-status-danger-soft, 231 210 198));
  --k-info:rgb(var(--h-status-info, 30 54 76)); --k-info-soft:rgb(var(--h-status-info-soft, 208 220 230));
  --k-neutral:rgb(var(--h-status-neutral, 92 86 76)); --k-neutral-soft:rgb(var(--h-status-neutral-soft, 221 212 198));
  --k-sev-critical:rgb(var(--h-sev-critical, 110 42 28)); --k-sev-high:rgb(var(--h-sev-high, 150 64 48));
  --k-sev-medium:rgb(var(--h-sev-medium, 138 90 30)); --k-sev-low:rgb(var(--h-sev-low, 79 107 91)); --k-sev-info:rgb(var(--h-sev-info, 95 103 95));
  ${RAMP_VARS}
  --k-serif:"Source Serif 4", Georgia, serif; --k-radius:14px; color:var(--k-text); }
* { box-sizing:border-box; }
button { font:inherit; color:inherit; }
:focus-visible { outline:2px solid var(--k-brand); outline-offset:2px; border-radius:6px; }
.card { height:100%; display:flex; flex-direction:column; background:var(--k-surface); border:1px solid var(--k-hairline); border-radius:var(--k-radius); overflow:hidden;
  box-shadow:0 1px 2px rgb(0 0 0 / .03), 0 8px 24px -18px rgb(0 0 0 / .25); }
.head { display:flex; flex-wrap:wrap; align-items:flex-start; justify-content:space-between; gap:var(--h-kit-gap, 12px); padding:var(--h-kit-pad-y, 18px) var(--h-kit-pad, 22px) var(--h-kit-head-pb, 12px); }
.head-l { display:flex; gap:var(--h-kit-gap, 12px); align-items:center; min-width:0; }
.head-t { min-width:0; }
.eyebrow { font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:var(--k-text-3); font-weight:600; }
.trow { display:flex; align-items:center; gap:2px; margin-top:2px; }
.title { margin:0; font-family:var(--k-serif); font-size:var(--h-kit-title-size, 20px); font-weight:500; letter-spacing:-.01em; }
.sub { margin-top:4px; font-size:13px; color:var(--k-text-2); }
.stats { display:flex; flex-wrap:wrap; gap:var(--h-kit-gap-sm, 6px); align-items:center; }
.body { padding:4px var(--h-kit-pad, 22px) var(--h-kit-pad-y, 18px); }
.chip { display:inline-grid; place-items:center; flex:none; width:24px; height:24px; border-radius:5px; }
.chip.lg { width:48px; height:48px; border-radius:10px; }
${HELP_CSS}
.stat { display:inline-flex; align-items:center; gap:6px; font-variant-numeric:tabular-nums; padding:5px 10px; border-radius:999px; font-size:12px; font-weight:600;
  background:var(--k-surface-2); border:1px solid var(--k-hairline); white-space:nowrap; }
.stat.ok { background:var(--k-ok-soft); color:var(--k-ok); border-color:transparent; }
.stat.warn { background:var(--k-warn-soft); color:var(--k-warn); border-color:transparent; }
.stat.bad { background:var(--k-bad-soft); color:var(--k-bad); border-color:transparent; }
.stat.info { background:var(--k-info-soft); color:var(--k-info); border-color:transparent; }
.stat svg { width:12px; height:12px; }
.pill { display:inline-flex; align-items:center; padding:2px 9px; border-radius:999px; font-size:12px; font-weight:600; white-space:nowrap; }
.av { width:22px; height:22px; border-radius:999px; display:inline-grid; place-items:center; font-size:9px; font-weight:700;
  background:var(--m-stone-bg); color:var(--m-stone-fg); flex:none; }
.muted { color:var(--k-text-3); }
.mono { font-variant-numeric:tabular-nums; }
.btn { display:inline-flex; align-items:center; gap:6px; padding:6px 12px; border-radius:999px; font-size:12px; font-weight:600; cursor:pointer;
  background:transparent; color:var(--k-text); border:1px solid var(--k-hairline-2); }
.btn:hover { background:var(--k-surface-2); }
.btn.primary { background:var(--k-text); color:var(--k-surface); border-color:transparent; }
.btn.primary:hover { background:var(--k-text); opacity:.88; }
.linkbtn { background:none; border:0; padding:0; cursor:pointer; color:var(--k-link); font-weight:600; font-size:12px; }
.linkbtn:hover { text-decoration:underline; }
.foot { margin-top:auto; display:flex; flex-wrap:wrap; gap:var(--h-kit-gap-sm, 6px) 16px; padding:var(--h-kit-row-py, 10px) var(--h-kit-pad, 22px) calc(var(--h-kit-pad-y, 18px) - 4px); font-size:12px; color:var(--k-text-3); border-top:1px solid var(--k-hairline); }
.foot a { color:var(--k-link); font-weight:600; text-decoration:none; }
.foot a:hover { text-decoration:underline; }
.foot b { color:var(--k-text-2); font-weight:600; }
.lead { margin:0 0 var(--h-kit-gap, 12px); font-size:14px; color:var(--k-text-2); }
.legend { display:flex; flex-wrap:wrap; gap:var(--h-kit-gap-sm, 6px) 14px; margin:var(--h-kit-gap, 12px) 0 0; padding:0; list-style:none; }
.legend li { display:flex; align-items:center; gap:6px; font-size:12px; color:var(--k-text-2); }
.legend .n { font-variant-numeric:tabular-nums; color:var(--k-text-3); }
.sw { width:10px; height:10px; border-radius:3px; box-sizing:border-box; flex:none; }
.note { min-height:1.25em; margin:8px 0 0; font-size:12px; color:var(--k-text-2); }
.note:empty { display:none; }
.clip { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); }
svg.plot { width:100%; height:auto; max-height:280px; display:block; }
.axis { fill:var(--k-text-3); font-size:11px; font-variant-numeric:tabular-nums; }
.grid { stroke:var(--k-hairline); stroke-width:1; }
.base { stroke:var(--k-hairline-2); stroke-width:1; }
.empty { padding:calc(var(--h-kit-empty-py, 32px) - 8px) var(--h-kit-pad, 22px); text-align:center; color:var(--k-text-2); font-size:13px; }
.sr { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }
@media (prefers-reduced-motion: reduce) { * { animation:none !important; transition:none !important; } }
@media (max-width: 720px) { .head, .body, .foot { padding-left:min(16px, var(--h-kit-pad, 22px)); padding-right:min(16px, var(--h-kit-pad, 22px)); } }
`;
