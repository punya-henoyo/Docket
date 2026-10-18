// <henoyo-record-timeline>: read-only audit trail for one record.
// Henoyo web-component contract: Custom Element v1, open shadow root, data in
// through properties (events, gaps, meta), events out as composed `henoyo:*`
// CustomEvents, colours only from the --h-* theme tokens.

import { eventTitleParts, humanize as humanizeValue, type ValueLabels } from './timelineText';
import { kitDate, kitDayMonth, kitLocale, kitTime, kitTimeZone } from './colourScheme';
import {
  helpCss,
  helpMarkup,
  nextFrameId,
  sourceMarkup,
  wireFrame,
  type KitSource,
} from './henoyoKit';

export interface HenoyoTimelineEvent {
  id: string;
  kind: string;
  at: string;
  title: string;
  actor?: string;
  from?: string;
  to?: string;
  cause?: string;
  /** false: this row's `to` is not a status value, so it never counts as a phase. */
  phase?: boolean;
  /** The field that changed ("Status"); with from/to it makes the title "Field: old → new". */
  field?: string;
}

export interface HenoyoTimelineGap {
  id: string;
  label: string;
}

export interface HenoyoTimelineLane {
  kind: string;
  label: string;
  role?: string;
}

export interface HenoyoTimelineMeta {
  subject?: string;
  openedAt?: string;
  dueAt?: string;
  closedAt?: string;
  lanes?: HenoyoTimelineLane[];
  /** false hides Export. The host passes the org export policy AND the placement's own switch; it can only restrict. */
  exportEnabled?: boolean;
  /** Picklist labels by stored value, used for event titles and from/to pills. */
  valueLabels?: Record<string, string>;
  /** The record's current value of the phase field; the phase bar ends here when events do not reach it. */
  currentStatus?: string;
  /** Stored values and labels of the phase field; a title whose new value is none of them is no status change. */
  phaseValues?: string[];
}

const humanize = (value: string, labels?: ValueLabels): string => humanizeValue(value, labels);

const LANE_TONES = [
  'brand',
  'status-warning',
  'status-info',
  'viz-8',
  'viz-4',
  'status-success',
  'viz-2',
  'viz-6',
];
const PRIORITY = ['approval', 'signoff', 'exception', 'validation', 'evidence', 'status'];
const DAY_MS = 86_400_000;

/** "Pending validation" -> "PV"; a single word -> its first three letters. */
export function phaseAbbreviation(label: string): string {
  const words = label
    .trim()
    .split(/[\s_-]+/)
    .filter((w) => w !== '');
  if (words.length === 0) return '';
  if (words.length === 1) return (words[0] ?? '').slice(0, 3);
  return words
    .map((w) => w.charAt(0).toUpperCase())
    .join('')
    .slice(0, 3);
}
const REFUSAL = /\b(refus|reject|den(y|ied)|declin|block)/i;

export interface FlagPlacement {
  /** Which side of the marker line the flag extends towards. */
  align: 'start' | 'center' | 'end';
  /** 0 = nearest the track, 1 = staggered one row higher. */
  row: number;
}

/**
 * Collision-aware flag layout. `pcts` are marker positions (0..100) in the
 * order of priority; `widthPct` is the estimated width of each flag as a share
 * of the track. Flags near an edge flip to stay inside the track; flags that
 * would overlap an earlier flag on the same row move up a row.
 */
export function layoutFlags(pcts: number[], widthPcts: number[]): FlagPlacement[] {
  const spans: { lo: number; hi: number; row: number }[] = [];
  return pcts.map((pct, i) => {
    const w = widthPcts[i] ?? 0;
    let align: FlagPlacement['align'] = 'center';
    let lo = pct - w / 2;
    let hi = pct + w / 2;
    if (lo < 0) {
      align = 'start';
      lo = pct;
      hi = pct + w;
    } else if (hi > 100) {
      align = 'end';
      lo = pct - w;
      hi = pct;
    }
    let row = 0;
    while (spans.some((s) => s.row === row && lo < s.hi + 1 && hi > s.lo - 1)) row += 1;
    spans.push({ lo, hi, row });
    return { align, row };
  });
}

function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function ms(iso: unknown): number | null {
  if (typeof iso !== 'string' || iso.trim() === '') return null;
  const v = iso.trim();
  const normalised =
    v.length === 10 ? `${v}T00:00:00Z` : /[zZ]|[+-]\d\d:?\d\d$/.test(v) ? v : `${v}Z`;
  const value = Date.parse(normalised);
  return Number.isNaN(value) ? null : value;
}

function statusTone(value: string): string {
  const v = value.toLowerCase();
  if (v.includes('closed') || v.includes('remediated')) return 'status-success';
  if (v.includes('accept')) return 'viz-4';
  if (v.includes('exception') || v.includes('rejected')) return 'status-warning';
  if (v.includes('validation')) return 'status-info';
  if (v.includes('remediation')) return 'brand';
  return 'status-neutral';
}

function fmtDay(t: number): string {
  return kitDate(t);
}

function fmtWeekday(t: number): string {
  return new Date(t).toLocaleDateString(kitLocale(), { weekday: 'short', timeZone: kitTimeZone() });
}

function fmtShort(t: number): string {
  return kitDayMonth(t);
}

function fmtTime(t: number): string {
  return kitTime(t);
}

function span(days: number): string {
  if (days < 1) return 'under a day';
  if (days < 14) return `${Math.round(days)} day${Math.round(days) === 1 ? '' : 's'}`;
  if (days < 60) return `${Math.round(days / 7)} weeks`;
  return `${Math.round(days / 30.4)} months`;
}

function relative(t: number, now: number): string {
  const days = (now - t) / DAY_MS;
  if (days < 1) return 'today';
  return `${span(days)} ago`;
}

function initials(actor: string): string {
  const local = actor.split('@')[0] ?? actor;
  const parts = local.split(/[._\-\s]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '') + (parts[1]?.[0] ?? '')).toUpperCase() || '·';
}

function sourceOf(id: string): { object: string; record: string } | null {
  const [object, record] = id.split(':');
  if (object === undefined || record === undefined || record === 'row') return null;
  return { object, record };
}

interface Moment {
  key: string;
  t: number;
  events: HenoyoTimelineEvent[];
}

const STYLE = `
${helpCss({
  surface: 'rgb(var(--h-surface))',
  text: 'rgb(var(--h-text))',
  line: 'rgb(var(--h-hairline-2))',
  muted: 'rgb(var(--h-text-3))',
  serif: 'Georgia, serif',
})}
.titlerow { display:flex; align-items:center; }
.titlerow h2 { margin:4px 0 0; }
footer a { color:rgb(var(--h-text-link)); font-weight:600; text-decoration:none; }
footer a:hover { text-decoration:underline; }
:host { display:block; font-family:inherit; color:rgb(var(--h-text)); --tl-radius:14px; }
* { box-sizing:border-box; }
button { font:inherit; color:inherit; }
.card { background:rgb(var(--h-surface)); border:1px solid rgb(var(--h-hairline)); border-radius:var(--tl-radius); overflow:hidden;
  box-shadow:0 1px 2px rgb(var(--h-text) / .04), 0 8px 24px -16px rgb(var(--h-text) / .18); }
header { display:flex; flex-wrap:wrap; align-items:flex-start; justify-content:space-between; gap:var(--h-kit-gap, 12px); padding:calc(var(--h-kit-pad-y, 18px) + 2px) calc(var(--h-kit-pad, 22px) + 2px) calc(var(--h-kit-head-pb, 12px) + 2px); }
.eyebrow { font-size:11px; letter-spacing:.14em; text-transform:uppercase; color:rgb(var(--h-text-3)); font-weight:600; }
h2 { margin:4px 0 0; font-size:var(--h-kit-title-size, 20px); font-weight:600; letter-spacing:-.01em; }
.sub { margin-top:4px; font-size:13px; color:rgb(var(--h-text-2)); display:flex; align-items:center; gap:6px; }
.lock { width:12px; height:12px; }
.stats { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
.stat { display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px; font-size:12px; font-weight:600;
  background:rgb(var(--h-surface-2)); border:1px solid rgb(var(--h-hairline)); white-space:nowrap; }
.stat.ok { background:rgb(var(--h-status-success-soft)); color:rgb(var(--h-status-success)); border-color:transparent; }
.stat.warn { background:rgb(var(--h-status-warning-soft)); color:rgb(var(--h-status-warning)); border-color:transparent; }
.stat.bad { background:rgb(var(--h-status-danger-soft)); color:rgb(var(--h-status-danger)); border-color:transparent; }
.btn { display:inline-flex; align-items:center; gap:6px; padding:6px 12px; border-radius:999px; font-size:12px; font-weight:600; cursor:pointer;
  background:rgb(var(--h-text)); color:rgb(var(--h-surface)); border:0; }
.btn:hover { opacity:.88; }
.btn svg, .stat svg { width:13px; height:13px; }
:focus-visible { outline:2px solid rgb(var(--h-brand)); outline-offset:2px; border-radius:6px; }

.overview { padding:6px calc(var(--h-kit-pad, 22px) + 2px) var(--h-kit-pad-y, 18px); }
.axis-row { display:grid; grid-template-columns:104px 1fr; align-items:center; gap:12px; }
.lane-label { font-size:11px; font-weight:600; line-height:1.2; color:rgb(var(--h-text-2)); text-align:right; overflow:hidden; overflow-wrap:anywhere;
  display:-webkit-box; -webkit-box-orient:vertical; -webkit-line-clamp:2; line-clamp:2; }
@media (max-width: 480px) { .axis-row { grid-template-columns:76px 1fr; gap:8px; } }
.track { position:relative; height:26px; }
.ribbon { position:relative; height:30px; border-radius:8px; overflow:hidden; background:rgb(var(--h-surface-2)); }
.seg { position:absolute; top:0; bottom:0; display:flex; align-items:center; padding:0 8px; font-size:11px; font-weight:600;
  color:rgb(var(--h-surface)); white-space:nowrap; overflow:hidden; border-right:2px solid rgb(var(--h-surface)); }
.seg span { overflow:hidden; text-overflow:clip; }
.seg span[hidden] { visibility:hidden; }
@media (max-width: 480px) {
  .ribbon, .track:has(.ribbon) { height:40px !important; }
  .seg { white-space:normal; padding:0 5px; font-size:10px; line-height:1.15; }
  .seg span { display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow-wrap:normal; }
}
.lane-line { position:absolute; left:0; right:0; top:50%; height:1px; background:rgb(var(--h-hairline)); }
.dot { position:absolute; top:50%; width:12px; height:12px; margin:-6px 0 0 -6px; border-radius:999px; border:2px solid rgb(var(--h-surface));
  cursor:pointer; padding:0; box-shadow:0 0 0 1px rgb(var(--h-text) / .08); transition:transform .15s ease; }
.dot::before { content:""; position:absolute; inset:-8px; border-radius:999px; }
.dot:hover, .dot:focus-visible { transform:scale(1.45); z-index:2; }
.marker { position:absolute; top:-4px; bottom:-4px; width:0; border-left:1.5px dashed rgb(var(--h-text-3)); pointer-events:none; }
.marker.due { border-left:2px solid rgb(var(--h-status-danger)); }
.marker-tag { position:absolute; top:calc(-20px - var(--row, 0) * 22px); transform:translateX(-50%); max-width:46vw; overflow:hidden; text-overflow:ellipsis; font-size:10px; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
  padding:2px 6px; border-radius:4px; white-space:nowrap; background:rgb(var(--h-surface-2)); color:rgb(var(--h-text-2)); }
.marker.due .marker-tag { background:rgb(var(--h-status-danger)); color:rgb(var(--h-surface)); }
.marker-tag[data-align="start"] { transform:none; left:-1px; }
.marker-tag[data-align="end"] { transform:none; left:auto; right:-1px; }
.markers { position:absolute; inset:0; pointer-events:none; }
.overview.stagger { padding-top:30px; }
.dwell-row { margin-top:12px; }
.dwell { display:flex; flex-wrap:wrap; gap:6px; }
.dw { display:inline-flex; align-items:center; gap:6px; padding:3px 9px; border-radius:999px; font-size:11.5px; color:rgb(var(--h-text-2)); background:rgb(var(--h-surface-2)); }
.dw b { color:rgb(var(--h-text)); font-weight:600; }
.dw .sw { width:7px; height:7px; border-radius:999px; }
.ticks { position:relative; height:18px; margin-top:6px; }
.tick { position:absolute; transform:translateX(-50%); font-size:10px; color:rgb(var(--h-text-3)); font-variant-numeric:tabular-nums; white-space:nowrap; }
.lanes { position:relative; margin-top:10px; }
.lanes-inner { display:grid; gap:2px; }
.ov-wrap { position:relative; padding-top:22px; }

.filters { display:flex; flex-wrap:wrap; gap:var(--h-kit-gap-sm, 6px); padding:var(--h-kit-gap, 12px) calc(var(--h-kit-pad, 22px) + 2px); border-top:1px solid rgb(var(--h-hairline)); border-bottom:1px solid rgb(var(--h-hairline));
  background:rgb(var(--h-surface-2) / .6); }
.chip { display:inline-flex; align-items:center; gap:7px; padding:5px 11px; border-radius:999px; font-size:12px; font-weight:600; cursor:pointer;
  border:1px solid rgb(var(--h-hairline-2)); background:rgb(var(--h-surface)); color:rgb(var(--h-text-2)); transition:all .15s ease; }
.chip:hover { border-color:rgb(var(--h-text-3)); color:rgb(var(--h-text)); }
.chip[aria-pressed="true"] { background:rgb(var(--h-text)); color:rgb(var(--h-surface)); border-color:transparent; }
.chip .sw { width:8px; height:8px; border-radius:999px; }
.chip .n { font-variant-numeric:tabular-nums; opacity:.7; font-weight:500; }

.gaps { margin:16px 24px 0; padding:12px 14px; border-radius:12px; font-size:13px; display:flex; gap:10px; align-items:flex-start; }
.gaps.warn { background:rgb(var(--h-status-warning-soft)); color:rgb(var(--h-text)); border:1px dashed rgb(var(--h-status-warning)); }
.gaps.ok { background:rgb(var(--h-status-success-soft)); color:rgb(var(--h-text)); }
.gaps svg { width:18px; height:18px; flex:none; margin-top:1px; }
.gaps ul { margin:4px 0 0; padding-left:18px; color:rgb(var(--h-text-2)); }
.gaps b { font-weight:600; }

.ledger { padding:8px calc(var(--h-kit-pad, 22px) + 2px) 8px; }
.day { display:grid; grid-template-columns:104px 1fr; gap:12px; }
.day-label { position:sticky; top:8px; align-self:start; padding-top:18px; text-align:right; }
.day-label .d { font-size:13px; font-weight:600; white-space:nowrap; }
.day-label .r { font-size:11px; color:rgb(var(--h-text-3)); margin-top:2px; }
.rail { position:relative; padding:12px 0 12px 28px; }
.rail::before { content:""; position:absolute; left:9px; top:0; bottom:0; width:2px; background:rgb(var(--h-hairline)); }
.gapline { display:grid; grid-template-columns:104px 1fr; gap:12px; }
.gapline .rail { padding:2px 0 2px 28px; }
.gapline .rail::before { background:repeating-linear-gradient(to bottom, rgb(var(--h-hairline-2)) 0 4px, transparent 4px 8px); }
.elapsed { display:inline-block; font-size:11px; color:rgb(var(--h-text-3)); padding:2px 8px; border-radius:999px; background:rgb(var(--h-surface-2)); }
.moment { position:relative; margin:6px 0; padding:var(--h-kit-gap, 12px) var(--h-kit-row-px, 14px); border-radius:12px; border:1px solid rgb(var(--h-hairline)); background:rgb(var(--h-surface));
  transition:box-shadow .2s ease, border-color .2s ease, transform .2s ease; animation:rise .35s ease both; }
.moment:hover { border-color:rgb(var(--h-hairline-2)); box-shadow:0 6px 18px -12px rgb(var(--h-text) / .35); }
.moment.flash { box-shadow:0 0 0 3px rgb(var(--h-brand) / .35); }
.node { position:absolute; left:-27px; top:14px; width:18px; height:18px; border-radius:999px; border:3px solid rgb(var(--h-surface));
  box-shadow:0 0 0 1px rgb(var(--h-hairline-2)); }
.mhead { display:flex; justify-content:space-between; gap:12px; align-items:baseline; }
.mtitle { font-size:14px; font-weight:600; line-height:1.35; }
.detail { display:block; flex-basis:100%; font-size:13px; color:rgb(var(--h-text-2)); line-height:1.4; }
.mtime { font-size:11px; color:rgb(var(--h-text-3)); font-variant-numeric:tabular-nums; white-space:nowrap; }
.row { display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin-top:8px; font-size:13px; color:rgb(var(--h-text-2)); }
.tag { display:inline-flex; align-items:center; gap:5px; font-size:10.5px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; }
.tag .sw { width:7px; height:7px; border-radius:999px; }
.pill { display:inline-flex; align-items:center; padding:2px 9px; border-radius:999px; font-size:12px; font-weight:600; }
.arrow { color:rgb(var(--h-text-3)); font-size:12px; }
.who { display:inline-flex; align-items:center; gap:6px; font-size:12px; color:rgb(var(--h-text-2)); }
.av { width:20px; height:20px; border-radius:999px; display:inline-grid; place-items:center; font-size:9px; font-weight:700;
  background:rgb(var(--h-text) / .08); color:rgb(var(--h-text)); }
.role { font-size:10px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; color:rgb(var(--h-text-3)); }
.src { margin-left:auto; font-size:12px; font-weight:600; color:rgb(var(--h-text-link)); background:none; border:0; cursor:pointer; padding:0; opacity:0; transition:opacity .15s ease; }
.moment:hover .src, .src:focus-visible { opacity:1; }
@media (hover: none) { .src { opacity:1; } }
.src:hover { text-decoration:underline; }
.sep { height:1px; background:rgb(var(--h-hairline)); margin:10px 0 0; }
footer { display:flex; flex-wrap:wrap; gap:6px 16px; padding:14px 24px 18px; font-size:11.5px; color:rgb(var(--h-text-3)); border-top:1px solid rgb(var(--h-hairline)); }
footer b { color:rgb(var(--h-text-2)); font-weight:600; }
.empty { padding:32px 24px; text-align:center; color:rgb(var(--h-text-2)); font-size:13px; }
@keyframes rise { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:none; } }
@media (prefers-reduced-motion: reduce) { .moment, .dot, .chip { animation:none; transition:none; } }
@media (max-width: 720px) {
  header, .overview, .ledger, .filters, footer { padding-left:16px; padding-right:16px; }
  .axis-row, .day, .gapline { grid-template-columns:64px 1fr; }
  .gaps { margin-left:16px; margin-right:16px; }
}
`;

const ICON = {
  lock: '<svg class="lock" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></svg>',
  down: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M8 2v8m0 0 3-3m-3 3L5 7M3 13h10"/></svg>',
  check:
    '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><circle cx="10" cy="10" r="8"/><path d="m6.5 10 2.5 2.5 4.5-5"/></svg>',
  alert:
    '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 3 2 17h16L10 3Z"/><path d="M10 8v4m0 2.5v.5"/></svg>',
};

export class HenoyoRecordTimeline extends HTMLElement {
  private _events: HenoyoTimelineEvent[] = [];
  private _gaps: HenoyoTimelineGap[] | null = null;
  private _meta: HenoyoTimelineMeta = {};
  private _active = new Set<string>();
  private _helpText: string | undefined;
  private _source: KitSource | undefined;
  private _asOf: string | undefined;
  private readonly frameId = nextFrameId();
  private readonly _root: ShadowRoot;

  constructor() {
    super();
    this._root = this.attachShadow({ mode: 'open' });
    this._root.addEventListener('click', (e) => this.onClick(e));
    wireFrame(this._root, this);
  }

  set helpText(v: string | undefined) {
    this._helpText = v;
    this.render();
  }
  get helpText(): string | undefined {
    return this._helpText;
  }
  set source(v: KitSource | undefined) {
    this._source = v;
    this.render();
  }
  get source(): KitSource | undefined {
    return this._source;
  }
  set asOf(v: string | undefined) {
    this._asOf = v;
    this.render();
  }
  get asOf(): string | undefined {
    return this._asOf;
  }

  set events(value: HenoyoTimelineEvent[]) {
    this._events = Array.isArray(value) ? value : [];
    this.render();
  }
  get events(): HenoyoTimelineEvent[] {
    return this._events;
  }
  set gaps(value: HenoyoTimelineGap[] | null | undefined) {
    this._gaps = Array.isArray(value) ? value : null;
    this.render();
  }
  get gaps(): HenoyoTimelineGap[] | null {
    return this._gaps;
  }
  set meta(value: HenoyoTimelineMeta) {
    this._meta = value ?? {};
    this.render();
  }
  get meta(): HenoyoTimelineMeta {
    return this._meta;
  }

  connectedCallback(): void {
    this.render();
  }

  private lanes(): HenoyoTimelineLane[] {
    const declared = this._meta.lanes ?? [];
    const kinds = new Set(this.dated().map((e) => e.kind));
    const lanes = declared.filter((l) => kinds.has(l.kind));
    for (const kind of kinds)
      if (!lanes.some((l) => l.kind === kind)) lanes.push({ kind, label: humanize(kind) });
    return lanes;
  }

  private tone(kind: string): string {
    const declared = (this._meta.lanes ?? []).map((l) => l.kind);
    const index = declared.indexOf(kind);
    const order =
      index >= 0
        ? index
        : declared.length + [...new Set(this._events.map((e) => e.kind))].indexOf(kind);
    return LANE_TONES[Math.max(0, order) % LANE_TONES.length] ?? 'brand';
  }

  private dated(): HenoyoTimelineEvent[] {
    return this._events.filter((e) => ms(e.at) !== null);
  }

  private shown(): HenoyoTimelineEvent[] {
    const all = this.dated().sort((a, b) => (ms(b.at) ?? 0) - (ms(a.at) ?? 0));
    return this._active.size === 0 ? all : all.filter((e) => this._active.has(e.kind));
  }

  private onClick(e: Event): void {
    const target = (e.target as HTMLElement | null)?.closest<HTMLElement>('[data-act]');
    if (target === null || target === undefined) return;
    const act = target.dataset['act'];
    const arg = target.dataset['arg'] ?? '';
    if (act === 'filter') {
      if (arg === '') this._active.clear();
      else if (this._active.has(arg)) this._active.delete(arg);
      else this._active.add(arg);
      this.render();
      this.emit('henoyo:timeline-filter', { kinds: [...this._active] });
    } else if (act === 'goto') {
      const card = this._root.getElementById(`m-${arg}`);
      if (card !== null) {
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        card.focus({ preventScroll: true });
        card.classList.add('flash');
        window.setTimeout(() => card.classList.remove('flash'), 1400);
      }
    } else if (act === 'open') {
      const [object, record] = arg.split('|');
      if (object !== undefined && record !== undefined)
        this.emit('henoyo:open-record', { objectApiName: object, recordId: record });
    } else if (act === 'export' && this._meta.exportEnabled !== false) {
      this.exportCsv();
    }
  }

  private emit(type: string, detail: Record<string, unknown>): void {
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
  }

  private exportCsv(): void {
    const quote = (v: string | undefined): string => {
      const raw = v ?? '';
      const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
      return `"${safe.replace(/"/g, '""')}"`;
    };
    const lines = ['time_utc,kind,event,from,to,actor,source'];
    for (const e of this.shown()) {
      lines.push([e.at, e.kind, e.title, e.from, e.to, e.actor, e.id].map(quote).join(','));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `audit-trail-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    this.emit('henoyo:export', {
      format: 'csv',
      rows: this.shown().length,
      kinds: [...this._active],
    });
    URL.revokeObjectURL(a.href);
  }

  private moments(events: HenoyoTimelineEvent[]): Moment[] {
    const out: Moment[] = [];
    for (const e of events) {
      const t = ms(e.at) ?? 0;
      const key = new Date(t).toISOString().slice(0, 16);
      const last = out[out.length - 1];
      if (last !== undefined && last.key === key) last.events.push(e);
      else out.push({ key, t, events: [e] });
    }
    for (const m of out) {
      m.events.sort((a, b) => {
        const pa = PRIORITY.indexOf(a.kind);
        const pb = PRIORITY.indexOf(b.kind);
        return (pa < 0 ? 99 : pa) - (pb < 0 ? 99 : pb);
      });
    }
    return out;
  }

  private overview(now: number): string {
    const dated = this.dated();
    const times = dated.map((e) => ms(e.at) ?? 0);
    const opened = ms(this._meta.openedAt);
    const due = ms(this._meta.dueAt);
    const closed = ms(this._meta.closedAt);
    const start = Math.min(...times, opened ?? Infinity, due ?? Infinity);
    const end = Math.max(...times, closed ?? now, due ?? 0, now);
    const pad = (end - start) * 0.02 || DAY_MS;
    const t0 = start - pad;
    const t1 = end + pad;
    const x = (t: number): number => ((t - t0) / (t1 - t0)) * 100;

    const statuses = dated
      .filter((e) => e.kind === 'status' && e.phase !== false && (e.to ?? '') !== '')
      .sort((a, b) => (ms(a.at) ?? 0) - (ms(b.at) ?? 0));
    const segs: string[] = [];
    const dwell = new Map<string, number>();
    const addDwell = (label: string, from: number, to: number): void => {
      dwell.set(label, (dwell.get(label) ?? 0) + Math.max(0, to - from));
    };
    const current = this._meta.currentStatus;
    const vl = this._meta.valueLabels;
    const noEvents = statuses.length === 0 && current !== undefined && current !== '';
    const firstFrom = statuses[0]?.from;
    const firstAt = statuses[0] !== undefined ? (ms(statuses[0].at) ?? start) : end;
    if (noEvents) {
      const label = humanize(current, vl);
      const a = opened ?? start;
      segs.push(this.seg(x(a), x(closed ?? now), label, statusTone(label)));
      addDwell(label, a, closed ?? now);
    } else if (firstFrom !== undefined || opened !== null) {
      const label = humanize(firstFrom ?? 'open', this._meta.valueLabels);
      segs.push(this.seg(x(opened ?? start), x(firstAt), label, statusTone(label)));
      addDwell(label, opened ?? start, firstAt);
    }
    statuses.forEach((e, i) => {
      const a = ms(e.at) ?? start;
      const next = statuses[i + 1];
      const b = next !== undefined ? (ms(next.at) ?? end) : (closed ?? now);
      const label = humanize(e.to ?? '', this._meta.valueLabels);
      segs.push(this.seg(x(a), x(b), label, statusTone(label)));
      addDwell(label, a, b);
    });
    // Events stop short of the record's current status: the last phase is that status, from the last change.
    const last = statuses[statuses.length - 1];
    if (last !== undefined && current !== undefined && current !== '') {
      const same = (v: string): string => humanize(v, vl).toLowerCase();
      if (same(last.to ?? '') !== same(current)) {
        const a = ms(last.at) ?? start;
        const label = humanize(current, vl);
        segs.push(this.seg(x(a), x(closed ?? now), label, statusTone(label)));
        addDwell(label, a, closed ?? now);
      }
    }

    const lanes = this.lanes()
      .map((lane) => {
        const dots = dated
          .filter((e) => e.kind === lane.kind)
          .map((e) => {
            const t = ms(e.at) ?? 0;
            const key = new Date(t).toISOString().slice(0, 16);
            const tip = `${fmtShort(t)} ${fmtTime(t)} UTC · ${e.title}`;
            return `<button class="dot" style="left:${x(t).toFixed(2)}%;background:rgb(var(--h-${this.tone(lane.kind)}))" data-act="goto" data-arg="${esc(key)}" title="${esc(tip)}" aria-label="${esc(tip)}"></button>`;
          })
          .join('');
        return `<div class="axis-row"><div class="lane-label" title="${esc(lane.label)}">${esc(lane.label)}</div><div class="track"><div class="lane-line"></div>${dots}</div></div>`;
      })
      .join('');

    const ticks: string[] = [];
    const first = new Date(t0);
    const cursor = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth() + 1, 1));
    const months = (t1 - t0) / (DAY_MS * 30);
    const stepMonths = months > 14 ? 3 : months > 7 ? 2 : 1;
    while (cursor.getTime() < t1) {
      const label = cursor.toLocaleDateString(kitLocale(), {
        month: 'short',
        year: cursor.getUTCMonth() === 0 ? '2-digit' : undefined,
        timeZone: kitTimeZone(),
      });
      ticks.push(
        `<div class="tick" style="left:${x(cursor.getTime()).toFixed(2)}%">${esc(label)}</div>`,
      );
      cursor.setUTCMonth(cursor.getUTCMonth() + stepMonths);
    }

    const dwellChips =
      dwell.size > 0
        ? `<div class="axis-row dwell-row"><div class="lane-label">Time in phase</div><div class="dwell">${[
            ...dwell.entries(),
          ]
            .filter(([, d]) => d >= DAY_MS)
            .sort((a, b) => b[1] - a[1])
            .map(
              ([label, d]) =>
                `<span class="dw"><span class="sw" style="background:rgb(var(--h-${statusTone(label)}))"></span>${esc(label)} <b>${esc(span(d / DAY_MS))}</b></span>`,
            )
            .join('')}</div></div>`
        : '';
    const phaseSummary = `Phases: ${[...dwell.entries()].map(([l, d]) => `${l} ${span(d / DAY_MS)}`).join(', ') || 'none recorded'}`;
    const overdue = due !== null && closed === null && now > due;
    const flagItems = [
      { pct: x(now), text: 'Today', due: false },
      ...(due !== null
        ? [
            {
              pct: x(due),
              text: `${overdue ? 'Target missed' : 'Target'} · ${fmtShort(due)}`,
              due: true,
            },
          ]
        : []),
    ];
    // ~7px per character plus padding, against an assumed ~560px track.
    const placed = layoutFlags(
      flagItems.map((f) => f.pct),
      flagItems.map((f) => ((f.text.length * 7 + 14) / 560) * 100),
    );
    const staggered = placed.some((p) => p.row > 0);
    const markers = flagItems
      .map((f, i) => {
        const p = placed[i] ?? { align: 'center', row: 0 };
        return `<div class="marker${f.due ? ' due' : ''}" style="left:${f.pct.toFixed(2)}%"><span class="marker-tag" data-align="${p.align}" style="--row:${p.row}" title="${esc(f.text)}">${esc(f.text)}</span></div>`;
      })
      .join('');

    return `<div class="overview${staggered ? ' stagger' : ''}">
      <div class="ov-wrap">
        <div class="axis-row"><div class="lane-label">Phase</div><div class="track" style="height:30px"><div class="ribbon" role="img" aria-label="${esc(phaseSummary)}">${segs.length > 0 ? segs.join('') : '<div class="seg" style="left:0;width:100%;background:rgb(var(--h-status-neutral))"><span>No status changes recorded</span></div>'}</div><div class="markers">${markers}</div></div></div>
        <div class="lanes"><div class="lanes-inner">${lanes}</div></div>
        <div class="axis-row"><div></div><div class="ticks">${ticks.join('')}</div></div>
        ${dwellChips}
      </div>
    </div>`;
  }

  private seg(a: number, b: number, label: string, tone: string): string {
    const width = Math.max(0, b - a);
    if (width <= 0) return '';
    const abbr = phaseAbbreviation(label);
    const text = `<span data-abbr="${esc(abbr)}">${esc(label)}</span>`;
    return `<div class="seg" style="left:${a.toFixed(2)}%;width:${width.toFixed(2)}%;background:rgb(var(--h-${tone}))" title="${esc(label)}">${text}</div>`;
  }

  private momentCard(m: Moment): string {
    const primary = m.events[0];
    if (primary === undefined) return '';
    const shownTransitions = new Set<string>();
    const rows = m.events
      .map((e, i) => {
        const tone = this.tone(e.kind);
        const lane = (this._meta.lanes ?? []).find((l) => l.kind === e.kind);
        const vl = this._meta.valueLabels;
        const fromTxt = e.from !== undefined && e.from !== '' ? humanize(e.from, vl) : '';
        const toTxt = e.to !== undefined && e.to !== '' ? humanize(e.to, vl) : '';
        const sig = `${fromTxt}\u0000${toTxt}`;
        const refused = REFUSAL.test(e.title) && toTxt !== '';
        const transition = refused
          ? `<span class="pill" style="background:rgb(var(--h-${statusTone(toTxt)}) / .14);color:rgb(var(--h-text))">Stays ${esc(toTxt)}</span>`
          : toTxt !== ''
            ? `${fromTxt !== '' ? `<span class="pill" style="background:rgb(var(--h-${statusTone(fromTxt)}) / .14);color:rgb(var(--h-text))">${esc(fromTxt)}</span><span class="arrow">→</span>` : ''}<span class="pill" style="background:rgb(var(--h-${statusTone(toTxt)}));color:rgb(var(--h-surface))">${esc(toTxt)}</span>`
            : '';
        // The same change recorded twice in one card (a refused sign-off and its status event) shows once.
        if (i > 0 && toTxt !== '' && shownTransitions.has(sig)) return '';
        if (toTxt !== '' && !refused) shownTransitions.add(sig);
        const who =
          e.actor !== undefined && e.actor !== ''
            ? `<span class="who"><span class="av">${esc(initials(e.actor))}</span>${lane?.role !== undefined ? `<span class="role">${esc(lane.role)}</span>` : ''}${esc(e.actor)}</span>`
            : `<span class="who"><span class="av">⚙</span>System</span>`;
        const source = sourceOf(e.id);
        const link =
          source !== null
            ? `<button class="src" data-act="open" data-arg="${esc(`${source.object}|${source.record}`)}">Open record ↗</button>`
            : '';
        const label = lane?.label ?? humanize(e.kind);
        const redundant =
          i === 0 ||
          (transition !== '' &&
            humanize(e.to ?? '', vl).toLowerCase() === e.title.trim().toLowerCase());
        const parts = eventTitleParts(e.title, e.from, e.to, vl, e.field, this._meta.phaseValues);
        const title = redundant
          ? ''
          : `<span>${esc(parts.title)}</span>${parts.detail !== undefined ? `<span class="detail">${esc(parts.detail)}</span>` : ''}`;
        return `${i > 0 ? '<div class="sep"></div>' : ''}<div class="row"><span class="tag" style="color:rgb(var(--h-${tone}))"><span class="sw" style="background:rgb(var(--h-${tone}))"></span>${esc(label)}</span>${title}${transition}${who}${link}</div>`;
      })
      .join('');
    const headParts = eventTitleParts(
      primary.title,
      primary.from,
      primary.to,
      this._meta.valueLabels,
      primary.field,
      this._meta.phaseValues,
    );
    return `<article class="moment" tabindex="-1" id="m-${esc(m.key)}" aria-label="${esc(`${fmtDay(m.t)} ${fmtTime(m.t)} UTC: ${primary.title}`)}">
      <span class="node" style="background:rgb(var(--h-${this.tone(primary.kind)}))"></span>
      <div class="mhead"><div class="mtitle">${esc(primary.title ? headParts.title : humanize(primary.kind))}</div><div class="mtime">${fmtTime(m.t)} UTC</div></div>${primary.title && headParts.detail !== undefined ? `<div class="detail">${esc(headParts.detail)}</div>` : ''}
      ${rows}
    </article>`;
  }

  private _queued = false;

  private render(): void {
    if (this._queued) return;
    this._queued = true;
    queueMicrotask(() => {
      this._queued = false;
      this.paint();
    });
  }

  private paint(): void {
    if (!this.isConnected) return;
    const now = Date.now();
    const dated = this.dated();
    const shown = this.shown();
    const subject = this._meta.subject ?? 'this record';
    const gaps = this._gaps ?? [];
    const gapsConfigured = this._gaps !== null;

    if (dated.length === 0) {
      const undatedGaps =
        gaps.length > 0
          ? `<div class="gaps warn" role="status">${ICON.alert}<div><b>${gaps.length} integrity ${gaps.length === 1 ? 'check needs' : 'checks need'} attention</b><ul>${gaps
              .map((g) => `<li>${esc(g.label)}</li>`)
              .join('')}</ul></div></div>`
          : '';
      this._root.innerHTML = `<style>${STYLE}</style><section class="card" aria-label="Audit trail">${undatedGaps}<div class="empty">No dated history recorded for ${esc(subject)} yet.</div></section>`;
      return;
    }

    const counts = new Map<string, number>();
    for (const e of dated) counts.set(e.kind, (counts.get(e.kind) ?? 0) + 1);
    const chips = [
      `<button class="chip" data-act="filter" data-arg="" aria-pressed="${this._active.size === 0}">All <span class="n">${dated.length}</span></button>`,
      ...this.lanes().map(
        (l) =>
          `<button class="chip" data-act="filter" data-arg="${esc(l.kind)}" aria-pressed="${this._active.has(l.kind)}"><span class="sw" style="background:rgb(var(--h-${this.tone(l.kind)}))"></span>${esc(l.label)} <span class="n">${counts.get(l.kind) ?? 0}</span></button>`,
      ),
    ].join('');

    const moments = this.moments(shown);
    const byDay: { day: string; t: number; moments: Moment[] }[] = [];
    for (const m of moments) {
      const day = m.key.slice(0, 10);
      const last = byDay[byDay.length - 1];
      if (last !== undefined && last.day === day) last.moments.push(m);
      else byDay.push({ day, t: m.t, moments: [m] });
    }
    const ledger = byDay
      .map((d, i) => {
        const prev = byDay[i - 1];
        const gap =
          prev !== undefined
            ? `<div class="gapline"><div></div><div class="rail"><span class="elapsed">${esc(span((prev.t - d.t) / DAY_MS))} earlier</span></div></div>`
            : '';
        return `${gap}<div class="day"><div class="day-label"><div class="d">${esc(fmtDay(d.t))}</div><div class="r">${esc(fmtWeekday(d.t))} · ${esc(relative(d.t, now))}</div></div><div class="rail">${d.moments.map((m) => this.momentCard(m)).join('')}</div></div>`;
      })
      .join('');

    const due = ms(this._meta.dueAt);
    const closed = ms(this._meta.closedAt);
    const overdueDays =
      due !== null && closed === null && now > due ? Math.floor((now - due) / DAY_MS) : 0;
    const gapsBlock = !gapsConfigured
      ? ''
      : gaps.length > 0
        ? `<div class="gaps warn" role="status">${ICON.alert}<div><b>${gaps.length} integrity ${gaps.length === 1 ? 'check needs' : 'checks need'} attention</b><ul>${gaps
            .slice(0, 4)
            .map((g) => `<li>${esc(g.label)}</li>`)
            .join('')}${gaps.length > 4 ? `<li>${gaps.length - 4} more</li>` : ''}</ul></div></div>`
        : `<div class="gaps ok" role="status">${ICON.check}<div><b>No gaps found by the configured checks.</b></div></div>`;

    const times = dated.map((e) => ms(e.at) ?? 0);
    const firstT = Math.min(...times);
    const lastT = Math.max(...times);
    const sources = new Set(dated.map((e) => e.id.split(':')[0]));

    this._root.innerHTML = `<style>${STYLE}</style>
    <section class="card" aria-label="Audit trail for ${esc(subject)}">
      <header>
        <div>
          <div class="eyebrow">Audit trail</div>
          <div class="titlerow"><h2>${dated.length} ${dated.length === 1 ? 'event' : 'events'} · last ${esc(relative(lastT, now))}</h2>${helpMarkup(this.frameId, this._helpText)}</div>
          <div class="sub">${ICON.lock} Read-only. Recorded by the platform as each change happened.</div>
        </div>
        <div class="stats">
          ${overdueDays > 0 ? `<span class="stat bad">Target missed by ${overdueDays} days</span>` : ''}
          ${!gapsConfigured ? '' : gaps.length > 0 ? `<span class="stat warn">${ICON.alert}${gaps.length} gap${gaps.length === 1 ? '' : 's'}</span>` : `<span class="stat ok">${ICON.check}No gaps</span>`}
          ${this._meta.exportEnabled === false ? '' : `<button class="btn" data-act="export" title="Download the events shown below as CSV">${ICON.down}Export</button>`}
        </div>
      </header>
      ${this.overview(now)}
      <div class="filters" role="toolbar" aria-label="Filter events">${chips}</div>
      ${gapsBlock}
      <div class="ledger">${ledger || '<div class="empty">No events match this filter.</div>'}</div>
      <footer>
        <span><b>${shown.length}</b> of ${dated.length} events shown</span>
        <span>From <b>${sources.size}</b> record types</span>
        <span>First <b>${esc(fmtShort(firstT))}</b> · last <b>${esc(fmtShort(lastT))}</b></span>
        <span>Times in UTC</span>
        ${this._meta.exportEnabled === false ? '<span>Export is turned off by your organisation</span>' : '<span>Export contains exactly the events shown</span>'}
        ${sourceMarkup(this._source, this._asOf)}
      </footer>
    </section>`;
    this.hideClippedPhaseLabels();
  }

  /** A phase label that cannot show in full is hidden, never cut to "Op…"; the title tooltip and the legend keep it. */
  private hideClippedPhaseLabels(): void {
    const clipped = (el: HTMLElement): boolean =>
      el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1;
    for (const span of this._root.querySelectorAll<HTMLElement>('.seg > span')) {
      if (!clipped(span)) continue;
      // Full label does not fit: show the abbreviation (the title tooltip keeps the full name).
      const abbr = span.dataset.abbr ?? '';
      if (abbr !== '') {
        span.textContent = abbr;
        if (!clipped(span)) continue;
      }
      span.setAttribute('hidden', '');
    }
  }
}

if (
  typeof customElements !== 'undefined' &&
  customElements.get('henoyo-record-timeline') === undefined
) {
  customElements.define('henoyo-record-timeline', HenoyoRecordTimeline);
}

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-record-timeline': HenoyoRecordTimeline;
  }
}
