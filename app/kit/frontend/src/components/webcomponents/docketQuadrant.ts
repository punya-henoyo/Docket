// <docket-quadrant>: the posture map. Every assessed application is one dot on a two-by-two:
// how current its required checks are (left to right) against how few problems are proven
// open (bottom to top). Top right is "checks current, nothing proven", which is never a
// promise of safety. The element plots what it is given. It never derives a quadrant, a
// rank or a number: the server decides `cell`, the notes and the movement; this draws them.
// No score, no percentage, no coordinates on the screen. Colour never stands alone: every
// level has a word in the tooltip, the legend and the list.
//
// Data shape: `posture` in docs/ui/policy-and-posture.md section 4.

import { HenoyoElement, defineElement, emit, esc, legend, type KitStat } from './henoyoKit';
import { watchWidth } from './vizPalette';
import { DOCKET_STYLE, LEVEL_WORD, type Level } from './docketKit';

export type QuadCell = 'tl' | 'tr' | 'bl' | 'br';
export type QuadDirection = 'up' | 'down' | 'steady';

export interface QuadTrailPoint {
  at: string;
  assurance: number;
  standing: number;
  /** Optional: the quadrant at that date. Without it a past dot's tooltip omits the quadrant. */
  cell?: QuadCell;
  level?: Level;
  assurance_note?: string;
  standing_note?: string;
}

export interface QuadMoved {
  assurance: QuadDirection;
  standing: QuadDirection;
}

export interface QuadPoint {
  id: string;
  label: string;
  tier?: string;
  category?: string | null;
  exposure?: string | null;
  /** Policy id. */
  policy?: string | null;
  policy_name?: string | null;
  level: Level;
  /** 0..100, x. Places the dot inside its half; never shown. */
  assurance: number;
  /** 0..100, y. Never shown. */
  standing: number;
  cell: QuadCell;
  days_in_cell?: number | null;
  assurance_note?: string;
  standing_note?: string;
  /** Oldest first. Null entries (not yet assessed) are skipped, never drawn as 0. */
  trail?: (QuadTrailPoint | null)[];
  moved?: QuadMoved | 'new' | null;
  /** "since 5 Oct" date, when the server says which snapshot it compared with. Else the snapshot 14 days before the latest. */
  moved_since?: string;
}

export interface QuadUnassessed {
  id: string;
  label: string;
  tier?: string;
  category?: string | null;
  exposure?: string | null;
  reason?: string;
}

export interface QuadQuadrant {
  key: QuadCell;
  title: string;
  note: string;
}

export interface QuadSnapshotCount {
  at: string;
  tl: number;
  tr: number;
  bl: number;
  br: number;
  unassessed?: number;
}

type PolicyOption = string | { id: string; name?: string };

const DEFAULT_QUADRANTS: QuadQuadrant[] = [
  { key: 'tl', title: 'Checks overdue, nothing proven', note: 'Quiet is not safe: a required check is missing or stale.' },
  { key: 'tr', title: 'Checks current, nothing proven', note: 'Required checks are current and no proven problem is open. That is not a promise of safety.' },
  { key: 'bl', title: 'Checks overdue, problems proven', note: 'Proven problems and gaps in coverage. Look here first.' },
  { key: 'br', title: 'Checks current, problems proven', note: 'The risk is real and well evidenced. Fix it.' },
];

const DEFAULT_HELP =
  'Position is not a grade: it shows how current the required checks are and whether a problem is proven or confirmed. Quiet is not safe, and compliance results are not an input.';

const DEFAULT_NOTE_PAST = "Past positions use today's policy";
const CELL_ORDER: QuadCell[] = ['bl', 'br', 'tl', 'tr'];
const LEVEL_RANK: Record<Level, number> = { action: 0, attention: 1, clear: 2, unknown: 3 };
const SNAP_GAP_DAYS = 14;
const DAY = 86_400_000;

// Plot geometry. Margins leave room for the axes; PAD_Y reserves a band at the top and bottom
// of the plot for the corner titles, so a dot never sits under one.
const M = { l: 44, r: 12, t: 8, b: 50 };
const MIN_PLOT_H = 520;
const CLUSTER_PX = 9;

interface Shown {
  p: QuadPoint;
  a: number;
  s: number;
  cell: QuadCell | undefined;
  level: Level;
  past: QuadTrailPoint | null;
}

interface Placed {
  key: string;
  members: Shown[];
  x: number;
  y: number;
  r: number;
  level: Level;
  cell: QuadCell | undefined;
  dim: boolean;
  always: boolean;
  label: { text: string; mode: 'right' | 'left' | 'above' | 'below'; w: number } | null;
}

interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface Geo {
  W: number;
  H: number;
  pw: number;
  ph: number;
  padY: number;
  X: (a: number) => number;
  Y: (s: number) => number;
}

interface SortState {
  key: string;
  dir: 'asc' | 'desc';
}

const clamp = (n: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, n));
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

function tierNumber(tier: string | undefined): number | null {
  const m = /(\d)/.exec(tier ?? '');
  return m ? Number(m[1]) : null;
}

function tierRadius(tier: string | undefined): number {
  const n = tierNumber(tier);
  return n === 1 ? 12 : n === 2 ? 9 : n === 3 ? 6.5 : 8;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function shortDate(iso: string | undefined): string {
  if (iso === undefined || iso === '') return '';
  const t = Date.parse(iso.length === 10 ? `${iso}T00:00:00Z` : iso);
  if (Number.isNaN(t)) return iso;
  const d = new Date(t);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}

function dayMs(iso: string): number {
  const t = Date.parse(iso.length === 10 ? `${iso}T00:00:00Z` : iso);
  return Number.isNaN(t) ? 0 : t;
}

function overlap(a: Rect, b: Rect, pad = 2): boolean {
  return a.x < b.x + b.w + pad && a.x + a.w + pad > b.x && a.y < b.y + b.h + pad && a.y + a.h + pad > b.y;
}

const ASSURANCE_WORD: Record<QuadDirection, string> = {
  down: 'Required checks slipping',
  up: 'Required checks catching up',
  steady: 'Required checks steady',
};
const STANDING_WORD: Record<QuadDirection, string> = {
  down: 'more problems proven',
  up: 'fewer problems proven',
  steady: 'proven problems steady',
};

/** Movement worded per axis, never summed. */
export function movementWords(moved: QuadPoint['moved'], since?: string): string {
  if (moved === 'new') return 'New on the map';
  if (moved === null || moved === undefined) return '';
  const tail = since ? ` since ${since}` : '';
  if (moved.assurance === 'steady' && moved.standing === 'steady') return `Steady${tail}`;
  return `${ASSURANCE_WORD[moved.assurance]}, ${STANDING_WORD[moved.standing]}${tail}`;
}

const SHORT_A: Record<QuadDirection, string> = { down: 'Checks slipping', up: 'Checks catching up', steady: 'Checks steady' };
const SHORT_S: Record<QuadDirection, string> = { down: 'more proven', up: 'fewer proven', steady: 'proven steady' };

/** The same movement in fewer words, for a narrow table column. Two lines, one per axis. */
function movementShort(moved: QuadPoint['moved']): string {
  if (moved === 'new') return 'New';
  if (!moved) return '';
  if (moved.assurance === 'steady' && moved.standing === 'steady') return 'Steady';
  return `${esc(SHORT_A[moved.assurance])}<br>${esc(SHORT_S[moved.standing])}`;
}

function movedRank(m: QuadPoint['moved']): number {
  if (m === 'new') return 0.5;
  if (!m) return 0.25;
  const f = (d: QuadDirection): number => (d === 'down' ? -1 : d === 'up' ? 1 : 0);
  return f(m.assurance) + f(m.standing);
}

const SVG_CHEVRON =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' fill='none' stroke='%235A625B' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E\")";

export class DocketQuadrant extends HenoyoElement {
  private _heading = 'Posture map';
  private _points: QuadPoint[] = [];
  private _unassessed: QuadUnassessed[] = [];
  private _quadrants: QuadQuadrant[] = DEFAULT_QUADRANTS;
  private _snapshots: string[] = [];
  private _bySnapshot: QuadSnapshotCount[] = [];
  private _asOfNote = '';
  private _policiesOverride: PolicyOption[] | null = null;
  private _categoriesOverride: string[] | null = null;
  private _exposuresOverride: string[] | null = null;

  // View state. Lives in fields so a re-render (resize, data) keeps the person's place.
  private showMovement = false;
  private mode: 'map' | 'list' = 'map';
  private snap = -1; // -1 = latest
  private filters = { category: '', exposure: '', policy: '' };
  private sort: SortState = { key: 'cell', dir: 'asc' };

  private geo: Geo | null = null;
  private placed: Placed[] = [];
  private prevPos = new Map<string, { x: number; y: number }>();
  private animateNext = false;
  private pendingFocus: string | null = null;

  constructor() {
    super();
    watchWidth(this, () => this.refresh());
    const r = this.root;
    r.addEventListener('click', (e) => this.onClick(e));
    r.addEventListener('change', (e) => this.onChange(e));
    r.addEventListener('pointerover', (e) => this.onOver(e));
    r.addEventListener('pointerout', (e) => this.onOut(e));
    r.addEventListener('focusin', (e) => this.onOver(e));
    r.addEventListener('focusout', (e) => this.onOut(e));
    r.addEventListener('keydown', (e) => this.onKey(e as KeyboardEvent));
    this.helpText = DEFAULT_HELP;
  }

  private readonly onDocClick = (e: Event): void => {
    const pop = this.root.querySelector('.pop');
    if (!pop) return;
    // The click that opened the popover is still bubbling: a dot click never closes it here.
    if (e.composedPath().some((n) => n === pop || (n instanceof HTMLElement && n.classList.contains('dot')))) return;
    this.closePop(false);
  };

  override connectedCallback(): void {
    super.connectedCallback();
    document.addEventListener('click', this.onDocClick);
  }

  disconnectedCallback(): void {
    document.removeEventListener('click', this.onDocClick);
  }

  // ---- properties ---------------------------------------------------------------
  get heading(): string {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v && v.trim() !== '' ? v : 'Posture map';
    this.invalidate();
  }
  get points(): QuadPoint[] {
    return this._points;
  }
  set points(v: QuadPoint[] | undefined) {
    this._points = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get unassessed(): QuadUnassessed[] {
    return this._unassessed;
  }
  set unassessed(v: QuadUnassessed[] | undefined) {
    this._unassessed = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get quadrants(): QuadQuadrant[] {
    return this._quadrants;
  }
  set quadrants(v: QuadQuadrant[] | undefined) {
    this._quadrants = Array.isArray(v) && v.length === 4 ? v : DEFAULT_QUADRANTS;
    this.invalidate();
  }
  get snapshots(): string[] {
    return this._snapshots;
  }
  set snapshots(v: string[] | undefined) {
    this._snapshots = Array.isArray(v) ? v : [];
    this.snap = -1;
    this.invalidate();
  }
  get bySnapshot(): QuadSnapshotCount[] {
    return this._bySnapshot;
  }
  set bySnapshot(v: QuadSnapshotCount[] | undefined) {
    this._bySnapshot = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get asOfNote(): string {
    return this._asOfNote;
  }
  set asOfNote(v: string | undefined) {
    this._asOfNote = v ?? '';
    this.invalidate();
  }
  /** Filter options. Derived from the points unless set. */
  get policies(): { id: string; name: string }[] {
    if (this._policiesOverride)
      return this._policiesOverride.map((o) => (typeof o === 'string' ? { id: o, name: o } : { id: o.id, name: o.name ?? o.id }));
    const seen = new Map<string, string>();
    for (const p of this._points) if (p.policy) seen.set(p.policy, p.policy_name ?? p.policy);
    return [...seen].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name));
  }
  set policies(v: PolicyOption[] | undefined) {
    this._policiesOverride = Array.isArray(v) ? v : null;
    this.invalidate();
  }
  get categories(): string[] {
    return this._categoriesOverride ?? this.distinct((p) => p.category);
  }
  set categories(v: string[] | undefined) {
    this._categoriesOverride = Array.isArray(v) ? v : null;
    this.invalidate();
  }
  get exposures(): string[] {
    return this._exposuresOverride ?? this.distinct((p) => p.exposure);
  }
  set exposures(v: string[] | undefined) {
    this._exposuresOverride = Array.isArray(v) ? v : null;
    this.invalidate();
  }

  private distinct(pick: (p: QuadPoint) => string | null | undefined): string[] {
    return [...new Set(this._points.map(pick).filter((x): x is string => !!x))].sort();
  }

  // ---- state -----------------------------------------------------------------------
  private refresh(animate = false): void {
    const ae = this.root.activeElement as HTMLElement | null;
    this.pendingFocus = ae?.dataset['fk'] ?? null;
    this.animateNext = animate;
    this.prevPos = new Map(this.placed.map((p) => [p.key, { x: p.x, y: p.y }]));
    this.invalidate();
  }

  private get snapIndex(): number {
    const n = this._snapshots.length;
    return this.snap < 0 || this.snap >= n ? n - 1 : this.snap;
  }
  private get isLatest(): boolean {
    return this._snapshots.length === 0 || this.snapIndex === this._snapshots.length - 1;
  }
  private quad(key: QuadCell | undefined): QuadQuadrant | undefined {
    return key === undefined ? undefined : this._quadrants.find((q) => q.key === key);
  }
  private filterActive(): boolean {
    return this.filters.category !== '' || this.filters.exposure !== '' || this.filters.policy !== '';
  }
  private passes(p: { category?: string | null; exposure?: string | null; policy?: string | null }): boolean {
    const f = this.filters;
    return (
      (f.category === '' || p.category === f.category) &&
      (f.exposure === '' || p.exposure === f.exposure) &&
      (f.policy === '' || p.policy === f.policy)
    );
  }
  private sinceFor(p: QuadPoint): string {
    if (p.moved_since) return shortDate(p.moved_since);
    const snaps = this._snapshots;
    const last = snaps[snaps.length - 1];
    if (last === undefined) return '';
    const limit = dayMs(last) - SNAP_GAP_DAYS * DAY;
    for (let i = snaps.length - 1; i >= 0; i -= 1) if (dayMs(snaps[i]!) <= limit) return shortDate(snaps[i]);
    return '';
  }

  // ---- what is shown at the selected snapshot ----------------------------------------
  private shownPoints(): Shown[] {
    const out: Shown[] = [];
    const selected = this._snapshots[this.snapIndex];
    for (const p of this._points) {
      if (this.isLatest) {
        const a = num(p.assurance);
        const s = num(p.standing);
        if (a === null || s === null) continue;
        out.push({ p, a: clamp(a, 0, 100), s: clamp(s, 0, 100), cell: p.cell, level: p.level, past: null });
      } else {
        const t = (p.trail ?? []).find((e) => e !== null && e.at === selected) ?? null;
        if (t === null) continue;
        const a = num(t.assurance);
        const s = num(t.standing);
        if (a === null || s === null) continue;
        out.push({ p, a: clamp(a, 0, 100), s: clamp(s, 0, 100), cell: t.cell, level: t.level ?? p.level, past: t });
      }
    }
    return out;
  }

  // ---- geometry and layout ---------------------------------------------------------
  private computeGeo(): Geo {
    const W = Math.max(300, Math.round((this.clientWidth || 800) - 44));
    const ph = Math.round(clamp(W / 1.45, MIN_PLOT_H, 660));
    const H = ph + M.t + M.b;
    const pw = W - M.l - M.r;
    const padY = W < 520 ? 40 : 62;
    return {
      W,
      H,
      pw,
      ph,
      padY,
      X: (a) => M.l + (a / 100) * pw,
      Y: (s) => M.t + padY + ((100 - s) / 100) * (ph - 2 * padY),
    };
  }

  private cornerRects(g: Geo): Rect[] {
    const noNotes = g.W < 520;
    const w = noNotes ? 150 : Math.min(300, g.pw / 2 - 24);
    const h = noNotes ? 22 : 52;
    return [
      { x: M.l + 12, y: M.t + 10, w, h },
      { x: M.l + g.pw - 12 - w, y: M.t + 10, w, h },
      { x: M.l + 12, y: M.t + g.ph - 10 - h, w, h },
      { x: M.l + g.pw - 12 - w, y: M.t + g.ph - 10 - h, w, h },
    ];
  }

  private place(g: Geo): Placed[] {
    const shown = this.shownPoints();
    const order = [...shown].sort((a, b) => g.Y(a.s) - g.Y(b.s) || g.X(a.a) - g.X(b.a));
    // Cluster dots whose centres are within a few pixels; never across quadrants.
    const clusters: Shown[][] = [];
    for (const s of order) {
      const x = g.X(s.a);
      const y = g.Y(s.s);
      const hit = clusters.find((c) => {
        const f = c[0]!;
        return f.cell === s.cell && Math.hypot(g.X(f.a) - x, g.Y(f.s) - y) < CLUSTER_PX;
      });
      if (hit) hit.push(s);
      else clusters.push([s]);
    }
    const items: Placed[] = clusters.map((members) => {
      const f = members[0]!;
      const worst = members.reduce((w, m) => (LEVEL_RANK[m.level] < LEVEL_RANK[w] ? m.level : w), f.level);
      return {
        key: members.length === 1 ? f.p.id : `c:${members.map((m) => m.p.id).join('+')}`,
        members,
        x: g.X(f.a),
        y: g.Y(f.s),
        r: Math.max(members.length > 1 ? 9 : 0, ...members.map((m) => tierRadius(m.p.tier))),
        level: worst,
        cell: f.cell,
        dim: this.filterActive() && !members.some((m) => this.passes(m.p)),
        always: f.cell === 'bl' || f.cell === 'br',
        label: null,
      };
    });
    // Greedy label placement: always-on labels first (bl, br), each trying right, left, above, below.
    const bounds: Rect = { x: M.l + 2, y: M.t + 2, w: g.pw - 4, h: g.ph - 4 };
    const obstacles = [
      ...this.cornerRects(g),
      ...items.map((i) => ({ x: i.x - i.r - 2, y: i.y - i.r - 2, w: 2 * i.r + 4, h: 2 * i.r + 4 })),
    ];
    const taken: Rect[] = [];
    const sorted = [...items].sort((a, b) => Number(b.always) - Number(a.always));
    for (const it of sorted) {
      const text = it.members.length === 1 ? it.members[0]!.p.label : `${it.members[0]!.p.label} +${it.members.length - 1}`;
      const w = Math.ceil(text.length * 6.7) + 4;
      const h = 17;
      const spots: { mode: 'right' | 'left' | 'above' | 'below'; rect: Rect }[] = [
        { mode: 'right', rect: { x: it.x + it.r + 7, y: it.y - h / 2, w, h } },
        { mode: 'left', rect: { x: it.x - it.r - 7 - w, y: it.y - h / 2, w, h } },
        { mode: 'above', rect: { x: it.x - w / 2, y: it.y - it.r - 6 - h, w, h } },
        { mode: 'below', rect: { x: it.x - w / 2, y: it.y + it.r + 6, w, h } },
      ];
      const inside = (r: Rect): boolean => r.x >= bounds.x && r.x + r.w <= bounds.x + bounds.w && r.y >= bounds.y && r.y + r.h <= bounds.y + bounds.h;
      const free = (r: Rect): boolean => inside(r) && !taken.some((t) => overlap(r, t)) && !obstacles.some((o) => overlap(r, o, 0));
      // Prefer the side with room: near the right edge, try left first.
      const prefer = it.x + it.r + 7 + w > bounds.x + bounds.w ? [1, 0, 2, 3] : [0, 1, 2, 3];
      let chosen = prefer.map((i) => spots[i]!).find((s) => free(s.rect));
      if (!chosen) chosen = prefer.map((i) => spots[i]!).find((s) => inside(s.rect) && !taken.some((t) => overlap(s.rect, t)));
      if (!chosen) chosen = spots[prefer[0]!]!;
      it.label = { text, mode: chosen.mode, w };
      if (it.always) taken.push(chosen.rect);
    }
    // Reading order for the DOM: top row first, then left to right.
    return items.sort((a, b) => Math.round(a.y / 14) - Math.round(b.y / 14) || a.x - b.x);
  }

  // ---- text builders --------------------------------------------------------------------
  private levelWord(l: Level): string {
    return LEVEL_WORD[l].word;
  }

  private daysHere(p: QuadPoint): string {
    const d = p.days_in_cell;
    if (typeof d !== 'number' || !Number.isFinite(d) || d < 1) return '';
    return d >= 28 ? '28+ days here' : `${d} day${d === 1 ? '' : 's'} here`;
  }

  private ariaFor(it: Placed): string {
    if (it.members.length > 1) {
      return `${it.members.length} applications close together: ${it.members.map((m) => m.p.label).join(', ')}. Press Enter to list them.`;
    }
    const m = it.members[0]!;
    const q = this.quad(m.cell);
    const a = m.past?.assurance_note ?? (m.past ? '' : m.p.assurance_note ?? '');
    const s = m.past?.standing_note ?? (m.past ? '' : m.p.standing_note ?? '');
    return [
      `${m.p.label}`,
      m.p.tier ?? '',
      this.levelWord(m.level),
      q ? q.title : '',
      a ? `Required checks: ${a}` : '',
      s ? `Proven problems: ${s}` : '',
    ]
      .filter((x) => x !== '')
      .join('. ');
  }

  private tipHtml(it: Placed): string {
    const row = (m: Shown): string => {
      const p = m.p;
      const q = this.quad(m.cell);
      const a = m.past ? m.past.assurance_note : p.assurance_note;
      const s = m.past ? m.past.standing_note : p.standing_note;
      const meta = [p.tier, p.category, p.exposure].filter((x): x is string => !!x).join(' · ');
      const policy = p.policy_name ?? p.policy;
      let html = `<b class="tn">${esc(p.label)}</b><span class="tl2">${esc(meta)}${meta ? ' · ' : ''}${esc(this.levelWord(m.level))}</span>`;
      if (policy) html += `<span class="tr2"><i>Policy</i>${esc(policy)}</span>`;
      if (a) html += `<span class="tr2"><i>Required checks</i>${esc(a)}</span>`;
      if (s) html += `<span class="tr2"><i>Proven problems</i>${esc(s)}</span>`;
      if (m.past) {
        html += `<span class="tr2"><i>On</i>${esc(shortDate(m.past.at))}${q ? `, ${esc(q.title)}` : ''}</span>`;
      } else {
        const mv = movementWords(p.moved, p.moved === 'new' ? undefined : this.sinceFor(p));
        if (mv) html += `<span class="tr2 mv">${esc(mv)}</span>`;
        if (m.cell === 'bl') {
          const d = this.daysHere(p);
          if (d) html += `<span class="tr2">${esc(d)} in ${esc(q?.title ?? 'this quadrant')}</span>`;
        }
      }
      return html;
    };
    if (it.members.length === 1) return row(it.members[0]!);
    return `<b class="tn">${it.members.length} applications here</b>${it.members
      .map((m) => `<span class="tr2">${esc(m.p.label)} <em>${esc(m.p.tier ?? '')} · ${esc(this.levelWord(m.level))}</em></span>`)
      .join('')}<span class="tr2 mv">Press Enter to open the list</span>`;
  }

  // ---- view ----------------------------------------------------------------------------
  protected styles(): string {
    return DOCKET_STYLE + STYLE;
  }

  protected view(): string {
    const hasPoints = this._points.length > 0;
    const counts = { tl: 0, tr: 0, bl: 0, br: 0 } as Record<QuadCell, number>;
    for (const p of this._points) if (p.cell in counts) counts[p.cell] += 1;
    const total = this._points.length;
    const q = (k: QuadCell): string => this.quad(k)?.title ?? k;

    if (!hasPoints) {
      return `<div class="card">${this.head(this._heading, 'No applications are on the map yet')}<div class="empty">The map appears after the first scan.</div>${this.trayHtml()}${this.foot()}</div>`;
    }

    const title =
      counts.bl > 0
        ? `${counts.bl} of ${total} ${counts.bl === 1 ? 'application has' : 'applications have'} proven problems and overdue checks`
        : counts.br > 0
          ? `${counts.br} of ${total} ${counts.br === 1 ? 'application has' : 'applications have'} proven problems`
          : `No proven problem is open on the ${total} assessed ${total === 1 ? 'application' : 'applications'}`;
    const stats: KitStat[] = [];
    if (counts.bl > 0) stats.push({ text: `${q('bl')}: ${counts.bl}`, tone: 'bad', icon: 'triangle-alert' });
    if (counts.br > 0) stats.push({ text: `${q('br')}: ${counts.br}`, tone: 'warn' });
    if (this._unassessed.length > 0) stats.push({ text: `Not assessed: ${this._unassessed.length}`, tone: 'neutral' });
    const sub = [this._asOfNote, 'Position shows evidence, not a grade.'].filter((x) => x !== '').join(' ');

    const body = this.mode === 'map' ? this.mapHtml() : this.listHtml();
    return `<div class="card">${this.head(this._heading, title, { sub, stats })}${this.toolsHtml()}${body}${this.trayHtml()}${this.foot()}</div>`;
  }

  private toolsHtml(): string {
    const sel = (key: 'category' | 'exposure' | 'policy', label: string, opts: { id: string; name: string }[]): string =>
      opts.length === 0
        ? ''
        : `<label class="fsel${this.filters[key] !== '' ? ' on' : ''}"><span>${esc(label)}</span><select data-filter="${key}" data-fk="f-${key}" aria-label="Filter by ${esc(label.toLowerCase())}"><option value="">All</option>${opts
            .map((o) => `<option value="${esc(o.id)}"${this.filters[key] === o.id ? ' selected' : ''}>${esc(o.name)}</option>`)
            .join('')}</select></label>`;
    const flat = (xs: string[]): { id: string; name: string }[] => xs.map((x) => ({ id: x, name: x }));
    return `<div class="tools" role="group" aria-label="Map controls">
      ${
        this.mode === 'map'
          ? `<button type="button" class="chipbtn" data-act="movement" data-fk="movement" aria-pressed="${this.showMovement}"><span class="sw2"></span>Show movement</button>`
          : ''
      }
      ${sel('category', 'Category', flat(this.categories))}${sel('exposure', 'Exposure', flat(this.exposures))}${sel('policy', 'Policy', this.policies)}
      ${this.filterActive() ? `<button type="button" class="linkbtn" data-act="clear" data-fk="clear">Clear filters</button>` : ''}
      <div class="seg" role="group" aria-label="View"><button type="button" data-view="map" data-fk="v-map" aria-pressed="${this.mode === 'map'}">Map</button><button type="button" data-view="list" data-fk="v-list" aria-pressed="${this.mode === 'list'}">List</button></div>
    </div>`;
  }

  // ---- map ------------------------------------------------------------------------------
  private mapHtml(): string {
    const g = this.computeGeo();
    this.geo = g;
    const placed = this.place(g);
    this.placed = placed;
    const { W, H, pw, ph } = g;
    const left = M.l;
    const top = M.t;
    const cx = left + pw / 2;
    const cy = top + ph / 2;
    const noNotes = W < 520;

    // Static layer: paper, the one warm corner, grid, centre cross, axes, trails.
    const warm = `<rect x="${left}" y="${cy}" width="${pw / 2}" height="${ph / 2}" fill="rgb(var(--h-sev-high, 217 122 26) / .09)"/>`;
    const grid = [25, 75]
      .map(
        (v) =>
          `<line class="gl" x1="${g.X(v)}" y1="${top}" x2="${g.X(v)}" y2="${top + ph}"/><line class="gl" x1="${left}" y1="${g.Y(v)}" x2="${left + pw}" y2="${g.Y(v)}"/>`,
      )
      .join('');
    const cross = `<line class="cross" x1="${cx}" y1="${top}" x2="${cx}" y2="${top + ph}"/><line class="cross" x1="${left}" y1="${cy}" x2="${left + pw}" y2="${cy}"/>`;
    const ay = top + ph + 14;
    const ax = left - 14;
    const axes = `
      <line class="axl" x1="${left}" y1="${ay}" x2="${left + pw - 4}" y2="${ay}"/><path class="axh" d="M${left + pw} ${ay} l-8 -4.5 v9 z"/>
      <line class="axl" x1="${ax}" y1="${top + ph}" x2="${ax}" y2="${top + 4}"/><path class="axh" d="M${ax} ${top} l-4.5 8 h9 z"/>
      <text class="axw" x="${left}" y="${ay + 20}" text-anchor="start">Overdue</text>
      <text class="axt" x="${cx}" y="${ay + 20}" text-anchor="middle">Required checks</text>
      <text class="axw" x="${left + pw}" y="${ay + 20}" text-anchor="end">Current</text>
      <text class="axw" transform="translate(${ax - 10} ${top + ph}) rotate(-90)" text-anchor="start">Some open</text>
      <text class="axt" transform="translate(${ax - 10} ${cy}) rotate(-90)" text-anchor="middle">Proven problems</text>
      <text class="axw" transform="translate(${ax - 10} ${top}) rotate(-90)" text-anchor="end">None open</text>`;

    const trails = this.showMovement ? this.trailsSvg(g, placed) : '';
    const svg = `<svg class="plot2" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Posture map. ${esc(this.quadrants.map((qd) => qd.title).join('; '))}.">
      <rect x="${left}" y="${top}" width="${pw}" height="${ph}" fill="var(--k-canvas)"/>${warm}${grid}${cross}
      <rect x="${left}" y="${top}" width="${pw}" height="${ph}" fill="none" stroke="var(--k-hairline-2)"/>${axes}${trails}</svg>`;

    // Corner titles and notes.
    const rects = this.cornerRects(g);
    const corners = (['tl', 'tr', 'bl', 'br'] as QuadCell[])
      .map((k, i) => {
        const qd = this.quad(k);
        const r = rects[i]!;
        const right = k === 'tr' || k === 'br';
        const vert = k === 'bl' || k === 'br' ? `bottom:${H - (r.y + r.h)}px` : `top:${r.y}px`;
        return `<div class="corner ${k}${right ? ' r' : ''}" style="left:${r.x}px;${vert};width:${r.w}px"><b>${esc(qd?.title ?? k)}</b>${noNotes ? '' : `<span>${esc(qd?.note ?? '')}</span>`}</div>`;
      })
      .join('');

    const dots = placed.map((it) => this.dotHtml(it)).join('');
    const unseen = this.isLatest ? 0 : this._points.length - this.placedCount(placed);
    const pastNote = this.isLatest
      ? ''
      : `<div class="pastnote"><b>${esc(shortDate(this._snapshots[this.snapIndex]))}</b>. ${esc(DEFAULT_NOTE_PAST)}.${unseen > 0 ? ` ${unseen} ${unseen === 1 ? 'application was' : 'applications were'} not assessed yet.` : ''}</div>`;

    return `<div class="mapwrap"><div class="plotwrap" style="width:${W}px;height:${H}px" data-plot>${svg}${corners}<div class="dots">${dots}</div>
      <div class="tip2" role="tooltip" id="${this.frameId}-qt" hidden></div></div></div>
      ${pastNote}${this.legendHtml()}${this.timeHtml()}`;
  }

  private placedCount(placed: Placed[]): number {
    return placed.reduce((n, p) => n + p.members.length, 0);
  }

  private dotHtml(it: Placed): string {
    const lab = it.label!;
    const off = it.r + 7;
    const pos =
      lab.mode === 'right'
        ? `left:${off}px;top:-9px`
        : lab.mode === 'left'
          ? `left:${-off}px;top:-9px;transform:translateX(-100%)`
          : lab.mode === 'above'
            ? `left:0;top:${-(it.r + 6 + 17)}px;transform:translateX(-50%)`
            : `left:0;top:${it.r + 6}px;transform:translateX(-50%)`;
    const size = it.r * 2 + 4;
    const cluster = it.members.length > 1;
    const id = it.members[0]!.p.id;
    return `<div class="dw${it.dim ? ' dim' : ''}" data-key="${esc(it.key)}" style="left:${it.x}px;top:${it.y}px">
      <button type="button" class="dot ${it.level}" data-kind="${cluster ? 'cluster' : 'single'}" data-id="${esc(id)}" data-key="${esc(it.key)}" data-fk="dot-${esc(it.key)}"
        style="width:${size}px;height:${size}px;left:${-size / 2}px;top:${-size / 2}px" aria-label="${esc(this.ariaFor(it))}" aria-describedby="${this.frameId}-qt"${cluster ? ' aria-haspopup="dialog"' : ''}>${
          cluster ? `<span class="badge">${it.members.length}</span>` : ''
        }</button>
      <span class="dl${it.always ? ' always' : ''}" style="${pos}" aria-hidden="true">${esc(lab.text)}</span></div>`;
  }

  private trailsSvg(g: Geo, placed: Placed[]): string {
    const selected = this._snapshots[this.snapIndex];
    const parts: string[] = [];
    for (const it of placed) {
      for (const m of it.members) {
        const hist = (m.p.trail ?? [])
          .filter((t): t is QuadTrailPoint => t !== null && num(t.assurance) !== null && num(t.standing) !== null && (selected === undefined || dayMs(t.at) < dayMs(selected)))
          .map((t) => ({ x: g.X(clamp(t.assurance, 0, 100)), y: g.Y(clamp(t.standing, 0, 100)) }));
        const cur = { x: g.X(m.a), y: g.Y(m.s) };
        // Drop repeats so a steady application does not draw a line to itself.
        const pts = [...hist, cur].filter((p, i, a) => i === 0 || Math.hypot(p.x - a[i - 1]!.x, p.y - a[i - 1]!.y) > 1.5);
        if (pts.length < 2) continue;
        const r = tierRadius(m.p.tier) + 3;
        const last = pts[pts.length - 1]!;
        const prev = pts[pts.length - 2]!;
        const len = Math.hypot(last.x - prev.x, last.y - prev.y);
        const ux = (last.x - prev.x) / len;
        const uy = (last.y - prev.y) / len;
        const tip = { x: last.x - ux * r, y: last.y - uy * r };
        const dim = this.filterActive() && !this.passes(m.p);
        const color = `var(--lv-${m.level})`;
        const line = pts.map((p, i) => (i === pts.length - 1 ? `${tip.x.toFixed(1)},${tip.y.toFixed(1)}` : `${p.x.toFixed(1)},${p.y.toFixed(1)}`)).join(' ');
        const rings = pts
          .slice(0, -1)
          .map((p) => `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3.6" fill="var(--k-surface)" stroke="${color}" stroke-width="1.4"/>`)
          .join('');
        const hx = tip.x - ux * 8;
        const hy = tip.y - uy * 8;
        const arrow = len > r + 10 ? `<path d="M${tip.x.toFixed(1)} ${tip.y.toFixed(1)} L${(hx - uy * 4.2).toFixed(1)} ${(hy + ux * 4.2).toFixed(1)} L${(hx + uy * 4.2).toFixed(1)} ${(hy - ux * 4.2).toFixed(1)} z" fill="${color}"/>` : '';
        parts.push(
          `<g class="trail${dim ? ' dim' : ''}"><polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>${rings}${arrow}</g>`,
        );
      }
    }
    return parts.join('');
  }

  private legendHtml(): string {
    const lv = (['action', 'attention', 'clear'] as Level[]).map((l) => ({
      label: this.levelWord(l),
      color: `var(--lv-${l})`,
      swatchStyle: 'border-radius:999px;width:11px;height:11px',
    }));
    const sizes = [12, 9, 6.5]
      .map((r, i) => `<span class="sz"><i style="width:${r * 2}px;height:${r * 2}px"></i>Tier ${i + 1}</span>`)
      .join('');
    const mv = this.showMovement
      ? `<span class="sz"><svg width="34" height="12" viewBox="0 0 34 12" aria-hidden="true"><circle cx="4" cy="6" r="3.2" fill="var(--k-surface)" stroke="var(--k-text-2)" stroke-width="1.4"/><line x1="7" y1="6" x2="24" y2="6" stroke="var(--k-text-2)" stroke-width="1.5"/><path d="M33 6 l-8 -4 v8 z" fill="var(--k-text-2)"/></svg>Earlier position to now</span>`
      : '';
    return `<div class="legrow">${legend(lv)}<div class="sizes" aria-label="Dot size shows tier">Size shows tier ${sizes}${mv}</div></div>`;
  }

  private timeHtml(): string {
    const snaps = this._snapshots;
    if (snaps.length === 0) return '';
    const last = snaps.length - 1;
    const stops = snaps
      .map((d, i) => {
        const on = i === this.snapIndex;
        const today = i === last;
        const bs = this._bySnapshot.find((b) => b.at === d);
        const tile = bs
          ? `<div class="sm${on ? ' on' : ''}" data-snap="${i}" role="img" aria-label="${esc(shortDate(d))}: ${esc(
              (['tl', 'tr', 'bl', 'br'] as QuadCell[]).map((k) => `${this.quad(k)?.title ?? k}, ${bs[k]}`).join('; '),
            )}${bs.unassessed ? `; ${bs.unassessed} not assessed` : ''}">
              <div class="g4">${(['tl', 'tr', 'bl', 'br'] as QuadCell[]).map((k) => `<span class="c ${k}${bs[k] === 0 ? ' z' : ''}" title="${esc(this.quad(k)?.title ?? k)}">${bs[k]}</span>`).join('')}</div>
              ${bs.unassessed ? `<div class="smf">${bs.unassessed} not assessed</div>` : '<div class="smf">&nbsp;</div>'}</div>`
          : '';
        return `<div class="snapcol"><button type="button" class="stop${on ? ' on' : ''}" data-snap="${i}" data-fk="snap-${i}" aria-pressed="${on}" aria-label="Show positions on ${esc(shortDate(d))}${today ? ', today' : ''}"><span class="dt">${esc(shortDate(d))}</span>${today ? '<span class="today">Today</span>' : ''}</button>${tile}</div>`;
      })
      .join('');
    return `<div class="time"><div class="timehead"><span class="eyebrow">Position over time</span><span class="muted tnote">${esc(DEFAULT_NOTE_PAST)}. Each tile is the map in miniature.</span></div>
      <div class="snaps" role="group" aria-label="Snapshot dates">${stops}</div></div>`;
  }

  // ---- list ------------------------------------------------------------------------------
  private listHtml(): string {
    const cols: { key: string; label: string }[] = [
      { key: 'label', label: 'Application' },
      { key: 'tier', label: 'Tier' },
      { key: 'policy', label: 'Policy' },
      { key: 'cell', label: 'Quadrant' },
      { key: 'assurance', label: 'Required checks' },
      { key: 'standing', label: 'Proven problems' },
      { key: 'moved', label: 'Moved' },
      { key: 'days', label: 'Days in cell' },
    ];
    const val = (p: QuadPoint, key: string): string | number | null => {
      switch (key) {
        case 'label':
          return p.label.toLowerCase();
        case 'tier':
          return p.tier ?? '';
        case 'policy':
          return (p.policy_name ?? p.policy ?? '').toLowerCase();
        case 'cell':
          return CELL_ORDER.indexOf(p.cell);
        case 'assurance':
          return (p.assurance_note ?? '').toLowerCase();
        case 'standing':
          return (p.standing_note ?? '').toLowerCase();
        case 'moved':
          return movedRank(p.moved);
        default:
          return typeof p.days_in_cell === 'number' ? p.days_in_cell : null;
      }
    };
    const dir = this.sort.dir === 'asc' ? 1 : -1;
    const rows = [...this._points].sort((a, b) => {
      const x = val(a, this.sort.key);
      const y = val(b, this.sort.key);
      if (x === null && y === null) return 0;
      if (x === null) return 1; // missing sorts last in either direction
      if (y === null) return -1;
      const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
      return c !== 0 ? c * dir : a.label.localeCompare(b.label);
    });
    const head = cols
      .map((c) => {
        const on = this.sort.key === c.key;
        const aria = on ? (this.sort.dir === 'asc' ? 'ascending' : 'descending') : 'none';
        return `<th scope="col" aria-sort="${aria}"><button type="button" class="sorter" data-sort="${c.key}" data-fk="sort-${c.key}">${esc(c.label)}<span class="arr ${on ? this.sort.dir : ''}" aria-hidden="true"></span></button></th>`;
      })
      .join('');
    const body = rows
      .map((p) => {
        const q = this.quad(p.cell);
        const mv = movementWords(p.moved, p.moved === 'new' ? undefined : this.sinceFor(p));
        const d = typeof p.days_in_cell === 'number' ? (p.days_in_cell >= 28 ? '28+' : String(p.days_in_cell)) : '';
        return `<tr class="${this.passes(p) ? '' : 'dimrow'}" data-open="${esc(p.id)}"><td class="app"><button type="button" class="applink" data-open="${esc(p.id)}"><span class="lamp ${p.level === 'action' ? 'bad' : p.level === 'attention' ? 'warn' : p.level === 'clear' ? 'ok' : 'off'}"></span><span><b>${esc(p.label)}</b><small>${esc(this.levelWord(p.level))}</small></span></button></td>
          <td>${esc(p.tier ?? '')}</td><td>${esc(p.policy_name ?? p.policy ?? '')}</td><td class="q ${p.cell}">${esc(q?.title ?? '')}</td>
          <td>${esc(p.assurance_note ?? '')}</td><td>${esc(p.standing_note ?? '')}</td><td class="mvc" title="${esc(mv)}">${movementShort(p.moved)}</td><td class="n">${esc(d)}</td></tr>`;
      })
      .join('');
    const widths = [17, 7, 12, 15, 16, 16, 10, 7];
    const colgroup = `<colgroup>${widths.map((w) => `<col style="width:${w}%">`).join('')}</colgroup>`;
    return `<div class="lwrap"><table class="lt">${colgroup}<thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  private trayHtml(): string {
    if (this._unassessed.length === 0) return '';
    const chips = this._unassessed
      .map(
        (u) =>
          `<button type="button" class="tchip" data-open="${esc(u.id)}" title="${esc(u.reason ?? 'Not assessed')}">${esc(u.label)}${u.tier ? `<small>${esc(u.tier)}</small>` : ''}</button>`,
      )
      .join('');
    return `<div class="tray"><span class="eyebrow">Not assessed</span><span class="tnote2">No evidence, so no position.</span>${chips}</div>`;
  }

  // ---- events --------------------------------------------------------------------------------
  private onClick(e: Event): void {
    const t = e.target as Element | null;
    if (!t) return;
    const open = t.closest<HTMLElement>('[data-open]');
    if (open?.dataset['open']) {
      // Row click opens the app, but the inner button already did: avoid a double emit.
      if (open.tagName === 'TR' && t.closest('button')) return;
      this.closePop(false);
      emit(this, 'docket:open-app', { id: open.dataset['open'] });
      return;
    }
    const dot = t.closest<HTMLElement>('.dot');
    if (dot) {
      if (dot.dataset['kind'] === 'cluster') this.openPop(dot);
      else emit(this, 'docket:open-app', { id: dot.dataset['id'] ?? '' });
      return;
    }
    const mv = t.closest<HTMLElement>('[data-act]');
    if (mv?.dataset['act'] === 'movement') {
      this.showMovement = !this.showMovement;
      this.refresh();
      return;
    }
    if (mv?.dataset['act'] === 'clear') {
      this.filters = { category: '', exposure: '', policy: '' };
      this.pendingFocus = null;
      this.refresh();
      return;
    }
    const view = t.closest<HTMLElement>('[data-view]');
    if (view) {
      this.mode = view.dataset['view'] === 'list' ? 'list' : 'map';
      this.refresh();
      return;
    }
    const snap = t.closest<HTMLElement>('[data-snap]');
    if (snap) {
      const i = Number(snap.dataset['snap']);
      if (Number.isInteger(i) && i !== this.snapIndex) {
        this.snap = i === this._snapshots.length - 1 ? -1 : i;
        this.refresh(true);
      }
      return;
    }
    const sort = t.closest<HTMLElement>('[data-sort]');
    if (sort?.dataset['sort']) {
      const key = sort.dataset['sort'];
      this.sort = this.sort.key === key ? { key, dir: this.sort.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' };
      this.refresh();
    }
  }

  private onChange(e: Event): void {
    const s = e.target as HTMLSelectElement | null;
    const key = s?.dataset['filter'];
    if (!s || (key !== 'category' && key !== 'exposure' && key !== 'policy')) return;
    this.filters = { ...this.filters, [key]: s.value };
    this.refresh();
  }

  private onOver(e: Event): void {
    const dot = (e.target as Element | null)?.closest<HTMLElement>('.dot');
    if (dot) this.showTip(dot);
  }

  private onOut(e: Event): void {
    const dot = (e.target as Element | null)?.closest<HTMLElement>('.dot');
    if (!dot) return;
    const to = (e as FocusEvent | PointerEvent).relatedTarget as Element | null;
    if (to && dot.contains(to)) return;
    this.hideTip();
  }

  private onKey(e: KeyboardEvent): void {
    if (e.key === 'Escape') {
      if (this.root.querySelector('.pop')) {
        e.stopPropagation();
        this.closePop(true);
      }
      this.hideTip();
      return;
    }
    const dot = (e.target as Element | null)?.closest<HTMLElement>('.dot');
    if (!dot) return;
    const dots = [...this.root.querySelectorAll<HTMLElement>('.dot')];
    const i = dots.indexOf(dot);
    const step = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (step === 0 || i < 0) return;
    e.preventDefault();
    dots[(i + step + dots.length) % dots.length]?.focus();
  }

  private showTip(dot: HTMLElement): void {
    const key = dot.dataset['key'];
    const it = this.placed.find((p) => p.key === key);
    const tip = this.root.querySelector<HTMLElement>('.tip2');
    const g = this.geo;
    if (!it || !tip || !g || this.root.querySelector('.pop')) return;
    tip.innerHTML = this.tipHtml(it);
    tip.style.visibility = 'hidden';
    tip.hidden = false;
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    // Beside the dot, 14px off its edge, on whichever side has room. Prefer a spot that
    // covers no other dot; never the hovered one.
    const gap = 14;
    const cands: Rect[] = [
      { x: it.x + it.r + gap, y: it.y - th / 2, w: tw, h: th },
      { x: it.x - it.r - gap - tw, y: it.y - th / 2, w: tw, h: th },
      { x: it.x - tw / 2, y: it.y - it.r - gap - th, w: tw, h: th },
      { x: it.x - tw / 2, y: it.y + it.r + gap, w: tw, h: th },
    ];
    const fit = (r: Rect, side: number): Rect => ({
      ...r,
      x: side < 2 ? r.x : clamp(r.x, 0, Math.max(0, g.W - tw)),
      y: side < 2 ? clamp(r.y, 0, Math.max(0, g.H - th)) : r.y,
    });
    const score = (r: Rect, side: number): number => {
      const out = r.x < 0 || r.y < 0 || r.x + r.w > g.W || r.y + r.h > g.H;
      const hits = this.placed.filter((o) => o !== it && overlap(r, { x: o.x - o.r - 2, y: o.y - o.r - 2, w: 2 * o.r + 4, h: 2 * o.r + 4 }, 0)).length;
      return (out ? 100 : 0) + hits * 10 + side;
    };
    let best = 0;
    let bestScore = Infinity;
    const fitted = cands.map(fit);
    fitted.forEach((r, i) => {
      const sc = score(r, i);
      if (sc < bestScore) {
        bestScore = sc;
        best = i;
      }
    });
    const r = fitted[best]!;
    tip.style.left = `${Math.round(r.x)}px`;
    tip.style.top = `${Math.round(r.y)}px`;
    tip.style.visibility = '';
  }

  private hideTip(): void {
    const tip = this.root.querySelector<HTMLElement>('.tip2');
    if (tip) tip.hidden = true;
  }

  private openPop(dot: HTMLElement): void {
    this.closePop(false);
    this.hideTip();
    const it = this.placed.find((p) => p.key === dot.dataset['key']);
    const wrap = this.root.querySelector<HTMLElement>('[data-plot]');
    const g = this.geo;
    if (!it || !wrap || !g) return;
    const pop = document.createElement('div');
    pop.className = 'pop';
    pop.setAttribute('role', 'dialog');
    pop.setAttribute('aria-label', 'Applications at this position');
    pop.dataset['for'] = it.key;
    pop.innerHTML = `<div class="pophead">${it.members.length} applications here</div><ul>${it.members
      .map(
        (m) =>
          `<li><button type="button" data-open="${esc(m.p.id)}"><span class="lamp ${m.level === 'action' ? 'bad' : m.level === 'attention' ? 'warn' : m.level === 'clear' ? 'ok' : 'off'}"></span><b>${esc(m.p.label)}</b><small>${esc(m.p.tier ?? '')} · ${esc(this.levelWord(m.level))}</small></button></li>`,
      )
      .join('')}</ul>`;
    const flipX = it.x > g.W * 0.58;
    pop.style.left = `${flipX ? it.x - it.r - 12 : it.x + it.r + 12}px`;
    pop.style.top = `${it.y - 14}px`;
    if (flipX) pop.style.transform = 'translateX(-100%)';
    wrap.appendChild(pop);
    pop.querySelector<HTMLElement>('button')?.focus();
    dot.setAttribute('aria-expanded', 'true');
  }

  private closePop(restoreFocus: boolean): void {
    const pop = this.root.querySelector<HTMLElement>('.pop');
    if (!pop) return;
    const key = pop.dataset['for'];
    pop.remove();
    const dot = [...this.root.querySelectorAll<HTMLElement>('.dot')].find((d) => d.dataset['key'] === key);
    dot?.removeAttribute('aria-expanded');
    if (restoreFocus) dot?.focus();
  }

  // ---- after render: focus, animation -----------------------------------------------------
  protected afterRender(): void {
    if (this.pendingFocus !== null) {
      const sel = `[data-fk="${CSS.escape(this.pendingFocus)}"]`;
      this.root.querySelector<HTMLElement>(sel)?.focus({ preventScroll: true });
      this.pendingFocus = null;
    }
    if (this.animateNext) {
      this.animateNext = false;
      const reduce = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (!reduce) this.flip();
    }
  }

  /** Slide each dot from where it was to where it is now. New dots simply appear. */
  private flip(): void {
    const els = [...this.root.querySelectorAll<HTMLElement>('.dw')];
    const moves: HTMLElement[] = [];
    for (const el of els) {
      const key = el.dataset['key'] ?? '';
      const it = this.placed.find((p) => p.key === key);
      const from = this.prevPos.get(key) ?? (it ? this.prevPos.get(it.members[0]!.p.id) : undefined);
      if (!it || !from) continue;
      const dx = from.x - it.x;
      const dy = from.y - it.y;
      if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) continue;
      el.style.transition = 'none';
      el.style.transform = `translate(${dx}px, ${dy}px)`;
      moves.push(el);
    }
    if (moves.length === 0) return;
    void this.root.querySelector('.plotwrap')?.getBoundingClientRect();
    for (const el of moves) {
      el.style.transition = 'transform 300ms cubic-bezier(.2,.7,.2,1)';
      el.style.transform = '';
    }
  }
}

const STYLE = `
:host { --lv-action:var(--k-sev-critical); --lv-attention:rgb(var(--h-sev-high, 217 122 26)); --lv-clear:var(--k-ok); --lv-unknown:var(--k-hairline-2); }
.tools { display:flex; flex-wrap:wrap; align-items:center; gap:8px; padding:2px 22px 14px; }
.chipbtn, .fsel { display:inline-flex; align-items:center; gap:8px; height:32px; padding:0 12px; border-radius:999px; border:1px solid var(--k-hairline-2); background:var(--k-surface); color:var(--k-text); font-size:12.5px; font-weight:600; cursor:pointer; white-space:nowrap; }
.chipbtn:hover, .fsel:hover { background:var(--k-surface-2); }
.chipbtn[aria-pressed="true"], .fsel.on { background:rgb(var(--h-verdant-50, 233 239 235)); border-color:rgb(var(--h-verdant-200, 168 191 175)); color:rgb(var(--h-verdant-700, 43 74 53)); }
.sw2 { position:relative; width:26px; height:15px; border-radius:999px; background:var(--k-hairline-2); flex:none; transition:background .15s; }
.sw2::after { content:''; position:absolute; top:2px; left:2px; width:11px; height:11px; border-radius:999px; background:var(--k-surface); transition:transform .15s; box-shadow:0 1px 2px rgb(0 0 0 / .25); }
.chipbtn[aria-pressed="true"] .sw2 { background:rgb(var(--h-verdant-600, 59 96 71)); }
.chipbtn[aria-pressed="true"] .sw2::after { transform:translateX(11px); }
.fsel { cursor:default; gap:6px; padding-right:8px; }
.fsel > span { color:var(--k-text-2); font-weight:500; }
.fsel.on > span { color:inherit; }
.fsel select { field-sizing:content; appearance:none; -webkit-appearance:none; border:0; background:transparent ${SVG_CHEVRON} no-repeat right 6px center; color:inherit; font:inherit; font-weight:600; padding:0 20px 0 0; height:28px; cursor:pointer; max-width:200px; }
.fsel select:focus-visible { outline:2px solid var(--k-brand); outline-offset:6px; border-radius:6px; }
.seg { margin-left:auto; display:inline-flex; padding:2px; border:1px solid var(--k-hairline-2); border-radius:999px; background:var(--k-surface); }
.seg button { height:26px; padding:0 14px; border:0; border-radius:999px; background:transparent; font-size:12.5px; font-weight:600; cursor:pointer; color:var(--k-text-2); }
.seg button[aria-pressed="true"] { background:var(--k-text); color:var(--k-surface); }
.linkbtn { font-size:12.5px; }

.mapwrap { padding:0 22px; overflow-x:auto; }
.plotwrap { position:relative; margin:0 auto; }
svg.plot2 { position:absolute; inset:0; display:block; }
.gl { stroke:var(--k-hairline); stroke-width:1; }
.cross { stroke:var(--k-text-3); stroke-width:1; stroke-dasharray:5 5; opacity:.7; }
.axl { stroke:var(--k-text-2); stroke-width:1.25; }
.axh { fill:var(--k-text-2); }
.axw { fill:var(--k-text-2); font-size:12px; font-family:inherit; }
.axt { fill:var(--k-text); font-size:12.5px; font-weight:700; font-family:inherit; letter-spacing:.02em; }
.trail { opacity:.7; } .trail.dim { opacity:.15; }
.corner { position:absolute; pointer-events:none; z-index:1; }
.corner.r { text-align:right; }
.corner b { display:block; font-size:11.5px; letter-spacing:.07em; text-transform:uppercase; font-weight:700; color:var(--k-text-2); line-height:1.35; }
.corner span { display:block; margin-top:2px; font-size:12px; line-height:1.35; color:var(--k-text-2); }
.corner.bl b { color:rgb(var(--h-status-warning, 180 83 9)); }
.dots { position:absolute; inset:0; z-index:2; pointer-events:none; }
.dw { position:absolute; width:0; height:0; pointer-events:none; }
.dw.dim { opacity:.2; transition:opacity .15s; }
.dw.dim:hover, .dw.dim:focus-within { opacity:.75; }
.dw:hover, .dw:focus-within { z-index:4; }
.dot { all:unset; box-sizing:border-box; position:absolute; border-radius:999px; border:2px solid var(--k-surface); cursor:pointer; pointer-events:auto;
  box-shadow:0 0 0 1px rgb(26 31 28 / .22), 0 1px 3px rgb(26 31 28 / .3); transition:box-shadow .12s; }
.dot.action { background:var(--lv-action); } .dot.attention { background:var(--lv-attention); }
.dot.clear { background:var(--lv-clear); } .dot.unknown { background:var(--lv-unknown); }
.dot:hover, .dot:focus-visible { box-shadow:0 0 0 1px rgb(26 31 28 / .3), 0 0 0 5px rgb(var(--h-verdant-200, 168 191 175) / .65); }
.dot:focus-visible { outline:2px solid var(--k-text); outline-offset:3px; border-radius:999px; }
.badge { position:absolute; right:-9px; top:-9px; min-width:19px; height:19px; padding:0 5px; border-radius:999px; background:var(--k-text); color:var(--k-surface); font-size:12px; font-weight:700; display:grid; place-items:center; border:2px solid var(--k-surface); box-sizing:border-box; font-variant-numeric:tabular-nums; }
.dl { position:absolute; white-space:nowrap; font-size:12px; font-weight:600; line-height:17px; color:var(--k-text); pointer-events:none;
  text-shadow:0 0 3px var(--k-canvas), 0 0 3px var(--k-canvas), 0 0 5px var(--k-canvas), 0 0 5px var(--k-canvas); }
.dl:not(.always) { opacity:0; transition:opacity .1s; }
.dw:hover .dl, .dw:focus-within .dl { opacity:1; }
.tip2 { position:absolute; z-index:8; width:max-content; max-width:min(300px, 80%); padding:10px 12px; border-radius:10px; background:var(--k-text); color:var(--k-surface); font-size:12px; line-height:1.45; pointer-events:none; box-shadow:0 10px 28px rgb(26 31 28 / .22); }
.tip2[hidden] { display:none; }
.tip2 .tn { display:block; font-size:13px; font-weight:600; }
.tip2 .tl2 { display:block; opacity:.8; margin-bottom:4px; }
.tip2 .tr2 { display:block; margin-top:3px; }
.tip2 .tr2 i { display:block; font-style:normal; font-size:10.5px; letter-spacing:.08em; text-transform:uppercase; opacity:.6; }
.tip2 .tr2 em { font-style:normal; opacity:.7; }
.tip2 .mv { margin-top:6px; padding-top:6px; border-top:1px solid rgb(255 254 251 / .2); font-weight:600; }
.pop { position:absolute; z-index:9; min-width:220px; max-width:300px; padding:6px; border-radius:10px; background:var(--k-surface); border:1px solid var(--k-hairline-2); box-shadow:0 12px 30px rgb(26 31 28 / .2); }
.pophead { padding:6px 8px 4px; font-size:11px; letter-spacing:.1em; text-transform:uppercase; font-weight:600; color:var(--k-text-2); }
.pop ul { margin:0; padding:0; list-style:none; }
.pop button { all:unset; box-sizing:border-box; display:grid; grid-template-columns:auto 1fr; column-gap:8px; align-items:center; width:100%; padding:7px 8px; border-radius:7px; cursor:pointer; font-size:13px; }
.pop button small { grid-column:2; font-size:12px; color:var(--k-text-2); }
.pop button:hover, .pop button:focus-visible { background:var(--k-surface-2); outline:none; }
.pop button:focus-visible { box-shadow:inset 0 0 0 2px var(--k-brand); }
.pastnote { margin:10px 22px 0; padding:7px 12px; border-radius:8px; background:var(--k-surface-2); font-size:12.5px; color:var(--k-text-2); }

.legrow { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:6px 24px; padding:2px 22px 4px; }
.legrow .legend { margin:12px 0 0; }
.sizes { display:flex; align-items:center; flex-wrap:wrap; gap:6px 14px; margin-top:12px; font-size:12px; color:var(--k-text-2); }
.sz { display:inline-flex; align-items:center; gap:6px; }
.sz i { display:inline-block; border-radius:999px; background:var(--k-text-3); border:2px solid var(--k-surface); box-shadow:0 0 0 1px rgb(26 31 28 / .22); box-sizing:content-box; }

.time { margin:14px 22px 6px; padding-top:14px; border-top:1px solid var(--k-hairline); }
.timehead { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:baseline; gap:4px 16px; margin-bottom:10px; }
.tnote { font-size:12px; color:var(--k-text-2); }
.eyebrow { font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:var(--k-text-2); font-weight:600; }
.snaps { position:relative; display:grid; grid-template-columns:repeat(5, minmax(0, 1fr)); gap:10px; }
.snaps::before { content:''; position:absolute; left:0; right:0; top:15px; border-top:1px solid var(--k-hairline-2); }
.snapcol { display:flex; flex-direction:column; align-items:stretch; gap:8px; min-width:0; }
.stop { position:relative; align-self:center; display:inline-flex; align-items:baseline; gap:6px; height:30px; padding:0 14px; border-radius:999px; border:1px solid var(--k-hairline-2); background:var(--k-surface); font-size:12.5px; font-weight:600; cursor:pointer; align-items:center; white-space:nowrap; }
.stop:hover { background:var(--k-surface-2); }
.stop.on { background:var(--k-text); color:var(--k-surface); border-color:transparent; }
.today { font-family:var(--k-serif); font-style:italic; font-weight:500; font-size:12.5px; opacity:.85; }
.sm { border:1px solid var(--k-hairline); border-radius:10px; padding:6px; background:var(--k-surface); cursor:pointer; }
.sm.on { border-color:var(--k-text); box-shadow:0 0 0 1px var(--k-text); }
.g4 { display:grid; grid-template-columns:1fr 1fr; gap:3px; }
.g4 .c { display:grid; place-items:center; height:30px; border-radius:6px; background:var(--k-surface-2); font-size:14px; font-weight:600; font-variant-numeric:tabular-nums; }
.g4 .c.bl { background:rgb(var(--h-sev-high, 217 122 26) / .14); }
.g4 .c.z { color:var(--k-text-3); font-weight:500; }
.smf { margin-top:5px; text-align:center; font-size:12px; color:var(--k-text-2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

.tray { display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin:10px 22px 16px; padding:10px 12px; border-radius:10px; border:1px dashed var(--k-hairline-2); background:var(--k-surface); }
.tnote2 { font-size:12px; color:var(--k-text-2); margin-right:4px; }
.tchip { display:inline-flex; align-items:center; gap:7px; height:28px; padding:0 12px; border-radius:999px; border:1px solid var(--k-hairline-2); background:var(--k-surface-2); font-size:12.5px; font-weight:600; cursor:pointer; }
.tchip small { font-size:12px; font-weight:500; color:var(--k-text-2); }
.tchip:hover { background:var(--k-surface-3, var(--k-hairline)); }

.lwrap { padding:0 22px 14px; overflow-x:auto; }
.lt { width:100%; min-width:1040px; border-collapse:collapse; font-size:12.5px; table-layout:fixed; }
.lt th { text-align:left; padding:0; background:var(--k-surface-2); border-bottom:1px solid var(--k-hairline); }
.sorter { all:unset; box-sizing:border-box; display:flex; align-items:center; gap:6px; width:100%; padding:10px 8px; cursor:pointer; font-size:11px; letter-spacing:.06em; text-transform:uppercase; font-weight:600; color:var(--k-text-2); line-height:1.25; }
.sorter:hover { color:var(--k-text); } .sorter:focus-visible { outline:2px solid var(--k-brand); outline-offset:-2px; }
.arr { width:0; height:0; border-left:4px solid transparent; border-right:4px solid transparent; border-top:5px solid var(--k-hairline-2); }
.arr.asc { border-top:0; border-bottom:5px solid var(--k-text); } .arr.desc { border-top:5px solid var(--k-text); }
.lt td { padding:10px 8px; border-bottom:1px solid var(--k-hairline); vertical-align:top; line-height:1.4; }
.lt tbody tr { cursor:pointer; } .lt tbody tr:hover { background:var(--k-surface-2); }
.lt tr.dimrow { opacity:.4; }
.lt td.n { text-align:right; padding-right:14px; font-variant-numeric:tabular-nums; }
.lt td.q.bl { color:rgb(var(--h-status-warning, 180 83 9)); font-weight:600; }
.lt td { overflow-wrap:anywhere; }
.lt td.app { overflow-wrap:normal; }
.applink { all:unset; box-sizing:border-box; display:flex; align-items:center; gap:10px; cursor:pointer; }
.applink b { display:block; font-size:13px; } .applink small { display:block; font-size:12px; color:var(--k-text-2); }
.applink:focus-visible { outline:2px solid var(--k-brand); outline-offset:3px; border-radius:4px; }
.empty { padding:36px 22px; }
@media (max-width:720px) { .tools, .mapwrap, .time, .tray, .lwrap, .legrow { padding-left:14px; padding-right:14px; margin-left:0; margin-right:0; } .snaps { gap:6px; } .stop { padding:0 8px; } .g4 .c { height:24px; font-size:12.5px; } }
`;

defineElement('docket-quadrant', DocketQuadrant);
