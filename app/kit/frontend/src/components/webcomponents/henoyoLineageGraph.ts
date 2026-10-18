// <henoyo-lineage-graph>: directed flows laid out left to right with a deterministic layered layout.

import {
  HenoyoElement,
  MATERIALS,
  defineElement,
  emit,
  esc,
  truncatedSpan,
  glyph,
  isMaterial,
  type Material,
} from './henoyoKit';
import { watchWidth } from './vizPalette';

export type FlagTone = 'warn' | 'bad' | 'info';

export interface LineageNode {
  id: string;
  label: string;
  sublabel?: string;
  material: Material;
  glyphName: string;
  group?: string;
  /** With recordId: the record a click opens (henoyo:open-record). */
  objectApiName?: string;
  recordId?: string;
}

export interface LineageEdge {
  from: string;
  to: string;
  label?: string;
  flag?: { label: string; tone: FlagTone };
}

export interface LineageLegendItem {
  tone: FlagTone;
  label: string;
}

const W = 200;
const H = 64;
const LAYER_GAP = 120;
const ROW_GAP = 24;
const PAD = 36;
const TOP = 36;
const BAND_GAP = 44;

export interface Placed {
  id: string;
  layer: number;
  x: number;
  y: number;
}

/** Longest-path layering (back edges ignored), barycentre ordering, fixed grid positions. */
export function layoutLineage(
  nodes: { id: string; group?: string }[],
  edges: LineageEdge[],
): Placed[] {
  const ids = new Set(nodes.map((n) => n.id));
  const out = new Map<string, string[]>();
  for (const n of nodes) out.set(n.id, []);
  const seen = new Set<string>();
  for (const e of edges) {
    const key = `${e.from}\u0000${e.to}`;
    if (!ids.has(e.from) || !ids.has(e.to) || e.from === e.to || seen.has(key)) continue;
    seen.add(key);
    out.get(e.from)?.push(e.to);
  }
  const state = new Map<string, number>();
  const dag = new Map<string, string[]>();
  for (const n of nodes) dag.set(n.id, []);
  const order: string[] = [];
  const dfs = (u: string): void => {
    state.set(u, 1);
    for (const v of out.get(u) ?? []) {
      if (state.get(v) === 1) continue;
      dag.get(u)?.push(v);
      if (!state.has(v)) dfs(v);
    }
    state.set(u, 2);
    order.push(u);
  };
  for (const n of nodes) if (!state.has(n.id)) dfs(n.id);
  const layer = new Map<string, number>();
  for (const n of nodes) layer.set(n.id, 0);
  for (const u of [...order].reverse())
    for (const v of dag.get(u) ?? [])
      layer.set(v, Math.max(layer.get(v) ?? 0, (layer.get(u) ?? 0) + 1));

  const preds = new Map<string, string[]>();
  const succs = new Map<string, string[]>();
  for (const n of nodes) {
    preds.set(n.id, []);
    succs.set(n.id, []);
  }
  for (const [u, vs] of dag)
    for (const v of vs) {
      preds.get(v)?.push(u);
      succs.get(u)?.push(v);
    }
  const maxLayer = Math.max(0, ...layer.values());
  const cols: string[][] = Array.from({ length: maxLayer + 1 }, () => []);
  for (const n of nodes) cols[layer.get(n.id) ?? 0]?.push(n.id);
  const pos = new Map<string, number>();
  const reindex = (): void => cols.forEach((c) => c.forEach((id, i) => pos.set(id, i)));
  reindex();
  const bary = (id: string, nb: Map<string, string[]>): number => {
    const list = nb.get(id) ?? [];
    if (list.length === 0) return pos.get(id) ?? 0;
    return list.reduce((s, p) => s + (pos.get(p) ?? 0), 0) / list.length;
  };
  const reorder = (l: number, nb: Map<string, string[]>): void => {
    const col = cols[l];
    if (!col) return;
    const keyed = col.map((id, i) => ({ id, b: bary(id, nb), i }));
    keyed.sort((a, b) => a.b - b.b || a.i - b.i);
    cols[l] = keyed.map((k) => k.id);
    reindex();
  };
  for (let sweep = 0; sweep < 2; sweep++) {
    for (let l = 1; l <= maxLayer; l++) reorder(l, preds);
    for (let l = maxLayer - 1; l >= 0; l--) reorder(l, succs);
  }
  const groupOf = new Map(nodes.map((n) => [n.id, str(n.group) ?? '']));
  const groupOrder: string[] = [];
  for (const n of nodes) {
    const g = groupOf.get(n.id) ?? '';
    if (!groupOrder.includes(g)) groupOrder.push(g);
  }
  const rowsOf = (g: string): number =>
    Math.max(1, ...cols.map((c) => c.filter((id) => groupOf.get(id) === g).length));
  const offset = new Map<string, number>();
  let rows = 0;
  groupOrder.forEach((g, gi) => {
    offset.set(g, rows + gi * (BAND_GAP / (H + ROW_GAP)));
    rows += rowsOf(g);
  });
  const placed: Placed[] = [];
  cols.forEach((c, l) => {
    const used = new Map<string, number>();
    for (const id of c) {
      const g = groupOf.get(id) ?? '';
      const i = used.get(g) ?? 0;
      used.set(g, i + 1);
      placed.push({
        id,
        layer: l,
        x: PAD + l * (W + LAYER_GAP),
        y: TOP + ((offset.get(g) ?? 0) + i) * (H + ROW_GAP),
      });
    }
  });
  return placed;
}

export interface Band {
  group: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

type Pt = { x: number; y: number };

export interface Route {
  d: string;
  segments: [Pt, Pt, Pt, Pt][];
  mid: Pt;
  back: boolean;
}

/** One horizontal lane per group, spanning the full width, sized to the group's rows. */
export function layoutBands(nodes: { id: string; group?: string }[], placed: Placed[]): Band[] {
  const at = new Map(placed.map((p) => [p.id, p]));
  const groups = new Map<string, Placed[]>();
  for (const n of nodes) {
    const p = at.get(n.id);
    const g = str(n.group);
    if (g && p) groups.set(g, [...(groups.get(g) ?? []), p]);
  }
  const width = Math.max(...placed.map((p) => p.x)) + W + PAD;
  return [...groups.entries()].map(([group, ps]) => {
    const y1 = Math.min(...ps.map((p) => p.y)) - 22;
    const y2 = Math.max(...ps.map((p) => p.y)) + H + 10;
    return { group, x: 8, y: y1, width: width - 16, height: y2 - y1 };
  });
}

const bez = (s: [Pt, Pt, Pt, Pt], t: number): Pt => {
  const u = 1 - t;
  const f = (a: number, b: number, c: number, d: number): number =>
    u * u * u * a + 3 * u * u * t * b + 3 * u * t * t * c + t * t * t * d;
  return { x: f(s[0].x, s[1].x, s[2].x, s[3].x), y: f(s[0].y, s[1].y, s[2].y, s[3].y) };
};

export function sampleRoute(segments: [Pt, Pt, Pt, Pt][], steps = 24): Pt[] {
  return segments.flatMap((s) => Array.from({ length: steps + 1 }, (_, i) => bez(s, i / steps)));
}

/** Forward edges run through the row gaps nearest the straight line; back edges loop below. */
export function routeEdge(a: Placed, b: Placed, placed: Placed[], loopY: number): Route {
  const x1 = a.x + W;
  const y1 = a.y + H / 2;
  const x2 = b.x;
  const y2 = b.y + H / 2;
  if (b.layer <= a.layer) {
    const d = `M${x1} ${y1} C${x1 + 36} ${y1} ${x1 + 36} ${loopY} ${x1} ${loopY} L${x2} ${loopY} C${x2 - 36} ${loopY} ${x2 - 36} ${y2} ${x2} ${y2}`;
    return { d, segments: [], mid: { x: (x1 + x2) / 2, y: loopY + 2 }, back: true };
  }
  const pts: Pt[] = [{ x: x1, y: y1 }];
  for (let l = a.layer + 1; l < b.layer; l++) {
    const col = placed.filter((p) => p.layer === l).sort((p, q) => p.y - q.y);
    if (col.length === 0) continue;
    const lx = col[0]!.x;
    const cx = lx + W / 2;
    const want = y1 + ((y2 - y1) * (cx - x1)) / (x2 - x1);
    const gaps = [col[0]!.y - 12, ...col.slice(1).map((p, i) => (col[i]!.y + H + p.y) / 2)];
    gaps.push(col[col.length - 1]!.y + H + 12);
    const gy = gaps.reduce((best, g) => (Math.abs(g - want) < Math.abs(best - want) ? g : best));
    pts.push({ x: lx - 16, y: gy }, { x: lx + W + 16, y: gy });
  }
  pts.push({ x: x2, y: y2 });
  const segments: [Pt, Pt, Pt, Pt][] = [];
  for (let i = 1; i < pts.length; i++) {
    const p = pts[i - 1] as Pt;
    const q = pts[i] as Pt;
    const dx = Math.max(20, (q.x - p.x) / 2);
    segments.push([p, { x: p.x + dx, y: p.y }, { x: q.x - dx, y: q.y }, q]);
  }
  const d = `M${x1} ${y1}${segments.map((s) => ` C${s[1].x} ${s[1].y} ${s[2].x} ${s[2].y} ${s[3].x} ${s[3].y}`).join('')}`;
  const poly = sampleRoute(segments);
  const lens = poly.map((p, i) => (i ? Math.hypot(p.x - poly[i - 1]!.x, p.y - poly[i - 1]!.y) : 0));
  const half = lens.reduce((s, v) => s + v, 0) / 2;
  let run = 0;
  let mid = poly[0] as Pt;
  for (let i = 0; i < poly.length; i++) {
    run += lens[i] as number;
    if (run >= half) {
      mid = poly[i] as Pt;
      break;
    }
  }
  return { d, segments, mid, back: false };
}

const hit = (
  a: { x: number; y: number; w: number; h: number },
  b: { x: number; y: number; w: number; h: number },
): boolean => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

export interface LabelBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

const SHIFTS = [0, 12, -12, 24, -24];

/** Centre a box on the route midpoint, nudging vertically clear of nodes and earlier labels. */
export function placeLabel(
  mid: Pt,
  w: number,
  h: number,
  nodes: Placed[],
  taken: LabelBox[],
): LabelBox {
  const boxes = nodes.map((p) => ({ x: p.x, y: p.y, w: W, h: H }));
  let first: LabelBox | undefined;
  for (const s of SHIFTS) {
    const box = { x: mid.x - w / 2, y: mid.y - h / 2 + s, w, h };
    first ??= box;
    if (![...boxes, ...taken].some((o) => hit(box, o))) return box;
  }
  return first as LabelBox;
}

const TONES: readonly FlagTone[] = ['warn', 'bad', 'info'];
const LINE_CHARS = 19;

function toneOf(v: unknown): FlagTone | undefined {
  return TONES.find((t) => t === v);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Greedy word wrap to at most two lines; the second ends in an ellipsis when text remains. */
export function wrapLabel(text: string, max = LINE_CHARS): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let cur = '';
  for (let w of words) {
    while (w.length > max) {
      if (cur) {
        lines.push(cur);
        cur = '';
      }
      lines.push(w.slice(0, max));
      w = w.slice(max);
    }
    if (!cur) cur = w;
    else if (cur.length + 1 + w.length <= max) cur += ` ${w}`;
    else {
      lines.push(cur);
      cur = w;
    }
  }
  if (cur) lines.push(cur);
  if (lines.length <= 2) return lines.length ? lines : [''];
  return [lines[0] as string, truncate(lines.slice(1).join(' '), max)];
}

/** The finding: how many flows and how many places they start from. */
export function lineageFinding(flows: number, sources: number): string {
  if (flows === 0) return 'No flows yet';
  return `${flows} ${flows === 1 ? 'flow' : 'flows'} from ${sources} ${sources === 1 ? 'source' : 'sources'}`;
}

export class HenoyoLineageGraph extends HenoyoElement {
  private _heading: string | undefined;
  private _truncated = false;
  private _nodes: LineageNode[] = [];
  private _edges: LineageEdge[] = [];
  private _legend: LineageLegendItem[] = [];
  private readonly gid = Math.random().toString(36).slice(2, 8);
  /** The viewer's own Fit / 100% choice; unset means: full size on a narrow host so text stays legible. */
  private userNative: boolean | undefined;
  private get native(): boolean {
    return this.userNative ?? (this.clientWidth > 0 && this.clientWidth < 560);
  }
  private focusId: string | undefined;
  private refocus = false;

  constructor() {
    super();
    watchWidth(this, () => this.invalidate());
    const pick = (e: Event): string | undefined =>
      (e.target as Element).closest<HTMLElement>('[data-act="select"]')?.dataset.arg;
    this.root.addEventListener('keydown', (e) => this.onKey(e as KeyboardEvent, pick(e)));
    this.root.addEventListener('click', (e) => {
      const id = pick(e);
      if (id !== undefined) this.select(id);
      else if ((e.target as Element).closest('[data-act="fit"]')) {
        this.userNative = !this.native;
        this.invalidate();
      }
    });
    this.root.addEventListener('mouseover', (e) => this.highlight(pick(e)));
    this.root.addEventListener('mouseout', () => this.highlight(undefined));
    this.root.addEventListener('focusin', (e) => {
      const id = pick(e);
      if (id !== undefined) this.focusId = id;
      this.highlight(id);
    });
    this.root.addEventListener('focusout', () => this.highlight(undefined));
  }

  protected invalidate(): void {
    if (this.root.activeElement) this.refocus = true;
    super.invalidate();
  }

  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(v: boolean | undefined) {
    this._truncated = v === true;
    this.invalidate();
  }
  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v;
    this.invalidate();
  }
  get nodes(): LineageNode[] {
    return this._nodes;
  }
  set nodes(v: LineageNode[] | undefined) {
    this._nodes = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get edges(): LineageEdge[] {
    return this._edges;
  }
  set edges(v: LineageEdge[] | undefined) {
    this._edges = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get legend(): LineageLegendItem[] {
    return this._legend;
  }
  set legend(v: LineageLegendItem[] | undefined) {
    this._legend = Array.isArray(v) ? v : [];
    this.invalidate();
  }

  private cleanNodes(): LineageNode[] {
    const seen = new Set<string>();
    const out: LineageNode[] = [];
    for (const n of this._nodes) {
      if (!n || typeof n !== 'object' || !str(n.id) || seen.has(n.id)) continue;
      seen.add(n.id);
      out.push(n);
    }
    return out;
  }

  private cleanEdges(): LineageEdge[] {
    return this._edges.filter((e) => e && typeof e === 'object' && str(e.from) && str(e.to));
  }

  private highlight(id: string | undefined): void {
    const svg = this.root.querySelector('svg.graph');
    if (!svg) return;
    svg.classList.toggle('dim', id !== undefined);
    const linked = new Set<string>();
    if (id !== undefined) linked.add(id);
    svg.querySelectorAll<SVGElement>('.edge').forEach((el) => {
      const on = id !== undefined && (el.dataset.from === id || el.dataset.to === id);
      el.classList.toggle('on', on);
      if (on) {
        linked.add(el.dataset.from ?? '');
        linked.add(el.dataset.to ?? '');
      }
    });
    svg.querySelectorAll<SVGElement>('.node').forEach((el) => {
      el.classList.toggle('on', linked.has(el.dataset.arg ?? ''));
    });
  }

  private focusNode(id: string): void {
    this.focusId = id;
    let target: SVGElement | undefined;
    this.root.querySelectorAll<SVGElement>('.node').forEach((el) => {
      const hit = el.dataset.arg === id;
      el.setAttribute('tabindex', hit ? '0' : '-1');
      if (hit) target = el;
    });
    target?.focus();
  }

  private select(id: string): void {
    emit(this, 'henoyo:node-selected', { id });
    const node = this._nodes.find((n) => n.id === id);
    if (node?.objectApiName !== undefined && node.recordId !== undefined) {
      emit(this, 'henoyo:open-record', {
        objectApiName: node.objectApiName,
        recordId: node.recordId,
      });
    }
  }

  private onKey(e: KeyboardEvent, id: string | undefined): void {
    if (id === undefined) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      this.select(id);
      return;
    }
    const dir = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[
      e.key
    ];
    if (!dir) return;
    const all = [...this.root.querySelectorAll<SVGElement>('.node')].map((el) => ({
      id: el.dataset.arg ?? '',
      layer: Number(el.dataset.layer),
      y: Number(el.dataset.y),
    }));
    const cur = all.find((n) => n.id === id);
    if (!cur) return;
    e.preventDefault();
    let next: { id: string } | undefined;
    if (dir[0] !== 0) {
      const same = all.filter((n) => n.layer === cur.layer + (dir[0] as number));
      next = same.sort((a, b) => Math.abs(a.y - cur.y) - Math.abs(b.y - cur.y))[0];
    } else {
      const col = all.filter((n) => n.layer === cur.layer).sort((a, b) => a.y - b.y);
      next = col[col.findIndex((n) => n.id === id) + (dir[1] as number)];
    }
    if (next) this.focusNode(next.id);
  }

  protected afterRender(): void {
    if (!this.refocus) return;
    this.refocus = false;
    if (this.focusId) this.focusNode(this.focusId);
  }

  protected styles(): string {
    return `
.scroll { overflow-x:auto; padding:0 22px 8px; }
svg.graph { display:block; }
svg.graph.fit { width:100%; height:auto; }
svg.graph.native { max-width:none; }
.node rect.box { fill:var(--k-surface); stroke:var(--k-hairline); stroke-width:1; }
.node { cursor:pointer; }
.node:focus-visible { outline:2px solid var(--k-brand); outline-offset:2px; }
.node:focus-visible rect.box { stroke:var(--k-brand); stroke-width:2; }
.node text { fill:var(--k-text); font-size:12.5px; font-weight:600; }
.node text.sub { fill:var(--k-text-3); font-size:11px; font-weight:400; }
.band { fill:var(--k-surface-2); opacity:.6; stroke:var(--k-hairline); stroke-dasharray:2 4; }
.bandlbl { fill:var(--k-text-3); font-size:10.5px; letter-spacing:.1em; text-transform:uppercase; font-weight:600; }
.edge path { fill:none; stroke:var(--k-hairline-2); stroke-width:1.5; }
.edge.warn path { stroke:var(--k-warn); } .edge.bad path { stroke:var(--k-bad); } .edge.info path { stroke:var(--k-info); }
.edge .elbl { fill:var(--k-text-3); font-size:10.5px; text-anchor:middle; }
.edge .lblbg { fill:var(--k-surface); stroke:var(--k-hairline); stroke-width:1; }
.edge .pillbg { fill:var(--k-surface); stroke:currentColor; stroke-width:1; }
.edge.warn { color:var(--k-warn); } .edge.bad { color:var(--k-bad); } .edge.info { color:var(--k-info); }
.edge .pilltx { fill:currentColor; font-size:10.5px; font-weight:600; text-anchor:middle; }
svg.dim .edge { opacity:.18; } svg.dim .edge.on { opacity:1; }
svg.dim .node { opacity:.45; } svg.dim .node.on { opacity:1; }
.legend { display:flex; flex-wrap:wrap; gap:8px 16px; padding:6px 22px 16px; font-size:12px; }
.lg { display:inline-flex; align-items:center; gap:6px; }
.sw { width:26px; height:0; border-top:2px dashed currentColor; }
.lg.warn { color:var(--k-warn); } .lg.bad { color:var(--k-bad); } .lg.info { color:var(--k-info); }
.lg .t { color:var(--k-text-2); }
`;
  }

  private lineageHead(eyebrow: string, title: string, withFit: boolean): string {
    const fit = withFit
      ? `<button class="btn" type="button" data-act="fit" aria-pressed="${this.native}" aria-label="${this.native ? 'Fit graph to width' : 'Show graph at full size'}">${this.native ? 'Fit' : '100%'}</button>`
      : undefined;
    return this.head(eyebrow, title, fit === undefined ? {} : { actions: fit });
  }

  protected view(): string {
    const title = this._heading ?? 'Lineage';
    const nodes = this.cleanNodes();
    if (nodes.length === 0) return this.emptyCard('Flows', title);
    const placed = layoutLineage(nodes, this.cleanEdges());
    const at = new Map(placed.map((p) => [p.id, p]));
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const labelOf = (id: string): string => str(byId.get(id)?.label) ?? id;
    const width = Math.max(...placed.map((p) => p.x)) + W + PAD;
    const bottom = Math.max(...placed.map((p) => p.y)) + H;
    const inb = new Map<string, number>();
    const outb = new Map<string, number>();
    const edges = this.cleanEdges().filter((e) => at.has(e.from) && at.has(e.to));
    for (const e of edges) {
      outb.set(e.from, (outb.get(e.from) ?? 0) + 1);
      inb.set(e.to, (inb.get(e.to) ?? 0) + 1);
    }
    const backCount = edges.filter(
      (e) => (at.get(e.to)?.layer ?? 0) <= (at.get(e.from)?.layer ?? 0),
    ).length;
    const height = bottom + PAD + 12 + (backCount ? 30 + backCount * 10 : 0);

    const bands = layoutBands(nodes, placed)
      .map(
        (bd) =>
          `<g><rect class="band" x="${bd.x}" y="${bd.y}" width="${bd.width}" height="${bd.height}" rx="12"/><text class="bandlbl" x="${bd.x + 12}" y="${bd.y + 15}">${esc(bd.group)}</text></g>`,
      )
      .join('');

    const mid = (t: string): string => `ar-${this.gid}-${t}`;
    const marker = (t: string, fill: string): string =>
      `<marker id="${mid(t)}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="${fill}"/></marker>`;
    const markers = [
      marker('n', 'var(--k-hairline-2)'),
      ...TONES.map((t) => marker(t, `var(--k-${t})`)),
    ].join('');

    let backIdx = 0;
    const taken: LabelBox[] = [];
    const edgeSvg = edges
      .map((e) => {
        const a = at.get(e.from) as Placed;
        const b = at.get(e.to) as Placed;
        const route = routeEdge(
          a,
          b,
          placed,
          bottom + 22 + (b.layer <= a.layer ? backIdx++ * 10 : 0),
        );
        const flag = e.flag && typeof e.flag === 'object' ? e.flag : undefined;
        const flagLabel = str(flag?.label);
        const tone = toneOf(flag?.tone);
        const dash = tone ? ' stroke-dasharray="6 4"' : '';
        const text = str(e.label) ? truncate(e.label as string, 24) : '';
        const textW = text.length * 5.8 + 8;
        const pillW = flagLabel ? flagLabel.length * 6.2 + 14 : 0;
        const bh = (text ? 14 : 0) + (flagLabel ? 18 : 0);
        let tags = '';
        if (bh) {
          const above = { x: route.mid.x, y: route.mid.y - bh / 2 - 10 };
          const box = placeLabel(above, Math.max(textW, pillW), bh, placed, taken);
          taken.push(box);
          const cx = box.x + box.w / 2;
          const label = text
            ? `<rect class="lblbg" x="${cx - textW / 2}" y="${box.y - 1}" width="${textW}" height="14" rx="7"/><text class="elbl" x="${cx}" y="${box.y + 9.5}">${esc(text)}</text>`
            : '';
          const py = box.y + (text ? 14 : 0);
          const pill = flagLabel
            ? `<rect class="pillbg" x="${cx - pillW / 2}" y="${py + 1}" width="${pillW}" height="16" rx="8"/><text class="pilltx" x="${cx}" y="${py + 12.5}">${esc(flagLabel)}</text>`
            : '';
          tags = label + pill;
        }
        return `<g class="edge${tone ? ` ${tone}` : ''}${route.back ? ' back' : ''}" data-from="${esc(e.from)}" data-to="${esc(e.to)}"><path d="${route.d}"${dash} marker-end="url(#${mid(tone ?? 'n')})"/>${tags}</g>`;
      })
      .join('');

    const focusId = byId.has(this.focusId ?? '') ? this.focusId : placed[0]?.id;
    const nodeSvg = placed
      .map((p) => {
        const n = byId.get(p.id) as LineageNode;
        const label = labelOf(n.id);
        const sub = str(n.sublabel);
        const [bg, fg] = MATERIALS[isMaterial(n.material) ? n.material : 'stone'];
        const aria = `${label}, ${inb.get(n.id) ?? 0} inbound, ${outb.get(n.id) ?? 0} outbound`;
        const lines = wrapLabel(label);
        const top = (H - (lines.length * 15 + (sub ? 14 : 0))) / 2;
        const tspans = lines
          .map((l, i) => `<tspan x="48" y="${top + 12 + i * 15}">${esc(l)}</tspan>`)
          .join('');
        return `<g class="node" data-act="select" data-arg="${esc(n.id)}" data-layer="${p.layer}" data-x="${p.x}" data-y="${p.y}" transform="translate(${p.x} ${p.y})" tabindex="${n.id === focusId ? 0 : -1}" role="button" aria-label="${esc(aria)}">
          <title>${esc(sub ? `${label} - ${sub}` : label)}</title>
          <rect class="box" width="${W}" height="${H}" rx="10"/>
          <rect x="10" y="${(H - 28) / 2}" width="28" height="28" rx="6" fill="${bg}"/>
          <g style="color:${fg}" transform="translate(16 ${(H - 16) / 2})">${glyph(n.glyphName, 16)}</g>
          <text>${tspans}</text>
          ${sub ? `<text class="sub" x="48" y="${top + lines.length * 15 + 11}">${esc(truncate(sub, 24))}</text>` : ''}
        </g>`;
      })
      .join('');

    const srList = edges
      .map((e) => {
        const fl = e.flag && typeof e.flag === 'object' ? str(e.flag.label) : undefined;
        return `<li>${esc(labelOf(e.from))} → ${esc(labelOf(e.to))}${fl ? ` (${esc(fl)})` : ''}</li>`;
      })
      .join('');

    const legend = this._legend.filter((l) => l && str(l.label) && toneOf(l.tone));
    const legendHtml = legend.length
      ? `<div class="legend">${legend.map((l) => `<span class="lg ${esc(l.tone)}"><span class="sw"></span><span class="t">${esc(l.label)}</span></span>`).join('')}</div>`
      : '';

    const sources = new Set(edges.filter((e) => !inb.has(e.from)).map((e) => e.from));
    const origins = sources.size > 0 ? sources.size : outb.size;
    const finding = lineageFinding(edges.length, origins);
    const svgStyle = this.native ? '' : ` style="max-width:${width}px"`;
    return `<section class="card" aria-label="${esc(title)}">
      ${this.lineageHead(title, finding, true)}
      <div class="scroll"><svg class="graph ${this.native ? 'native' : 'fit'}"${this.native ? ` width="${width}" height="${height}"` : svgStyle} viewBox="0 0 ${width} ${height}" role="group" aria-label="${esc(title)}"><defs>${markers}</defs>${bands}${edgeSvg}${nodeSvg}</svg></div>
      ${legendHtml}
      <ul class="sr" aria-label="Flows">${srList}</ul>
    ${this.foot(truncatedSpan(this._truncated))}</section>`;
  }
}

defineElement('henoyo-lineage-graph', HenoyoLineageGraph);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-lineage-graph': HenoyoLineageGraph;
  }
}
