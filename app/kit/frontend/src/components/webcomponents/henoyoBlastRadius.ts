// <henoyo-blast-radius>: the open record in the centre, each hop a ring of equal arcs. The nearest ring is the accent.

import {
  HenoyoElement,
  defineElement,
  esc,
  legend,
  truncatedSpan,
  type KitStat,
} from './henoyoKit';
import { openAttrs, wireRecordOpen, type VizNode } from './vizGraph';

const HUB = 36;
const BAND = 24;
const PITCH = 29;
const MAX_SIZE = 260;
const FADE = [1, 0.5, 0.32, 0.2];

/** The finding: how many records are in reach and how many hops it takes to reach them all. */
export function blastFinding(nodes: readonly Pick<VizNode, 'ring'>[]): string {
  const far = nodes.filter((node) => node.ring > 0);
  const hops = Math.max(0, ...far.map((node) => node.ring));
  return `${far.length} record${far.length === 1 ? '' : 's'} within ${hops} hop${hops === 1 ? '' : 's'}`;
}

export class HenoyoBlastRadius extends HenoyoElement {
  private _heading = 'Blast radius';
  private _nodes: VizNode[] = [];
  private _truncated = false;

  constructor() {
    super();
    wireRecordOpen(this.root, this);
    this.root.addEventListener('mouseover', (event) => {
      const raw = event.target;
      if (!(raw instanceof Element)) return;
      const node = raw.closest('[data-tip]');
      const note = this.root.querySelector('.note');
      if (note) note.textContent = node?.getAttribute('data-tip') ?? '';
    });
  }

  get heading(): string {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v && v.trim() !== '' ? v : 'Blast radius';
    this.invalidate();
  }
  get nodes(): VizNode[] {
    return this._nodes;
  }
  set nodes(v: VizNode[] | undefined) {
    this._nodes = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(v: boolean | undefined) {
    this._truncated = v === true;
    this.invalidate();
  }

  protected styles(): string {
    return `.wrap { display:flex; flex-wrap:wrap; align-items:center; gap:12px 28px; }
.wrap svg.plot { flex:none; max-width:100%; }
.wrap .legend { flex-direction:column; margin:0; }
.arc { cursor:pointer; stroke:var(--k-surface); stroke-width:1; }
.ring-1 { fill:var(--k-accent); }
.ring-2, .ring-3, .ring-4 { fill:var(--k-text-3); }
.ring-2 { opacity:.5; } .ring-3 { opacity:.32; } .ring-4 { opacity:.2; }
.hub { font-size:12px; fill:var(--k-text); }
`;
  }

  protected view(): string {
    const nodes = this._nodes.filter((node) => node && typeof node.label === 'string');
    const root = nodes.find((node) => node.ring === 0);
    const far = nodes.filter((node) => node.ring > 0);
    if (root === undefined || far.length === 0) {
      return this.emptyCard(
        this._heading,
        'Nothing in reach yet',
        'This record is not linked to any other records yet.',
      );
    }
    const rings = new Map<number, VizNode[]>();
    for (const node of far) {
      const group = rings.get(node.ring) ?? [];
      group.push(node);
      rings.set(node.ring, group);
    }
    const hops = Math.max(...rings.keys());
    const half = HUB + 4 + hops * PITCH;
    let arcs = '';
    for (const [ring, group] of [...rings].sort((a, b) => a[0] - b[0])) {
      const inner = HUB + 4 + (ring - 1) * PITCH;
      const step = (Math.PI * 2) / group.length;
      const klass = `arc ring-${Math.min(ring, FADE.length)}`;
      group.forEach((node, index) => {
        const a0 = -Math.PI / 2 + index * step + 0.03;
        const a1 = -Math.PI / 2 + (index + 1) * step - 0.03;
        arcs += `<path class="${klass}" d="${donut(half, inner, inner + BAND, a0, a1)}" data-tip="${esc(node.tip || node.label)}"${openAttrs(node)}><title>${esc(node.label)}</title></path>`;
      });
    }
    const hub = `<circle cx="${half}" cy="${half}" r="${HUB}" fill="var(--k-surface-2)" stroke="var(--k-hairline-2)"></circle><text class="hub" x="${half}" y="${half}" text-anchor="middle" dominant-baseline="middle">${esc(short(root.label))}</text>`;
    const key = legend(
      [...rings]
        .sort((a, b) => a[0] - b[0])
        .map(([ring, group]) => ({
          label: `${ring} hop${ring === 1 ? '' : 's'}`,
          color: ring === 1 ? 'var(--k-accent)' : 'var(--k-text-3)',
          count: group.length,
          swatchStyle: `opacity:${FADE[Math.min(ring, FADE.length) - 1]}`,
        })),
    );
    const hot = far.filter(
      (node) => node.severity === 'critical' || node.severity === 'high',
    ).length;
    const stats: KitStat[] = hot > 0 ? [{ text: `${hot} critical or high`, tone: 'bad' }] : [];
    const finding = blastFinding(nodes);
    const size = Math.min(MAX_SIZE, half * 2);
    return `<div class="card">${this.head(this._heading, finding, { stats, sub: 'Select a segment to open the record.' })}<div class="body"><div class="wrap"><svg class="plot" viewBox="0 0 ${half * 2} ${half * 2}" style="width:${size}px" role="img" aria-label="${esc(`${this._heading}. ${finding}`)}">${arcs}${hub}</svg>${key}</div><p class="note"></p></div>${this.foot(truncatedSpan(this._truncated))}</div>`;
  }
}

function donut(c: number, inner: number, outer: number, a0: number, a1: number): string {
  const p = (radius: number, angle: number): string => {
    const x = c + radius * Math.cos(angle);
    const y = c + radius * Math.sin(angle);
    return `${x.toFixed(1)} ${y.toFixed(1)}`;
  };
  const large = a1 - a0 > Math.PI ? 1 : 0;
  return `M ${p(outer, a0)} A ${outer} ${outer} 0 ${large} 1 ${p(outer, a1)} L ${p(inner, a1)} A ${inner} ${inner} 0 ${large} 0 ${p(inner, a0)} Z`;
}

function short(label: string): string {
  return label.length > 10 ? `${label.slice(0, 9)}…` : label;
}

defineElement('henoyo-blast-radius', HenoyoBlastRadius);
