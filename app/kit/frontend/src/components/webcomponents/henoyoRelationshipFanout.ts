// <henoyo-relationship-fanout>: the open record at the centre, each hop a ring of records coloured by type.

import { HenoyoElement, defineElement, esc, legend, truncatedSpan } from './henoyoKit';
import { openAttrs, wireRecordOpen, type VizEdge, type VizNode } from './vizGraph';
import { plotWidth, watchWidth } from './vizPalette';

const H = 260;
const RESERVE = 128;
const LINE = 18;

/** The finding: how many records the open one reaches, and across how many kinds. */
export function fanoutFinding(nodes: readonly Pick<VizNode, 'ring' | 'objectApiName'>[]): string {
  const far = nodes.filter((node) => node.ring > 0);
  const types = new Set(far.map((node) => node.objectApiName)).size;
  return `Connected to ${far.length} record${far.length === 1 ? '' : 's'} across ${types} type${types === 1 ? '' : 's'}`;
}

export class HenoyoRelationshipFanout extends HenoyoElement {
  private _heading = 'Relationships';
  private _nodes: VizNode[] = [];
  private _edges: VizEdge[] = [];
  private _truncated = false;

  constructor() {
    super();
    watchWidth(this, () => this.invalidate());
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
    this._heading = v && v.trim() !== '' ? v : 'Relationships';
    this.invalidate();
  }
  get nodes(): VizNode[] {
    return this._nodes;
  }
  set nodes(v: VizNode[] | undefined) {
    this._nodes = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get edges(): VizEdge[] {
    return this._edges;
  }
  set edges(v: VizEdge[] | undefined) {
    this._edges = Array.isArray(v) ? v : [];
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
    return `.node { cursor:pointer; }
.label { font-size:12px; fill:var(--k-text); paint-order:stroke; stroke:var(--k-surface); stroke-width:3px; stroke-linejoin:round; }
.edge { fill:none; stroke-width:1.5; opacity:.6; }
.names { list-style:none; margin:10px 0 0; padding:0; display:flex; flex-wrap:wrap; gap:6px; }
.names li { font-size:12px; line-height:1.3; padding:3px 9px; border:1px solid var(--k-hairline-2); border-radius:999px; color:var(--k-text); max-width:100%; overflow-wrap:break-word; min-width:0; }
.names li[data-act] { cursor:pointer; }
`;
  }

  private sideLabel(node: Placed, right: boolean): string {
    const lines = wrap(node.label);
    const x = node.x + (right ? 12 : -12);
    const first = node.y + 4 - (lines.length - 1) * 7;
    const spans = lines
      .map((line, i) => `<tspan x="${x}" y="${first + i * 14}">${esc(line)}</tspan>`)
      .join('');
    return `<text class="label" text-anchor="${right ? 'start' : 'end'}">${spans}</text>`;
  }

  protected view(): string {
    const nodes = this._nodes.filter((node) => node && typeof node.label === 'string');
    const root = nodes.find((node) => node.ring === 0);
    const far = nodes.filter((node) => node.ring > 0);
    if (root === undefined || far.length === 0) {
      return this.emptyCard(
        this._heading,
        'Nothing connected yet',
        'This record is not linked to any other records yet.',
      );
    }
    const sch = this.scheme();
    const types = [...new Set(far.map((node) => node.objectApiName))];
    const paintOf = (node: VizNode): { fill: string; stroke: string } => {
      if (node.ring === 0) return { fill: sch.accent, stroke: sch.accent };
      const paint = sch.series[types.indexOf(node.objectApiName) % sch.series.length] ?? sch.other;
      return { fill: paint.fill, stroke: paint.stroke };
    };
    const width = plotWidth(this);
    const narrow = width < 460;
    const placed = place(nodes, width);
    const at = new Map(placed.map((node) => [node.id, node]));
    const lines = this._edges
      .map((edge) => {
        const from = at.get(edge.from);
        const to = at.get(edge.to);
        if (from === undefined || to === undefined) return '';
        const mid = (from.x + to.x) / 2;
        return `<path class="edge" stroke="${esc(paintOf(to).stroke)}" d="M ${from.x} ${from.y} C ${mid} ${from.y} ${mid} ${to.y} ${to.x} ${to.y}"></path>`;
      })
      .join('');
    const marks = placed
      .map((node) => {
        const paint = paintOf(node);
        const r = node.ring === 0 ? 11 : 7;
        const right = node.x >= width / 2;
        const label =
          !node.labelled || (narrow && node.ring > 0)
            ? ''
            : node.ring === 0
              ? `<text class="label" x="${node.x}" y="${node.y + 26}" text-anchor="middle">${esc(short(node.label))}</text>`
              : this.sideLabel(node, right);
        return `<g class="node" data-tip="${esc(node.tip || node.label)}"${openAttrs(node)}><circle cx="${node.x}" cy="${node.y}" r="${r}" fill="${esc(paint.fill)}" stroke="${esc(paint.stroke)}" stroke-width="1.5"></circle>${label}</g>`;
      })
      .join('');
    const names = `<ul class="names" aria-label="Connected records">${far
      .map(
        (node) =>
          `<li data-tip="${esc(node.tip || node.label)}"${openAttrs(node)}>${esc(node.label)}</li>`,
      )
      .join('')}</ul>`;
    const key = legend(
      types.map((type, index) => {
        const group = far.filter((node) => node.objectApiName === type);
        const paint = sch.series[index % sch.series.length] ?? sch.other;
        return { label: group[0]?.typeLabel ?? type, color: paint.stroke, count: group.length };
      }),
    );
    return `<div class="card">${this.head(this._heading, fanoutFinding(nodes), { sub: 'Select a record to open it.' })}<div class="body"><svg class="plot" viewBox="0 0 ${width} ${H}" role="img" aria-label="${esc(`${this._heading}. ${fanoutFinding(nodes)}`)}">${lines}${marks}</svg>${key}${narrow ? names : ''}<p class="note"></p></div>${this.foot(truncatedSpan(this._truncated))}</div>`;
  }
}

interface Placed extends VizNode {
  x: number;
  y: number;
  labelled: boolean;
}

function place(nodes: VizNode[], width: number): Placed[] {
  const cx = width / 2;
  const cy = H / 2;
  const rings = Math.max(1, ...nodes.map((node) => node.ring));
  const rxMax = Math.max(60, cx - RESERVE);
  const ryMax = cy - 22;
  const byRing = new Map<number, VizNode[]>();
  for (const node of nodes) {
    const ring = byRing.get(node.ring) ?? [];
    ring.push(node);
    byRing.set(node.ring, ring);
  }
  const placed: Placed[] = [];
  for (const [ring, group] of byRing) {
    group.forEach((node, index) => {
      if (ring === 0) {
        placed.push({ ...node, x: cx, y: cy, labelled: true });
        return;
      }
      const angle = (index / group.length) * Math.PI * 2 - Math.PI / 2 + ring * 0.4;
      placed.push({
        ...node,
        x: Math.round(cx + ((rxMax * ring) / rings) * Math.cos(angle)),
        y: Math.round(cy + ((ryMax * ring) / rings) * Math.sin(angle)),
        labelled: group.length <= 14,
      });
    });
  }
  return placed;
}

function wrap(label: string): string[] {
  const words = label.split(/\s+/).filter((w) => w !== '');
  const lines: string[] = [];
  let line = '';
  for (const word of words) {
    if (line !== '' && line.length + 1 + word.length > LINE) {
      lines.push(line);
      line = word;
    } else {
      line = line === '' ? word : `${line} ${word}`;
    }
  }
  if (line !== '') lines.push(line);
  if (lines.length <= 2) return lines;
  const rest = lines.slice(1).join(' ');
  return [lines[0] ?? '', rest.length > LINE ? `${rest.slice(0, LINE - 1)}…` : rest];
}

function short(label: string): string {
  return label.length > 16 ? `${label.slice(0, 15)}…` : label;
}

defineElement('henoyo-relationship-fanout', HenoyoRelationshipFanout);
