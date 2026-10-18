// <henoyo-discovery-trend>: counts over time, stacked by a second grouping.
// Zero baseline, straight segments, Editorial severity and material colours.

import {
  HenoyoElement,
  compact,
  defineElement,
  esc,
  finite,
  legend,
  truncatedSpan,
  type KitStat,
} from './henoyoKit';
import { fmt, plotWidth, severityOf, solidFill, watchWidth } from './vizPalette';

export interface TrendPeriod {
  key: string;
  label: string;
}

export interface TrendSeries {
  key: string;
  label: string;
  fill: string;
  stroke: string;
  outline: boolean;
  values: number[];
}

const VIEW_H = 240;
const PAD = { l: 40, r: 12, t: 12, b: 28 };

function tickStep(max: number): number {
  const raw = Math.max(max / 4, 1);
  const pow = 10 ** Math.floor(Math.log10(raw));
  const n = raw / pow;
  const nice = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return Math.max(1, nice * pow);
}

function num(value: unknown): number {
  const n = finite(value);
  return n === null || n < 0 ? 0 : n;
}

/** The finding: how the latest period compares with the one before it. */
export function trendFinding(totals: readonly number[]): string {
  const now = totals[totals.length - 1] ?? 0;
  if (totals.length < 2) return `${fmt(now)} in the only period`;
  const prev = totals[totals.length - 2] ?? 0;
  if (prev === 0) {
    return now === 0
      ? 'No change vs previous period (0 now)'
      : `Up from none vs previous period (${fmt(now)} now)`;
  }
  const pct = Math.round(((now - prev) / prev) * 100);
  const sign = pct > 0 ? '+' : pct < 0 ? '−' : '';
  return `${sign}${Math.abs(pct)}% vs previous period (${fmt(now)} now)`;
}

export class HenoyoDiscoveryTrend extends HenoyoElement {
  private _heading = 'Discoveries';
  private _periods: TrendPeriod[] = [];
  private _series: TrendSeries[] = [];
  private _truncated = false;
  private _xs: number[] = [];
  private _w = 640;

  constructor() {
    super();
    watchWidth(this, () => this.invalidate());
    this.root.addEventListener('mousemove', (event) => this.onMove(event));
    this.root.addEventListener('mouseleave', () => this.showNote(''));
  }

  get heading(): string {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v && v.trim() !== '' ? v : 'Discoveries';
    this.invalidate();
  }
  get periods(): TrendPeriod[] {
    return this._periods;
  }
  set periods(v: TrendPeriod[] | undefined) {
    this._periods = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get series(): TrendSeries[] {
    return this._series;
  }
  set series(v: TrendSeries[] | undefined) {
    this._series = Array.isArray(v) ? v : [];
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
    return `.area { stroke:var(--k-surface); stroke-width:1.5; }
`;
  }

  protected view(): string {
    const periods = this._periods.filter((p) => p && typeof p.label === 'string');
    const series = this._series
      .filter((s) => s && typeof s.label === 'string')
      .map((s) => ({
        ...s,
        values: periods.map((_, i) => num(s.values?.[i])),
      }));
    if (periods.length === 0 || series.length === 0) {
      return this.emptyCard(
        this._heading,
        'Nothing to show yet',
        'No records match this report yet.',
      );
    }

    const totals = periods.map((_, i) => series.reduce((sum, s) => sum + (s.values[i] ?? 0), 0));
    const last = periods.length - 1;
    const hot = series.reduce((sum, s) => {
      const band = severityOf(s.key);
      return band === 'critical' || band === 'high' ? sum + (s.values[last] ?? 0) : sum;
    }, 0);
    const stats: KitStat[] = series.some((s) => severityOf(s.key) !== undefined)
      ? [{ text: `${fmt(hot)} critical or high now`, tone: hot > 0 ? 'bad' : 'ok' }]
      : [];
    this._w = plotWidth(this);
    const plot = this.plot(periods, series, Math.max(...totals, 0));
    const key = legend(
      [...series].reverse().map((s) => {
        const mark = solidFill(s);
        return {
          label: s.label,
          color: mark.color,
          count: fmt(s.values[last] ?? 0),
          swatchStyle: `opacity:${mark.opacity}`,
        };
      }),
    );
    return `<div class="card">${this.head(this._heading, trendFinding(totals), { stats })}<div class="body">${plot}${key}<p class="note"></p>${this.table(periods, series)}</div>${this.foot(truncatedSpan(this._truncated))}</div>`;
  }

  private plot(periods: TrendPeriod[], series: TrendSeries[], max: number): string {
    const innerW = this._w - PAD.l - PAD.r;
    const innerH = VIEW_H - PAD.t - PAD.b;
    const ceiling = max <= 0 ? 1 : max;
    const yOf = (v: number): number => PAD.t + innerH - (v / ceiling) * innerH;
    const xOf = (i: number): number =>
      periods.length === 1 ? PAD.l + innerW / 2 : PAD.l + (i / (periods.length - 1)) * innerW;
    this._xs = periods.map((_, i) => xOf(i));

    const step = tickStep(ceiling);
    let grid = '';
    for (let v = 0; v <= ceiling; v += step) {
      const y = yOf(v);
      grid += `<line class="grid" x1="${PAD.l}" y1="${y.toFixed(1)}" x2="${this._w - PAD.r}" y2="${y.toFixed(1)}"></line>`;
      grid += `<text class="axis" x="${PAD.l - 6}" y="${y.toFixed(1)}" text-anchor="end" dominant-baseline="middle">${compact(v)}</text>`;
    }
    const base = yOf(0);
    grid += `<line class="base" x1="${PAD.l}" y1="${base.toFixed(1)}" x2="${this._w - PAD.r}" y2="${base.toFixed(1)}"></line>`;

    const lower = periods.map(() => 0);
    let areas = '';
    for (const s of series) {
      const upper = s.values.map((v, i) => (lower[i] ?? 0) + v);
      const mark = solidFill(s);
      areas += `<path class="area" d="${this.band(xOf, yOf, lower, upper)}" fill="${esc(mark.color)}" fill-opacity="${mark.opacity}"></path>`;
      upper.forEach((v, i) => {
        lower[i] = v;
      });
    }

    const labelStep = Math.ceil(periods.length / Math.max(2, Math.floor(innerW / 80)));
    let labels = '';
    periods.forEach((p, i) => {
      if (i % labelStep !== 0 && i !== periods.length - 1) return;
      const edge =
        periods.length > 1 ? (i === 0 ? 'start' : i === periods.length - 1 ? 'end' : '') : '';
      labels += `<text class="axis" x="${xOf(i).toFixed(1)}" y="${VIEW_H - 8}" text-anchor="${edge === '' ? 'middle' : edge}">${esc(p.label)}</text>`;
    });
    const cursor = `<line id="cursor" class="base" x1="0" y1="${PAD.t}" x2="0" y2="${base.toFixed(1)}" visibility="hidden"></line>`;
    return `<svg class="plot" viewBox="0 0 ${this._w} ${VIEW_H}" role="img" aria-label="${esc(this._heading)}">${grid}${areas}${labels}${cursor}</svg>`;
  }

  private band(
    xOf: (i: number) => number,
    yOf: (v: number) => number,
    lower: number[],
    upper: number[],
  ): string {
    const n = upper.length;
    if (n === 1) {
      const x = xOf(0);
      const half = 28;
      const y0 = yOf(lower[0] ?? 0);
      const y1 = yOf(upper[0] ?? 0);
      return `M${(x - half).toFixed(1)},${y0.toFixed(1)} L${(x - half).toFixed(1)},${y1.toFixed(1)} L${(x + half).toFixed(1)},${y1.toFixed(1)} L${(x + half).toFixed(1)},${y0.toFixed(1)} Z`;
    }
    const top = upper
      .map((v, i) => `${i === 0 ? 'M' : 'L'}${xOf(i).toFixed(1)},${yOf(v).toFixed(1)}`)
      .join(' ');
    const bottom = [...lower]
      .reverse()
      .map((v, i) => `L${xOf(n - 1 - i).toFixed(1)},${yOf(v).toFixed(1)}`)
      .join(' ');
    return `${top} ${bottom} Z`;
  }

  private table(periods: TrendPeriod[], series: TrendSeries[]): string {
    const head = periods.map((p) => `<th>${esc(p.label)}</th>`).join('');
    const rows = series
      .map((s) => {
        const cells = s.values.map((v) => `<td>${fmt(v)}</td>`).join('');
        return `<tr><th>${esc(s.label)}</th>${cells}</tr>`;
      })
      .join('');
    return `<table class="clip"><caption>${esc(this._heading)}</caption><thead><tr><th>Band</th>${head}</tr></thead><tbody>${rows}</tbody></table>`;
  }

  private onMove(event: Event): void {
    const svg = this.root.querySelector('svg.plot');
    if (
      !(svg instanceof SVGSVGElement) ||
      this._xs.length === 0 ||
      !(event instanceof MouseEvent)
    ) {
      return;
    }
    const rect = svg.getBoundingClientRect();
    if (rect.width === 0) return;
    const x = ((event.clientX - rect.left) / rect.width) * this._w;
    let best = 0;
    let bestD = Number.POSITIVE_INFINITY;
    this._xs.forEach((px, i) => {
      const d = Math.abs(px - x);
      if (d < bestD) {
        bestD = d;
        best = i;
      }
    });
    const cursor = this.root.querySelector('#cursor');
    const at = this._xs[best];
    if (cursor instanceof Element && at !== undefined) {
      cursor.setAttribute('x1', String(at));
      cursor.setAttribute('x2', String(at));
      cursor.setAttribute('visibility', 'visible');
    }
    this.showNote(this.periodSentence(best));
  }

  private periodSentence(i: number): string {
    const period = this._periods[i];
    if (period === undefined) return '';
    const parts = this._series
      .map((s) => ({ label: s.label, value: num(s.values?.[i]) }))
      .filter((part) => part.value > 0)
      .map((part) => `${part.label} ${fmt(part.value)}`);
    return `${period.label} — ${parts.length === 0 ? 'none' : parts.join(', ')}.`;
  }

  private showNote(text: string): void {
    const note = this.root.querySelector('.note');
    if (note) note.textContent = text;
    if (text === '') this.root.querySelector('#cursor')?.setAttribute('visibility', 'hidden');
  }
}

defineElement('henoyo-discovery-trend', HenoyoDiscoveryTrend);
