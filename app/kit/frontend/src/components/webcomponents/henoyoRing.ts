// <henoyo-ring>: parts of a whole as a donut, with an optional target on one part.

import { kitLocale } from './colourScheme';
import {
  HenoyoElement,
  defineElement,
  emit,
  esc,
  finite,
  oneOf,
  truncatedSpan,
  type KitStat,
} from './henoyoKit';

export type HenoyoRingTone =
  | 'ok'
  | 'warn'
  | 'bad'
  | 'info'
  | 'neutral'
  | 'sev-critical'
  | 'sev-high'
  | 'sev-medium'
  | 'sev-low'
  | 'sev-info';

export interface HenoyoRingPart {
  label: string;
  count: number;
  tone?: HenoyoRingTone;
}

export interface HenoyoRingTarget {
  label: string;
  percent: number;
  /** Which part the target measures. */
  partLabel: string;
}

// Severity tones keep Core's severity colours (palette rule: severity keeps its own colours).
const TONES: readonly HenoyoRingTone[] = [
  'ok',
  'warn',
  'bad',
  'info',
  'neutral',
  'sev-critical',
  'sev-high',
  'sev-medium',
  'sev-low',
  'sev-info',
];
const NEUTRAL_SHADES = [0.9, 0.62, 0.42, 0.28, 0.2];
const R = 40;
const C = 2 * Math.PI * R;
const GAP = 2;

const fmtN = (n: number): string => n.toLocaleString(kitLocale());
const totalSize = (text: string): number => Math.min(34, Math.floor(80 / (text.length * 0.56)));

const fmtPct = (n: number): string => `${Math.round(n * 10) / 10}%`;

/** The finding: the largest part and its share of the whole. */
export function ringFinding(parts: readonly { label: string; count: number }[]): string {
  const total = parts.reduce((sum, p) => sum + p.count, 0);
  const top = parts.reduce<{ label: string; count: number } | null>(
    (best, p) => (best === null || p.count > best.count ? p : best),
    null,
  );
  if (top === null || total <= 0) return 'Nothing counted yet';
  return `${top.label} is ${Math.round((top.count / total) * 100)}% of ${fmtN(total)}`;
}

export class HenoyoRing extends HenoyoElement {
  private _heading: string | undefined;
  private _truncated = false;
  private _parts: HenoyoRingPart[] = [];
  private _target: HenoyoRingTarget | undefined;
  private _centerLabel: string | undefined;
  /** Docket patch: a host-written finding that replaces the computed "largest part" title. */
  private _finding: string | undefined;
  /** Docket patch: false drops the percentage column; counts of applications read better as counts. */
  private _showPercent = true;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as Element | null)?.closest<HTMLElement>('[data-act]');
      if (target?.dataset.act === 'part')
        emit(this, 'henoyo:part-selected', { label: target.dataset.arg ?? '' });
    });
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
  get parts(): HenoyoRingPart[] {
    return this._parts;
  }
  set parts(v: HenoyoRingPart[]) {
    this._parts = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get target(): HenoyoRingTarget | undefined {
    return this._target;
  }
  set target(v: HenoyoRingTarget | undefined) {
    this._target = v;
    this.invalidate();
  }
  set showPercent(v: boolean | undefined) {
    this._showPercent = v !== false;
    this.invalidate();
  }
  get finding(): string | undefined {
    return this._finding;
  }
  set finding(v: string | undefined) {
    this._finding = v;
    this.invalidate();
  }
  get centerLabel(): string | undefined {
    return this._centerLabel;
  }
  set centerLabel(v: string | undefined) {
    this._centerLabel = v;
    this.invalidate();
  }

  protected styles(): string {
    return `
.wrap { display:grid; grid-template-columns:auto minmax(0,1fr); gap:calc(var(--h-kit-gap, 12px) + 4px) 28px; align-items:center; }
@media (max-width: 480px) { .wrap { grid-template-columns:1fr; justify-items:center; } .legend { width:100%; } }
.donut { position:relative; width:180px; height:180px; }
.donut svg { width:100%; height:100%; display:block; }
.mid { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; }
.total { font-family:var(--k-serif); font-size:34px; line-height:1; font-weight:500; }
.cl { margin-top:4px; font-size:11.5px; color:var(--k-text-3); max-width:90px; }
.legend { display:block; list-style:none; margin:0; padding:0; min-width:0; }
.row { display:grid; grid-template-columns:10px minmax(0,1fr) auto auto;  gap:10px; align-items:center; width:100%; min-height:28px; padding:2px 4px;
  background:none; border:0; text-align:left; cursor:pointer; font-size:12px; border-radius:6px; }
.row:hover { background:var(--k-surface-2); }
.num { font-variant-numeric:tabular-nums; font-weight:600; }
.pc { font-variant-numeric:tabular-nums; color:var(--k-text-3); min-width:44px; text-align:right; }
.tc { margin-top:4px; font-size:11px; font-weight:600; color:var(--k-text-2); max-width:96px; }
.seg { fill:none; stroke-width:14; }
.tickm { stroke:var(--k-text); stroke-width:2; }
`;
  }

  protected view(): string {
    const clean: { label: string; count: number; tone: HenoyoRingTone | undefined }[] = [];
    for (const p of this._parts) {
      const count = p ? finite(p.count) : null;
      if (!p || count === null || count < 0) continue;
      clean.push({
        label: String(p.label ?? ''),
        count,
        tone: p.tone === undefined ? undefined : oneOf(p.tone, TONES, 'neutral'),
      });
    }
    const total = clean.reduce((s, p) => s + p.count, 0);
    const eyebrow = this._heading ?? 'Distribution';
    if (clean.length === 0) return this.emptyCard('Breakdown', eyebrow);

    const largest = clean.reduce(
      (best, p, i) => (p.count > (clean[best]?.count ?? -1) ? i : best),
      0,
    );
    let neutralIdx = 0;
    const toned = clean.map((p, i) => {
      const accent = p.tone === undefined && i === largest && total > 0;
      return {
        ...p,
        tone: accent ? 'accent' : (p.tone ?? 'neutral'),
        opacity:
          p.tone === undefined || p.tone === 'neutral'
            ? accent
              ? 1
              : NEUTRAL_SHADES[Math.min(neutralIdx++, NEUTRAL_SHADES.length - 1)]!
            : 1,
        pct: total === 0 ? 0 : (p.count / total) * 100,
      };
    });
    const visibleCount = toned.filter((x) => x.count > 0).length;
    let offset = 0;
    const segs = toned
      .filter((p) => p.count > 0)
      .map((p) => {
        const len = (p.count / total) * C;
        const visible = visibleCount > 1 ? Math.max(0.5, len - GAP) : len;
        const svg = `<circle class="seg" cx="50" cy="50" r="${R}" stroke="var(--k-${p.tone})" stroke-opacity="${p.opacity}" stroke-dasharray="${visible} ${C - visible}" stroke-dashoffset="${-offset}" transform="rotate(-90 50 50)"></circle>`;
        offset += len;
        return svg;
      })
      .join('');

    const track =
      total === 0
        ? `<circle class="seg" cx="50" cy="50" r="${R}" stroke="var(--k-hairline-2)"></circle>`
        : '';
    let tick = '';
    let tgtStat: KitStat | undefined;
    let tgtNote = '';
    let tgtAria = '';
    let tgtCenter = '';
    const t = this._target;
    if (t) {
      const measured = toned.find((p) => p.label === t.partLabel);
      const actual = measured ? measured.pct : 0;
      const angle = ((t.percent / 100) * 360 - 90) * (Math.PI / 180);
      const x1 = 50 + (R - 9) * Math.cos(angle);
      const y1 = 50 + (R - 9) * Math.sin(angle);
      const x2 = 50 + (R + 9) * Math.cos(angle);
      const y2 = 50 + (R + 9) * Math.sin(angle);
      tick = `<line class="tickm" x1="${x1.toFixed(2)}" y1="${y1.toFixed(2)}" x2="${x2.toFixed(2)}" y2="${y2.toFixed(2)}"></line>`;
      const within = actual <= t.percent;
      const text = `${fmtPct(actual)} vs target ${fmtPct(t.percent)}`;
      tgtStat = {
        tone: within ? 'ok' : 'warn',
        text: `${t.partLabel}: ${text}${within ? ' (within target)' : ' (over target)'}`,
      };
      tgtNote = t.label;
      tgtCenter = `<span class="tc">${esc(`${fmtPct(actual)} vs ${fmtPct(t.percent)} target`)}</span>`;
      tgtAria = `. ${t.partLabel}: ${text}`;
    }

    const aria = `${this._heading ?? 'Distribution'}: ${toned.map((p) => `${p.label} ${fmtN(p.count)} (${fmtPct(p.pct)})`).join(', ')}, total ${fmtN(total)}${tgtAria}`;
    const rows = toned
      .map(
        (p) =>
          `<li><button class="row" type="button" data-act="part" data-arg="${esc(p.label)}"><span class="sw" style="background:var(--k-${p.tone});opacity:${p.opacity}"></span><span>${esc(p.label)}</span><span class="num">${fmtN(p.count)}</span>${this._showPercent ? `<span class="pc">${fmtPct(p.pct)}</span>` : ""}</button></li>`,
      )
      .join('');
    return `<div class="card">${this.head(eyebrow, this._finding ?? ringFinding(toned), {
      sub: tgtNote,
      stats: tgtStat === undefined ? [] : [tgtStat],
    })}
  <div class="body"><div class="wrap">
    <div class="donut"><svg viewBox="-10 -10 120 120" role="img" aria-label="${esc(aria)}">${track}${segs}${tick}</svg>
      <div class="mid" aria-hidden="true"><span class="total" style="font-size:${totalSize(fmtN(total))}px">${fmtN(total)}</span>${this._centerLabel ? `<span class="cl">${esc(this._centerLabel)}</span>` : ''}${tgtCenter}</div></div>
    <ul class="legend">${rows}</ul>
  </div></div>${this.foot(truncatedSpan(this._truncated))}
</div>`;
  }
}

defineElement('henoyo-ring', HenoyoRing);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-ring': HenoyoRing;
  }
}
