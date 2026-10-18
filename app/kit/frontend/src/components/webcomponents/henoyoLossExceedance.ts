// <henoyo-loss-exceedance>: how often a loss of at least this size shows up.

import { HenoyoElement, defineElement, esc, truncatedSpan, type KitStat } from './henoyoKit';
import { formatMoney, type LossMode, type LossReading, type LossStep } from './lossCurve';

function isStep(value: unknown): value is LossStep {
  if (value === null || typeof value !== 'object') return false;
  const step = value as LossStep;
  return Number.isFinite(step.amount) && Number.isFinite(step.exceedance);
}

function isMode(value: unknown): value is LossMode {
  return value === 'equal' || value === 'distribution' || value === 'weights';
}

function ticks(max: number): number[] {
  if (!(max > 0)) return [0];
  const raw = max / 4;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const err = raw / pow;
  const step = err <= 1 ? pow : err <= 2 ? 2 * pow : err <= 5 ? 5 * pow : 10 * pow;
  const out: number[] = [];
  for (let value = 0; value <= max + step * 0.001; value += step) out.push(value);
  return out;
}

const MODE_NOTE: Record<LossMode, string> = {
  equal: 'Each record counts equally.',
  distribution: 'Each record counts by its chance.',
  weights: 'The chances add up to more than one, so each record counts by its share.',
};

/** The finding: the largest loss read off the curve, 1 in 10 years when there is one. */
export function lossFinding(curve: LossReading, money: (value: number) => string): string {
  if (curve.oneInTen !== null) return `1-in-10 year loss: ${money(curve.oneInTen)}`;
  if (curve.oneInTwo !== null) return `1-in-2 year loss: ${money(curve.oneInTwo)}`;
  return `Worst loss: ${money(curve.worst)}`;
}

export class HenoyoLossExceedance extends HenoyoElement {
  private _heading: string | undefined;
  private _curve: LossReading | null = null;
  private _currency = '';
  private _truncated = false;

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(value: string | undefined) {
    this._heading = typeof value === 'string' && value !== '' ? value : undefined;
    this.invalidate();
  }

  get curve(): LossReading | null {
    return this._curve;
  }
  set curve(value: LossReading | null | undefined) {
    if (value == null || !isMode(value.mode) || !Array.isArray(value.steps)) {
      this._curve = null;
    } else {
      const steps = value.steps.filter(isStep);
      this._curve =
        steps.length === 0
          ? null
          : {
              mode: value.mode,
              steps,
              expected: Number.isFinite(value.expected) ? value.expected : 0,
              oneInTwo: typeof value.oneInTwo === 'number' ? value.oneInTwo : null,
              oneInTen: typeof value.oneInTen === 'number' ? value.oneInTen : null,
              worst: Number.isFinite(value.worst)
                ? value.worst
                : (steps[steps.length - 1]?.amount ?? 0),
            };
    }
    this.invalidate();
  }

  get currency(): string {
    return this._currency;
  }
  set currency(value: string | undefined) {
    this._currency = typeof value === 'string' ? value : '';
    this.invalidate();
  }

  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(value: boolean | undefined) {
    this._truncated = value === true;
    this.invalidate();
  }

  protected styles(): string {
    return `
.body svg.plot { max-height:260px; }
.mark { fill:var(--k-accent); stroke:var(--k-surface); stroke-width:2; }
`;
  }

  protected view(): string {
    const eyebrow = this._heading ?? 'Loss exceedance';
    const curve = this._curve;
    if (curve === null) return this.emptyCard(eyebrow, 'No losses to chart');
    const money = (value: number | null): string =>
      value === null ? '—' : formatMoney(value, this._currency);
    const stats: KitStat[] = [
      { text: `Expected ${money(curve.expected)}` },
      ...(curve.oneInTen !== null && curve.oneInTwo !== null
        ? [{ text: `1 in 2 ${money(curve.oneInTwo)}` }]
        : []),
      { text: `Worst ${money(curve.worst)}` },
    ];
    return `<div class="card">${this.head(
      eyebrow,
      lossFinding(curve, (v) => money(v)),
      { stats },
    )}
      <div class="body">
        ${this.plot(curve)}
        <p class="note">${esc(MODE_NOTE[curve.mode])}</p>
      </div>
      ${this.foot(truncatedSpan(this._truncated))}
    </div>`;
  }

  private plot(curve: LossReading): string {
    const steps = curve.steps;
    const width = 640;
    const height = 260;
    const left = 56;
    const right = 32;
    const top = 16;
    const bottom = 32;
    const maxAmount = Math.max(...steps.map((step) => step.amount), 0);
    const xTicks = ticks(maxAmount);
    const xMax = xTicks[xTicks.length - 1] ?? 0;
    const plotW = width - left - right;
    const plotH = height - top - bottom;
    const xOf = (amount: number): number => left + (xMax === 0 ? 0 : (amount / xMax) * plotW);
    const yOf = (exceedance: number): number =>
      top + (1 - Math.min(1, Math.max(0, exceedance))) * plotH;
    const first = steps[0];
    if (first === undefined) return '';
    let d = `M${xOf(first.amount).toFixed(1)} ${yOf(first.exceedance).toFixed(1)}`;
    for (let i = 1; i < steps.length; i += 1) {
      const step = steps[i];
      if (step === undefined) continue;
      d += ` H${xOf(step.amount).toFixed(1)} V${yOf(step.exceedance).toFixed(1)}`;
    }
    const last = steps[steps.length - 1];
    if (last !== undefined) d += ` H${xOf(last.amount).toFixed(1)} V${yOf(0).toFixed(1)}`;
    const grid = [0, 0.25, 0.5, 0.75, 1]
      .map((tick) => {
        const y = yOf(tick).toFixed(1);
        return `<line class="grid" x1="${left}" x2="${width - right}" y1="${y}" y2="${y}" />
          <text class="axis" x="${left - 8}" y="${y}" text-anchor="end" dominant-baseline="middle">${Math.round(tick * 100)}%</text>`;
      })
      .join('');
    const axis = xTicks
      .map((tick) => {
        const x = xOf(tick).toFixed(1);
        return `<text class="axis" x="${x}" y="${height - 8}" text-anchor="middle">${esc(formatMoney(tick, this._currency, 0, true))}</text>`;
      })
      .join('');
    const marks = (
      [
        ['1 in 2', curve.oneInTwo],
        ['1 in 10', curve.oneInTen],
      ] as const
    )
      .map(([name, amount]) => {
        const step = amount === null ? undefined : steps.find((item) => item.amount === amount);
        if (amount === null || step === undefined) return '';
        const x = xOf(amount);
        const y = yOf(step.exceedance);
        const flip = x > width * 0.8;
        return `<circle class="mark" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5" />
          <text class="axis" x="${(flip ? x - 10 : x + 10).toFixed(1)}" y="${(y - 8).toFixed(1)}" text-anchor="${flip ? 'end' : 'start'}">${name}</text>`;
      })
      .join('');
    return `<svg class="plot" viewBox="0 0 ${width} ${height}" role="img" aria-label="Loss exceedance curve">
      ${grid}
      <line class="base" x1="${left}" y1="${top + plotH}" x2="${width - right}" y2="${top + plotH}" />
      ${axis}
      <path d="${d}" fill="none" stroke="var(--k-accent)" stroke-width="2" />
      ${marks}
    </svg>`;
  }
}

defineElement('henoyo-loss-exceedance', HenoyoLossExceedance);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-loss-exceedance': HenoyoLossExceedance;
  }
}
