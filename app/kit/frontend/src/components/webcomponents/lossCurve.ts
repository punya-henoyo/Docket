// Loss exceedance over a set of records.
// Chances that add up to more than one are weights, not independent probabilities (not 1 − Π(1 − p)).

import { kitLocale } from './colourScheme';
import { defaultCurrency } from './henoyoKit';

export type LossMode = 'equal' | 'distribution' | 'weights';

export interface LossStep {
  amount: number;
  exceedance: number;
}

export interface LossReading {
  mode: LossMode;
  steps: LossStep[];
  expected: number;
  oneInTwo: number | null;
  oneInTen: number | null;
  worst: number;
}

export interface LossRow {
  amount: number;
  probability?: number;
}

/** Largest amount whose exceedance is still at least `probability`. */
export function lossExceededBy(steps: readonly LossStep[], probability: number): number | null {
  let found: number | null = null;
  for (const step of steps) {
    if (step.exceedance + 1e-12 >= probability) found = step.amount;
  }
  return found;
}

function reading(
  rows: { amount: number; weight: number }[],
  mode: LossMode,
  normalise: boolean,
): LossReading | null {
  const kept = rows.filter(
    (row) =>
      Number.isFinite(row.amount) &&
      row.amount >= 0 &&
      Number.isFinite(row.weight) &&
      row.weight > 0,
  );
  if (kept.length === 0) return null;
  const mass = kept.reduce((sum, row) => sum + row.weight, 0);
  const scale = normalise ? mass : 1;
  const byAmount = new Map<number, number>();
  for (const row of kept) byAmount.set(row.amount, (byAmount.get(row.amount) ?? 0) + row.weight);
  const amounts = [...byAmount.keys()].sort((a, b) => a - b);
  let remaining = mass;
  const steps: LossStep[] = amounts.map((amount) => {
    const exceedance = remaining / scale;
    remaining -= byAmount.get(amount) ?? 0;
    return { amount, exceedance };
  });
  const expected = kept.reduce((sum, row) => sum + row.amount * row.weight, 0) / scale;
  const worst = amounts[amounts.length - 1] ?? 0;
  return {
    mode,
    steps,
    expected,
    oneInTwo: lossExceededBy(steps, 0.5),
    oneInTen: lossExceededBy(steps, 0.1),
    worst,
  };
}

/** Drop negative amounts. Without usable chances, every remaining record counts equally. */
export function lossCurve(rows: readonly LossRow[], hasProbability: boolean): LossReading | null {
  const finite = rows.filter((row) => Number.isFinite(row.amount) && row.amount >= 0);
  if (!hasProbability)
    return reading(
      finite.map((row) => ({ amount: row.amount, weight: 1 })),
      'equal',
      true,
    );
  const weighted = finite.map((row) => ({
    amount: row.amount,
    weight:
      typeof row.probability === 'number' && Number.isFinite(row.probability) && row.probability > 0
        ? row.probability
        : 0,
  }));
  const sum = weighted.reduce((total, row) => total + row.weight, 0);
  if (sum <= 0)
    return reading(
      finite.map((row) => ({ amount: row.amount, weight: 1 })),
      'equal',
      true,
    );
  if (sum <= 1 + 1e-9) return reading(weighted, 'distribution', false);
  return reading(weighted, 'weights', true);
}

function currencyCode(currency: string): string {
  return /^[A-Za-z]{3}$/.test(currency) ? currency.toUpperCase() : defaultCurrency();
}

/** Money in the given ISO code, else the tenant default, else a plain number: never an assumed symbol. */
export function formatMoney(value: number, currency: string, digits = 0, short = false): string {
  const code = currencyCode(currency);
  const notation = short ? 'compact' : 'standard';
  if (code !== '') {
    try {
      return new Intl.NumberFormat(kitLocale(), {
        style: 'currency',
        currency: code,
        maximumFractionDigits: short ? 1 : digits,
        notation,
      }).format(value);
    } catch {
      // An unknown code still has a number to show.
    }
  }
  return value.toLocaleString(kitLocale(), { maximumFractionDigits: short ? 1 : digits, notation });
}
