import { isRelatedListRef, str, type ResolvedInput } from './bindingTypes';
import { lossCurve, type LossRow } from './lossCurve';

import type { RecordRow } from '../../lib/dataApi';

function numberOf(row: RecordRow, key: string): number | null {
  const value = row[key];
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value.replace(/,/g, ''));
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/** One point per related record that has a usable amount. */
export function lossExceedanceProps(input: ResolvedInput): Record<string, unknown> | null {
  const source = input.props['source'];
  const amountField = str(input.props['amount_field']);
  if (!isRelatedListRef(source) || amountField === undefined) return null;
  const probabilityField = str(input.props['probability_field']);
  const rows: LossRow[] = [];
  for (const row of input.rows['source'] ?? []) {
    const amount = numberOf(row, amountField);
    if (amount === null) continue;
    const probability =
      probabilityField === undefined ? undefined : numberOf(row, probabilityField);
    rows.push(
      probability === null || probability === undefined ? { amount } : { amount, probability },
    );
  }
  const heading = str(input.props['title']);
  const currency = str(input.props['currency']) ?? '';
  return {
    curve: lossCurve(rows, probabilityField !== undefined),
    currency,
    truncated: input.truncated === true,
    ...(heading !== undefined ? { heading } : {}),
  };
}
