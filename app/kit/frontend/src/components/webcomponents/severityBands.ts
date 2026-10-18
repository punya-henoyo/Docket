// Severity bands for the unit grid. A value folds once, then lands on a band
// or on Other — an unknown value never borrows a real band's colour.

import { kitLocale } from './colourScheme';

export const BANDS = ['critical', 'high', 'medium', 'low', 'info', 'other'] as const;

export type SeverityBand = (typeof BANDS)[number];

const WORDS: Record<SeverityBand, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  other: 'Other',
};

export function bandWord(band: SeverityBand): string {
  return WORDS[band];
}

export function canonBand(value: string): SeverityBand | null {
  const key = value
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  if (key === 'critical' || key === 'crit') return 'critical';
  if (key === 'high') return 'high';
  if (key === 'medium' || key === 'med') return 'medium';
  if (key === 'low') return 'low';
  if (key === 'info' || key === 'informational' || key === 'information') return 'info';
  if (key === 'other') return 'other';
  return null;
}

/** One hop. The raw value, or the value it folds into, else Other. */
export function foldBand(raw: string | undefined, folds: Record<string, string>): SeverityBand {
  const key = (raw ?? '').trim();
  if (key === '') return 'other';
  const target = Object.prototype.hasOwnProperty.call(folds, key) ? folds[key] : key;
  if (target === undefined || target.trim() === '') return 'other';
  return canonBand(target) ?? 'other';
}

export function joinOr(labels: readonly string[]): string {
  const clean = labels.map((label) => label.trim()).filter((label) => label !== '');
  if (clean.length === 0) return '';
  if (clean.length === 1) return clean[0] ?? '';
  if (clean.length === 2) return `${clean[0]} or ${clean[1]}`;
  return `${clean.slice(0, -1).join(', ')} or ${clean[clean.length - 1]}`;
}

export function summarySentence(total: number, notable: number, shareLabel: string): string {
  if (total <= 0) return 'Nothing tracked.';
  const tracked = total.toLocaleString(kitLocale());
  if (shareLabel.trim() === '') return `${tracked} tracked.`;
  const count = notable.toLocaleString(kitLocale());
  const pct = Math.round((notable / total) * 100);
  return `${tracked} tracked — ${count} (${pct}%) ${shareLabel}.`;
}
