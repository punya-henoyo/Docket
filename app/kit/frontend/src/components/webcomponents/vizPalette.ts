// Band folding, period labels and summary sentences shared by the Visual Kit
// charts. Colours come from the colour scheme in henoyoKit, never from here.

import { kitLocale } from './colourScheme';
import { type ColourScheme, type Paint, type SeverityKey } from './henoyoKit';

export interface Band {
  key: string;
  label: string;
  total: number;
}

export const OTHER_KEY = '__other__';
export const MAX_SERIES = 6;

export const SEVERITY_WORD: Record<SeverityKey, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
};

const SEVERITY_RANK: Record<SeverityKey, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function severityOf(value: string): SeverityKey | undefined {
  const s = value.trim().toLowerCase();
  if (s.startsWith('crit')) return 'critical';
  if (/^high\b/.test(s)) return 'high';
  if (s.startsWith('med')) return 'medium';
  if (/^low\b/.test(s)) return 'low';
  if (s.startsWith('info')) return 'info';
  return undefined;
}

export function severityWord(value: string): string | undefined {
  const key = severityOf(value);
  return key === undefined ? undefined : SEVERITY_WORD[key];
}

export function paintFor(key: string, categoryIndex: number, scheme: ColourScheme): Paint {
  const severity = severityOf(key);
  if (severity !== undefined) return scheme.severity[severity];
  if (key === OTHER_KEY) return scheme.other;
  return scheme.series[categoryIndex % scheme.series.length] ?? scheme.other;
}

/** At most six bands. Severity bands stay; the rest of the tail folds into Other. */
export function foldBands(bands: readonly Band[], max = MAX_SERIES): Band[] {
  const byKey = new Map<string, Band>();
  for (const band of bands) {
    const prev = byKey.get(band.key);
    if (prev === undefined) byKey.set(band.key, { ...band });
    else prev.total += band.total;
  }
  const all = [...byKey.values()];
  const severities = all
    .filter((band) => severityOf(band.key) !== undefined)
    .sort(
      (a, b) =>
        (SEVERITY_RANK[severityOf(a.key) ?? 'info'] ?? 9) -
        (SEVERITY_RANK[severityOf(b.key) ?? 'info'] ?? 9),
    );
  const rest = all
    .filter((band) => severityOf(band.key) === undefined)
    .sort((a, b) => b.total - a.total || (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
  const ordered = [...severities, ...rest];
  if (ordered.length <= max) return ordered;
  const head = ordered.slice(0, max - 1);
  const tail = ordered.slice(max - 1);
  return [
    ...head,
    {
      key: OTHER_KEY,
      label: 'Other',
      total: tail.reduce((sum, band) => sum + band.total, 0),
    },
  ];
}

/** Stack bottom → top: least severe first, then categories, then Other. */
export function stackBands(bands: readonly Band[]): Band[] {
  const folded = foldBands(bands);
  const severities = folded.filter((band) => severityOf(band.key) !== undefined).reverse();
  const rest = folded.filter(
    (band) => severityOf(band.key) === undefined && band.key !== OTHER_KEY,
  );
  const other = folded.filter((band) => band.key === OTHER_KEY);
  return [...severities, ...rest, ...other];
}

export function paints(bands: readonly Band[], scheme: ColourScheme): Paint[] {
  let category = 0;
  return bands.map((band) => {
    const paint = paintFor(band.key, category, scheme);
    if (severityOf(band.key) === undefined && band.key !== OTHER_KEY) category += 1;
    return paint;
  });
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** `YYYY-MM` or `YYYY-MM-DD` → a month index, or undefined when it is not a month. */
export function monthStamp(key: string): number | undefined {
  const match = /^(\d{4})-(\d{2})(?:-\d{2})?$/.exec(key);
  if (match === null) return undefined;
  const month = Number(match[2]);
  if (month < 1 || month > 12) return undefined;
  return Number(match[1]) * 12 + (month - 1);
}

export function monthKey(stamp: number, withDay: boolean): string {
  const year = Math.floor(stamp / 12);
  const month = String((stamp % 12) + 1).padStart(2, '0');
  return withDay ? `${year}-${month}-01` : `${year}-${month}`;
}

export function periodLabel(key: string): string | undefined {
  const stamp = monthStamp(key);
  if (stamp === undefined) return undefined;
  const month = MONTHS[stamp % 12];
  const year = Math.floor(stamp / 12);
  const day = /^(\d{4})-(\d{2})-(\d{2})$/.exec(key);
  if (day !== null && day[3] !== '01') return `${Number(day[3])} ${month} ${year}`;
  return `${month} ${year}`;
}

export function fmt(n: number): string {
  return n.toLocaleString(kitLocale());
}

/** A fill that is never paper: an outlined severity (High) is drawn as its stroke colour, softened. */
export function solidFill(paint: Paint): { color: string; opacity: number } {
  return paint.outline ? { color: paint.stroke, opacity: 0.55 } : { color: paint.fill, opacity: 1 };
}

/** The width an SVG plot should be drawn at so 11px labels stay 11px: the host width less the card padding. */
export function plotWidth(host: HTMLElement, fallback = 640): number {
  const width = host.clientWidth - 44;
  return width >= 280 ? Math.min(Math.round(width), 1200) : fallback;
}

/** Calls `redraw` when the host's width changes, so a plot is drawn at its true size. */
export function watchWidth(host: HTMLElement, redraw: () => void): void {
  if (typeof ResizeObserver === 'undefined') return;
  let last = 0;
  new ResizeObserver(() => {
    const width = host.clientWidth;
    if (Math.abs(width - last) < 8) return;
    last = width;
    redraw();
  }).observe(host);
}
