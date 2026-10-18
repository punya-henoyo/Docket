// Colour schemes for the Visual Kit and the report charts: one pure module, no DOM, so charts
// that cannot read CSS variables can import it. henoyoKit re-exports everything here.

export const MATERIALS = {
  stone: ['#D9D3C4', '#2F3832'],
  grove: ['#D3E3D8', '#184A2E'],
  clay: ['#E7D2C6', '#6E2E28'],
  brass: ['#E8D5AE', '#5C400E'],
  sea: ['#D0DCE6', '#1E364C'],
  dusk: ['#D8D5E6', '#343058'],
  tide: ['#D0E3DC', '#154440'],
  sand: ['#DDD4C6', '#4A433C'],
} as const;

export type Material = keyof typeof MATERIALS;

export type SixPaints = readonly [Paint, Paint, Paint, Paint, Paint, Paint];

export interface Paint {
  fill: string;
  stroke: string;
  outline: boolean;
}

export const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type SeverityKey = (typeof SEVERITY_KEYS)[number];

export const SCHEME_IDS = ['editorial', 'traffic_light', 'colour_blind_safe'] as const;
export type SchemeId = (typeof SCHEME_IDS)[number];

export interface ColourScheme {
  id: SchemeId;
  label: string;
  /** Severity bands. The word is always shown beside the colour. */
  severity: Record<SeverityKey, Paint>;
  /** Pale cell backgrounds for severity bands that are not solid. */
  tint: Record<SeverityKey, string>;
  /** Five flat steps from least to most; a magnitude picks one, never a gradient. */
  ramp: readonly [string, string, string, string, string];
  /** Six category washes with ink strokes, for values that are not severities. */
  series: SixPaints;
  other: Paint;
  /** The single colour for one measure, such as a curve or a bar. */
  accent: string;
}

export const PAPER = '#FBF8F1';
export const INK = '#1A1F1C';
export const ON_DARK = '#FFFEFB';

const VIZ_CATEGORICAL_FALLBACK: string[] = [
  '#2A669F',
  '#A97E2C',
  '#63579D',
  '#619655',
  '#824B85',
  '#0F9B89',
  '#98483C',
  '#1195B4',
  '#934E1E',
  '#0A999F',
  '#96455B',
  '#8D8B32',
];
const VIZ_OTHER_FALLBACK = '#8A877E';
const VIZ_SEQ_FALLBACK = ['#FCEEEC', '#EECBC5', '#D99D92', '#AE6256', '#723127'] as const;
const VIZ_DIV_FALLBACK = ['#98483C', '#CD958B', '#E6E4E1', '#88A8C9', '#2A669F'] as const;
const DIV_KEYS = ['neg2', 'neg1', 'mid', 'pos1', 'pos2'] as const;

export interface VizPalette {
  /** Twelve categories in a fixed order, never cycled. */
  categorical: string[];
  other: string;
  /** Five steps, quiet to loud. */
  seq: readonly [string, string, string, string, string];
  /** Five steps, negative to positive, grey in the middle. */
  div: readonly [string, string, string, string, string];
}

export const VIZ_FALLBACK: VizPalette = {
  categorical: VIZ_CATEGORICAL_FALLBACK,
  other: VIZ_OTHER_FALLBACK,
  seq: VIZ_SEQ_FALLBACK,
  div: VIZ_DIV_FALLBACK,
};

function tripletToHex(value: string, fallback: string): string {
  const parts = value.trim().split(/\s+/).map(Number);
  if (parts.length !== 3 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return fallback;
  }
  return `#${parts.map((n) => n.toString(16).padStart(2, '0')).join('')}`.toUpperCase();
}

const vizCache = new Map<string, VizPalette>();

/** The chart palette from the `--h-viz-*` tokens of the active theme; hex constants where there is no DOM or token. */
export function resolveViz(host?: Element): VizPalette {
  const el = host ?? (typeof document === 'undefined' ? undefined : document.documentElement);
  if (el === undefined || typeof getComputedStyle === 'undefined') return VIZ_FALLBACK;
  const themeId = host === undefined ? (el.getAttribute('data-theme') ?? 'classic') : null;
  const cached = themeId === null ? undefined : vizCache.get(themeId);
  if (cached !== undefined) return cached;
  const style = getComputedStyle(el);
  const read = (name: string, fallback: string): string | null => {
    const raw = style.getPropertyValue(name);
    return raw.trim() === '' ? null : tripletToHex(raw, fallback);
  };
  const tokens = {
    categorical: VIZ_CATEGORICAL_FALLBACK.map((f, i) => read(`--h-viz-${i + 1}`, f)),
    other: read('--h-viz-other', VIZ_OTHER_FALLBACK),
    seq: VIZ_SEQ_FALLBACK.map((f, i) => read(`--h-viz-seq-${i}`, f)),
    div: VIZ_DIV_FALLBACK.map((f, i) => read(`--h-viz-div-${DIV_KEYS[i]}`, f)),
  };
  if (tokens.categorical[0] === null) return VIZ_FALLBACK;
  const palette: VizPalette = {
    categorical: tokens.categorical.map((v, i) => v ?? VIZ_CATEGORICAL_FALLBACK[i]!),
    other: tokens.other ?? VIZ_OTHER_FALLBACK,
    seq: tokens.seq.map((v, i) => v ?? VIZ_SEQ_FALLBACK[i]!) as unknown as VizPalette['seq'],
    div: tokens.div.map((v, i) => v ?? VIZ_DIV_FALLBACK[i]!) as unknown as VizPalette['div'],
  };
  if (themeId !== null) vizCache.set(themeId, palette);
  return palette;
}

export function clearVizCache(): void {
  vizCache.clear();
}

const solid = (hex: string): Paint => ({ fill: hex, stroke: hex, outline: false });
const outlined = (hex: string): Paint => ({ fill: PAPER, stroke: hex, outline: true });
const INFO = '#5F675F';

/** Surface colour at `share` of `hex` over paper: the wash behind a category's stroke. */
export function wash(hex: string, share = 0.2): string {
  const [r, g, b] = rgb(hex);
  const [pr, pg, pb] = rgb(PAPER);
  return `#${[
    r! * share + pr! * (1 - share),
    g! * share + pg! * (1 - share),
    b! * share + pb! * (1 - share),
  ]
    .map((c) => Math.round(c).toString(16).padStart(2, '0'))
    .join('')}`.toUpperCase();
}

function categorySeries(viz: VizPalette): SixPaints {
  return viz.categorical
    .slice(0, 6)
    .map((hex) => ({ fill: wash(hex), stroke: hex, outline: false })) as unknown as SixPaints;
}

function otherPaint(viz: VizPalette): Paint {
  return { fill: wash(viz.other, 0.35), stroke: viz.other, outline: false };
}

function buildScheme(id: SchemeId, viz: VizPalette): ColourScheme {
  const series = categorySeries(viz);
  const other = otherPaint(viz);
  if (id === 'traffic_light') {
    return {
      id,
      label: 'Traffic light (red, amber, green)',
      severity: {
        critical: solid('#A04038'),
        high: outlined('#A04038'),
        medium: solid('#B07A20'),
        low: solid('#3E8343'),
        info: solid(INFO),
      },
      tint: {
        critical: '#FBDCD8',
        high: '#FEEEEB',
        medium: '#FFEBD2',
        low: '#DBF3DB',
        info: '#EEEFEC',
      },
      ramp: ['#3E8343', '#8A8C34', '#B07A20', '#B26232', '#A04038'],
      series,
      other,
      accent: '#A04038',
    };
  }
  if (id === 'colour_blind_safe') {
    return {
      id,
      label: 'Colour-blind safe (blue to orange)',
      severity: {
        critical: solid('#964D09'),
        high: outlined('#964D09'),
        medium: solid('#B76B1C'),
        low: solid('#2A669F'),
        info: solid(INFO),
      },
      tint: {
        critical: '#FBDECC',
        high: '#FDEBDF',
        medium: '#FDEBDA',
        low: '#D9EAFC',
        info: '#EEEFEC',
      },
      ramp: ['#2A669F', '#8CB8D2', '#E9E8E4', '#E0AA86', '#A65C20'],
      series: [
        { fill: '#CBE1F8', stroke: '#23588A', outline: false },
        { fill: '#F8D7BE', stroke: '#7F4413', outline: false },
        { fill: '#C3E7DF', stroke: '#066357', outline: false },
        { fill: '#F4D4E2', stroke: '#7A3F5C', outline: false },
        { fill: '#E5DFBA', stroke: '#605619', outline: false },
        { fill: '#DEDEDE', stroke: '#484848', outline: false },
      ],
      other,
      accent: '#964D09',
    };
  }
  return {
    id: 'editorial',
    label: 'Editorial',
    severity: {
      critical: solid('#6E2A1C'),
      high: outlined('#964030'),
      medium: solid('#8A5A1E'),
      low: solid('#4F6B5B'),
      info: solid(INFO),
    },
    tint: {
      critical: '#E7D2C6',
      high: '#F4ECE6',
      medium: '#F6EDE0',
      low: '#E7EEE9',
      info: '#EEEFEC',
    },
    ramp: viz.seq,
    series,
    other,
    accent: viz.categorical[0]!,
  };
}

export const SCHEMES: Record<SchemeId, ColourScheme> = {
  editorial: buildScheme('editorial', VIZ_FALLBACK),
  traffic_light: buildScheme('traffic_light', VIZ_FALLBACK),
  colour_blind_safe: buildScheme('colour_blind_safe', VIZ_FALLBACK),
};

const schemeCache = new WeakMap<VizPalette, Partial<Record<SchemeId, ColourScheme>>>();

function schemeFor(id: SchemeId, viz: VizPalette): ColourScheme {
  if (viz === VIZ_FALLBACK) return SCHEMES[id];
  const byId = schemeCache.get(viz) ?? {};
  schemeCache.set(viz, byId);
  return (byId[id] ??= buildScheme(id, viz));
}

export function isSchemeId(value: unknown): value is SchemeId {
  return typeof value === 'string' && (SCHEME_IDS as readonly string[]).includes(value);
}

let tenantScheme: SchemeId = 'editorial';

/** Seam for a tenant-wide default: call with the admin's chosen scheme id. */
export function setDefaultScheme(id: unknown): void {
  tenantScheme = isSchemeId(id) ? id : 'editorial';
}

let tenantCurrency = '';

/** Seam for a tenant-wide currency: an ISO 4217 code, or empty for plain numbers. */
export function setDefaultCurrency(code: unknown): void {
  tenantCurrency = typeof code === 'string' && /^[A-Za-z]{3}$/.test(code) ? code.toUpperCase() : '';
}

export function defaultCurrency(): string {
  return tenantCurrency;
}

let tenantLocale = 'en-GB';

/** Seam for the tenant's number and date locale (a BCP 47 tag); an unsupported tag keeps en-GB. */
export function setDefaultLocale(tag: unknown): void {
  try {
    tenantLocale =
      typeof tag === 'string' && Intl.NumberFormat.supportedLocalesOf(tag).length > 0
        ? tag
        : 'en-GB';
  } catch {
    tenantLocale = 'en-GB';
  }
}

/** The locale every Visual Kit number and date is written in. */
export function kitLocale(): string {
  return tenantLocale;
}

interface KitDateTime {
  dateFormat: string;
  timeFormat: string;
  timeZone: string;
}

let tenantDateTime: KitDateTime = { dateFormat: 'd MMM yyyy', timeFormat: '24h', timeZone: 'UTC' };

/** Seam for the tenant's date pattern, clock and time zone; an unknown zone keeps UTC. */
export function setDefaultDateTime(next: Partial<KitDateTime>): void {
  const merged = { ...tenantDateTime, ...next };
  try {
    new Intl.DateTimeFormat('en-GB', { timeZone: merged.timeZone });
  } catch {
    merged.timeZone = 'UTC';
  }
  tenantDateTime = merged;
}

export function kitTimeZone(): string {
  return tenantDateTime.timeZone;
}

function zoned(t: number): Record<string, string> {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tenantDateTime.timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(t));
  return Object.fromEntries(parts.map((p) => [p.type, p.value]));
}

function monthShort(t: number): string {
  return new Intl.DateTimeFormat(tenantLocale, {
    month: 'short',
    timeZone: tenantDateTime.timeZone,
  }).format(new Date(t));
}

/** A date in the tenant's pattern: "6 Oct 2026", "06/10/2026", "2026-10-06". */
export function kitDate(t: number): string {
  const p = zoned(t);
  const [day, month, year] = [p['day']!, p['month']!, p['year']!];
  switch (tenantDateTime.dateFormat) {
    case 'dd/MM/yyyy':
      return `${day}/${month}/${year}`;
    case 'MM/dd/yyyy':
      return `${month}/${day}/${year}`;
    case 'yyyy-MM-dd':
      return `${year}-${month}-${day}`;
    default:
      return `${Number(day)} ${monthShort(t)} ${year}`;
  }
}

/** The same date without its year, for axes and ticks: "6 Oct", "06/10", "10-06". */
export function kitDayMonth(t: number): string {
  const p = zoned(t);
  const [day, month] = [p['day']!, p['month']!];
  switch (tenantDateTime.dateFormat) {
    case 'dd/MM/yyyy':
      return `${day}/${month}`;
    case 'MM/dd/yyyy':
      return `${month}/${day}`;
    case 'yyyy-MM-dd':
      return `${month}-${day}`;
    default:
      return `${Number(day)} ${monthShort(t)}`;
  }
}

/** A time of day on the tenant's clock: "14:05" or "2:05 PM". */
export function kitTime(t: number): string {
  const p = zoned(t);
  const hour = Number(p['hour']) % 24;
  if (tenantDateTime.timeFormat !== '12h') return `${String(hour).padStart(2, '0')}:${p['minute']}`;
  return `${hour % 12 === 0 ? 12 : hour % 12}:${p['minute']} ${hour < 12 ? 'AM' : 'PM'}`;
}

/** The short name of the tenant's time zone at `t`: "UTC", "IST". */
export function kitZoneName(t: number): string {
  const part = new Intl.DateTimeFormat(tenantLocale, {
    timeZone: tenantDateTime.timeZone,
    timeZoneName: 'short',
  })
    .formatToParts(new Date(t))
    .find((x) => x.type === 'timeZoneName');
  return part?.value ?? tenantDateTime.timeZone;
}

/** An explicit name wins, then the `--h-chart-scheme` theme token, then the tenant default. */
export function scheme(name?: unknown, host?: Element): ColourScheme {
  const viz = resolveViz(host);
  if (isSchemeId(name)) return schemeFor(name, viz);
  const el = host ?? (typeof document === 'undefined' ? undefined : document.documentElement);
  const token =
    el === undefined || typeof getComputedStyle === 'undefined'
      ? ''
      : getComputedStyle(el).getPropertyValue('--h-chart-scheme').trim();
  return schemeFor(isSchemeId(token) ? token : tenantScheme, viz);
}

type Lab = [number, number, number];

function oklab(hex: string): Lab {
  const [r, g, b] = rgb(hex).map((c) => {
    const v = c / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const n = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [
    0.2104542553 * l + 0.793617785 * m - 0.0040720468 * n,
    1.9779984951 * l - 2.428592205 * m + 0.4505937099 * n,
    0.0259040371 * l + 0.7827717662 * m - 0.808675766 * n,
  ];
}

const HEX6 = /^#[0-9a-f]{6}$/i;
const HEX3 = /^#[0-9a-f]{3}$/i;

/** The palette colour nearest `hex` in OKLab: categorical, status and Other. Anything that is not a hex colour is returned unchanged. */
export function snapToPalette(hex: string, viz: VizPalette = resolveViz()): string {
  const full = HEX3.test(hex) ? `#${[...hex.slice(1)].map((c) => c + c).join('')}` : hex;
  if (!HEX6.test(full)) return hex;
  const target = oklab(full);
  let best = viz.other;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const candidate of [...viz.categorical, viz.other]) {
    const lab = oklab(candidate);
    const d = (lab[0] - target[0]) ** 2 + (lab[1] - target[1]) ** 2 + (lab[2] - target[2]) ** 2;
    if (d < bestDistance) {
      best = candidate;
      bestDistance = d;
    }
  }
  return best;
}

/** A flat ramp colour for `t` in 0..1, blended between the scheme's five steps. */
export function rampColor(s: ColourScheme, t: number): string {
  const u = Math.max(0, Math.min(1, Number.isFinite(t) ? t : 0)) * (s.ramp.length - 1);
  const at = Math.min(s.ramp.length - 2, Math.floor(u));
  const from = rgb(s.ramp[at] ?? PAPER);
  const to = rgb(s.ramp[at + 1] ?? PAPER);
  const k = u - at;
  const hex = (i: number): string =>
    Math.round((from[i] ?? 0) + ((to[i] ?? 0) - (from[i] ?? 0)) * k)
      .toString(16)
      .padStart(2, '0');
  return `#${hex(0)}${hex(1)}${hex(2)}`.toUpperCase();
}

function rgb(hex: string): [number, number, number] {
  return [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16)) as [number, number, number];
}

function luminance(hex: string): number {
  const [r, g, b] = rgb(hex).map((c) => {
    const v = c / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** White or ink text, whichever reads better on `fill` (WCAG contrast). */
export function inkOn(fill: string): string {
  return contrast(fill, ON_DARK) >= contrast(fill, INK) ? ON_DARK : INK;
}

export function schemeVars(s: ColourScheme): string {
  const sev = SEVERITY_KEYS.map((k) => `--k-sev-${k}:${s.severity[k].stroke};`).join('');
  const ramp = s.ramp.map((c, i) => `--k-ramp-${i}:${c};`).join('');
  return `:host{${sev}${ramp}--k-accent:${s.accent};}`;
}
