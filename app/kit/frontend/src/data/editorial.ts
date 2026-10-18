import { SCHEMES } from '../components/webcomponents/colourScheme';

// Editorial chart colours. One source for report and dashboard charts and for
// the heatmap's default ramp. Author pins and named palettes still win.

export const SERIES_CAP = 6;
export const OTHER_LABEL = 'Other';

const EDITORIAL_SCHEME = SCHEMES.editorial;

export const HAIRLINE = '#E3DFD4';
export const CLAY = '#6E2E28';

const WORDS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
} as const;

const severityEntry = (key: keyof typeof WORDS) => {
  const paint = EDITORIAL_SCHEME.severity[key];
  return {
    word: WORDS[key],
    fill: paint.stroke,
    text: key === 'critical' ? '#FFFFFF' : paint.stroke,
    outline: paint.outline ? paint.stroke : null,
  };
};

export const SEVERITY = {
  critical: severityEntry('critical'),
  high: severityEntry('high'),
  medium: severityEntry('medium'),
  low: severityEntry('low'),
  info: severityEntry('info'),
};

export type SeverityKey = keyof typeof SEVERITY;

const SEVERITY_KEYS: readonly SeverityKey[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityKey(value: string): SeverityKey | null {
  const key = value.trim().toLowerCase().replace(/^sev-/, '');
  return SEVERITY_KEYS.find((k) => k === key) ?? null;
}

/** The severity word, always, plus the fill a chart series uses. */
export function severityMark(value: string): (typeof SEVERITY)[SeverityKey] | null {
  const key = severityKey(value);
  return key === null ? null : SEVERITY[key];
}
