import { CLAY } from '../../data/editorial';
import {
  INK,
  contrast,
  inkOn,
  isMaterial,
  MATERIALS,
  scheme,
  snapToPalette,
  type ColourScheme,
  type Material,
  type SeverityKey,
} from './henoyoKit';

export interface HeatBand {
  label: string;
  min: number;
  color: string;
  custom_color?: string;
}

export interface CellPaint {
  background: string;
  color: string;
  outline: string | null;
  bandLabel: string | null;
}

const HEX = /^#[0-9A-Fa-f]{6}$/;
const BAND_SEVERITY = /^(?:sev-)?(critical|high|medium|low|info)$/;

function severityCell(
  s: ColourScheme,
  key: SeverityKey,
): { background: string; color: string; outline: string | null } {
  const paint = s.severity[key];
  if (key === 'critical')
    return { background: paint.stroke, color: inkOn(paint.stroke), outline: null };
  const background = key === 'high' ? s.ramp[0] : s.tint[key];
  const color = contrast(paint.stroke, background) >= 4.5 ? paint.stroke : INK;
  return { background, color, outline: paint.outline ? paint.stroke : null };
}

export function rampIndex(value: number, min: number, max: number, steps: number): number {
  if (steps <= 1) return 0;
  if (!(max > min)) return value > 0 ? steps - 1 : 0;
  const scaled = ((value - min) / (max - min)) * steps;
  return Math.min(steps - 1, Math.max(0, Math.floor(scaled)));
}

export function usableBands(bands: readonly HeatBand[] | null | undefined): HeatBand[] {
  if (!Array.isArray(bands)) return [];
  return bands.filter(
    (band) =>
      band !== null &&
      typeof band === 'object' &&
      typeof band.label === 'string' &&
      typeof band.min === 'number' &&
      Number.isFinite(band.min) &&
      typeof band.color === 'string',
  );
}

function materialPaint(color: Material, label: string): CellPaint {
  const [background, ink] = MATERIALS[color];
  return { background, color: ink, outline: null, bandLabel: label };
}

export function paintCell(
  value: number,
  bands: readonly HeatBand[] | null | undefined,
  min: number,
  max: number,
  s: ColourScheme = scheme(),
): CellPaint {
  const list = usableBands(bands);
  const plain = (label: string | null): CellPaint => {
    const background = s.ramp[0];
    return { background, color: inkOn(background), outline: null, bandLabel: label };
  };
  if (list.length === 0) {
    const background = s.ramp[rampIndex(value, min, max, s.ramp.length)] ?? s.ramp[0];
    return { background, color: inkOn(background), outline: null, bandLabel: null };
  }
  let chosen: HeatBand | null = null;
  for (const band of list) {
    if (band.min <= value && (chosen === null || band.min >= chosen.min)) chosen = band;
  }
  if (chosen === null) return plain(null);
  if (typeof chosen.custom_color === 'string' && HEX.test(chosen.custom_color)) {
    const background = snapToPalette(chosen.custom_color);
    return { background, color: inkOn(background), outline: null, bandLabel: chosen.label };
  }
  const severity = BAND_SEVERITY.exec(chosen.color.trim().toLowerCase())?.[1] as
    | SeverityKey
    | undefined;
  if (severity !== undefined) return { ...severityCell(s, severity), bandLabel: chosen.label };
  if (isMaterial(chosen.color)) return materialPaint(chosen.color, chosen.label);
  return plain(chosen.label);
}

export function isExcessive(value: number, excessAt: number | null | undefined): boolean {
  return typeof excessAt === 'number' && Number.isFinite(excessAt) && value >= excessAt;
}

export const EXCESS_COLOR = CLAY;

export function countScaleProps(props: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { showCounts: props['show_counts'] !== false };
  if (Array.isArray(props['bands'])) out['bands'] = props['bands'];
  const excess = props['excess_at'];
  if (typeof excess === 'number' && Number.isFinite(excess)) out['excessAt'] = excess;
  return out;
}
